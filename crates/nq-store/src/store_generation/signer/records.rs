//! Canonical signer-lifecycle records owned by the Store-private signer.
//!
//! These records contain correspondence evidence only.  Constructors bind
//! every coordinate into a domain-separated identity and verifiers re-check
//! the complete relation.  None of the types contains private key material or
//! provides an authority-bearing constructor outside this crate.

use std::collections::BTreeSet;

use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize, Serializer};

use crate::store_generation::live_c2::{
    ConsumedStoreFoundationAdoptionAuthorityV1, StoreC2AuthoritySnapshotV1, StoreC2SnapshotActorV1,
};
use crate::store_generation::records::{
    A2ApplicabilityInterpretationIdentityV1, A2ChainRootIdentityV1, ActiveStorePolicyIdentityV1,
    BootstrapGrantIdentityV1, BootstrapGrantRequestIdentityV1, C2StructuralCutV1,
    CanonicalC2RecordV1, ControllingActivationIdentityV1, DependencyAnchorIdentityV1,
    Ed25519SignatureBytesV1, Ed25519StoreIntegrityPublicKeyV1, EnrollmentProvenancePurposeV1,
    ResidentIdentityV1, RoleManifestIdentityV1, SignerScopePolicyIdentityV1,
    StoreIntegrityCustodyEvidenceIdentityV1, StoreIntegrityEnrollmentAttemptIdentityV1,
    StoreIntegrityEnrollmentCandidateIdentityV1, StoreIntegrityKeyEnrollmentInputV1,
    StoreIntegrityKeyEnrollmentV1, StoreIntegrityKeyGenerationV1,
    StoreIntegrityProofOfPossessionIdentityV1, StoreIntegrityProposalIdentityV1,
    StoreOccurrenceIdentityV1, TerminalA1IssuerIdentityV1, construct_n_18_key_enrollment,
    decode_store_integrity_key_enrollment_v1, verify_n_18_key_enrollment,
};

use super::coordinator::ConsumedInitialProposalPoPV1;
use super::custody::VerifiedFoundationalCustodyV1;
use super::external_governance::{StoreAdoptedBootstrapGrantV1, VerifiedBootstrapGrantV1};
use super::manifest::{
    StoreAdmittedSignerImplementationManifestV1,
    verify_store_admitted_signer_implementation_manifest_basis_v1,
};
use super::messages::SignerIdentityV1;
use super::result::SignerRefusalV2;

const ENROLLMENT_CANDIDATE_DOMAIN: &[u8] =
    b"nq.c2.store_integrity_enrollment_candidate.identity.v1";
const ENROLLMENT_SCHEMA_V2: &str = "nq.c2_store_integrity_enrollment.v2";
const ENROLLMENT_IDENTITY_DOMAIN_V2: &str = "nq.c2.store_integrity_enrollment.identity.v2";
const SIGNER_FOUNDATION_SCHEMA_V1: &str = "nq.c2_store_integrity_signer_foundation.v1";
const SIGNER_FOUNDATION_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.store_integrity_signer_foundation.identity.v1";
const FOUNDATIONAL_ADOPTION_SCHEMA_V1: &str = "nq.c2_store_integrity_foundational_adoption.v1";
const FOUNDATIONAL_ADOPTION_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.store_integrity_foundational_adoption.identity.v1";
const GENESIS_DOMAIN: &[u8] = b"nq.c2.store_generation_genesis.identity.v1";
const BOOTSTRAP_RECEIPT_DOMAIN: &[u8] = b"nq.c2.signer_bootstrap_transition_receipt.identity.v1";
const NORMAL_INTENT_DOMAIN: &[u8] = b"nq.c2.signer_normal_rotation_intent.identity.v1";
const NORMAL_RECEIPT_DOMAIN: &[u8] = b"nq.c2.signer_normal_rotation_receipt.identity.v1";
const IJSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Durable evidence append outcome. Exact replay is a no-write verification;
/// it never converts the persisted row into process-local authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentBridgeAppendDispositionV1 {
    Appended,
    ExactReplay,
}

/// Closed durable taxonomy for the authority route that admitted one exact
/// signer foundation.  The tag is evidence about an adoption event; it is not
/// itself authority and has no caller-selectable production constructor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum FoundationalAdoptionLineageV1 {
    #[serde(rename = "initialExternal")]
    InitialExternal,
    #[serde(rename = "ordinarySuccessorContinuity")]
    OrdinarySuccessorContinuity,
    #[serde(rename = "restoreHistorical")]
    RestoreHistorical,
    #[serde(rename = "recoveryNewFoundation")]
    RecoveryNewFoundation,
}

impl FoundationalAdoptionLineageV1 {
    const ALL: [Self; 4] = [
        Self::InitialExternal,
        Self::OrdinarySuccessorContinuity,
        Self::RestoreHistorical,
        Self::RecoveryNewFoundation,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::InitialExternal => "initialExternal",
            Self::OrdinarySuccessorContinuity => "ordinarySuccessorContinuity",
            Self::RestoreHistorical => "restoreHistorical",
            Self::RecoveryNewFoundation => "recoveryNewFoundation",
        }
    }
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerRecordCoordinatesV1 {
    pub(crate) occurrence: SignerIdentityV1,
    pub(crate) physical_generation: SignerIdentityV1,
    pub(crate) lifecycle_root: SignerIdentityV1,
    pub(crate) scope: SignerIdentityV1,
    pub(crate) resident: String,
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
            || self.resident.is_empty()
            || self.resident.len() > 1024
            || self.resident.chars().any(char::is_control)
            || [
                self.resident_generation,
                self.role_manifest_generation,
                self.signer_policy_version,
            ]
            .into_iter()
            .any(|value| value > IJSON_SAFE_INTEGER)
            || [
                self.occurrence,
                self.physical_generation,
                self.lifecycle_root,
                self.scope,
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
        let mut bytes = Vec::with_capacity(32 * 7 + 32 + self.resident.len());
        bytes.extend_from_slice(&self.occurrence);
        bytes.extend_from_slice(&self.physical_generation);
        bytes.extend_from_slice(&self.lifecycle_root);
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(&(self.resident.len() as u64).to_be_bytes());
        bytes.extend_from_slice(self.resident.as_bytes());
        bytes.extend_from_slice(&self.resident_generation.to_be_bytes());
        bytes.extend_from_slice(&self.role);
        bytes.extend_from_slice(&self.role_manifest_generation.to_be_bytes());
        bytes.extend_from_slice(&self.authority_domain);
        bytes.extend_from_slice(&self.signer_policy);
        bytes.extend_from_slice(&self.signer_policy_version.to_be_bytes());
        bytes
    }
}

/// Exact pre-generation scope shared by the inert candidate and initial PoP.
///
/// Physical generation and signer-lifecycle root are intentionally absent;
/// MSG-03/MSG-04 introduce them only after accepted enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreGenerationSignerCoordinatesV1 {
    pub(crate) occurrence: String,
    pub(crate) signer_scope_policy: Sha256Digest,
    pub(crate) signer_scope_policy_version: u64,
    pub(crate) a2_chain_root: Sha256Digest,
    pub(crate) controlling_activation: Sha256Digest,
    pub(crate) dependency_anchor: Sha256Digest,
    pub(crate) resident: String,
    pub(crate) resident_generation: u64,
    pub(crate) role: String,
    pub(crate) role_manifest: Sha256Digest,
    pub(crate) role_manifest_generation: u64,
    pub(crate) authority_domain: String,
    pub(crate) activation_policy_version: u64,
    pub(crate) active_store_policy: Sha256Digest,
    pub(crate) active_store_policy_generation: u64,
}

impl PreGenerationSignerCoordinatesV1 {
    fn token(value: &str, maximum: usize) -> bool {
        !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
    }

    pub(crate) fn verify(&self) -> Result<(), SignerRefusalV2> {
        if !Self::token(&self.occurrence, 256)
            || !Self::token(&self.resident, 1024)
            || !Self::token(&self.role, 256)
            || !Self::token(&self.authority_domain, 256)
            || self.resident_generation == 0
            || self.role_manifest_generation == 0
            || self.signer_scope_policy_version == 0
            || self.activation_policy_version == 0
            || self.active_store_policy_generation == 0
            || [
                self.resident_generation,
                self.role_manifest_generation,
                self.signer_scope_policy_version,
                self.activation_policy_version,
                self.active_store_policy_generation,
            ]
            .into_iter()
            .any(|value| value > IJSON_SAFE_INTEGER)
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Result<Vec<u8>, SignerRefusalV2> {
        self.verify()?;
        canonical_json_bytes(self).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)
    }
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
    pub(crate) coordinates: PreGenerationSignerCoordinatesV1,
    pub(crate) public_key: [u8; 32],
    pub(crate) key_generation: u64,
    pub(crate) active_policy: SignerIdentityV1,
    pub(crate) active_policy_generation: u64,
}

fn candidate_identity(
    candidate: &StoreIntegrityEnrollmentCandidateV1,
) -> Result<SignerIdentityV1, SignerRefusalV2> {
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
    let coordinate_bytes = candidate.coordinates.identity_bytes()?;
    parts.push(&coordinate_bytes);
    Ok(exact_identity(ENROLLMENT_CANDIDATE_DOMAIN, &parts))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_05a_candidate(
    candidate_cut: u64,
    attempt_identity: SignerIdentityV1,
    proposal_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    grant_request_identity: SignerIdentityV1,
    coordinates: PreGenerationSignerCoordinatesV1,
    public_key: [u8; 32],
    key_generation: u64,
    active_policy: SignerIdentityV1,
    active_policy_generation: u64,
) -> Result<StoreIntegrityEnrollmentCandidateV1, SignerRefusalV2> {
    coordinates.verify()?;
    if candidate_cut == 0
        || candidate_cut > IJSON_SAFE_INTEGER
        || key_generation > IJSON_SAFE_INTEGER
        || active_policy_generation == 0
        || active_policy_generation > IJSON_SAFE_INTEGER
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
    candidate.identity = candidate_identity(&candidate)?;
    verify_sg_rec_05a_candidate(&candidate)?;
    Ok(candidate)
}

pub(crate) fn verify_sg_rec_05a_candidate(
    candidate: &StoreIntegrityEnrollmentCandidateV1,
) -> Result<(), SignerRefusalV2> {
    candidate.coordinates.verify()?;
    if candidate.candidate_cut == 0
        || candidate.candidate_cut > IJSON_SAFE_INTEGER
        || candidate.key_generation > IJSON_SAFE_INTEGER
        || candidate.active_policy_generation == 0
        || candidate.active_policy_generation > IJSON_SAFE_INTEGER
        || candidate.public_key.iter().all(|byte| *byte == 0)
        || VerifyingKey::from_bytes(&candidate.public_key).is_err()
        || candidate.active_policy != digest_identity(&candidate.coordinates.active_store_policy)?
        || candidate.active_policy_generation
            != candidate.coordinates.active_store_policy_generation
        || candidate.identity != candidate_identity(candidate)?
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

fn identity_digest(identity: &SignerIdentityV1) -> Result<Sha256Digest, SignerRefusalV2> {
    Sha256Digest::parse(format!("sha256:{}", hex::encode(identity)))
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn digest_identity(digest: &Sha256Digest) -> Result<SignerIdentityV1, SignerRefusalV2> {
    hex::decode(
        digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?,
    )
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
    .try_into()
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn text_coordinate_identity(
    domain: &[u8],
    value: &str,
) -> Result<SignerIdentityV1, SignerRefusalV2> {
    let mut preimage = Vec::with_capacity(domain.len() + value.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(value.as_bytes());
    digest_identity(&sha256_bytes(&preimage))
}

pub(crate) fn pre_generation_scope_identity_v1(
    coordinates: &PreGenerationSignerCoordinatesV1,
) -> Result<SignerIdentityV1, SignerRefusalV2> {
    let bytes = canonical_json_bytes(coordinates)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let mut preimage = b"nq.c2.pre_generation_signer_scope.identity.v1\0".to_vec();
    preimage.extend_from_slice(&bytes);
    digest_identity(&sha256_bytes(&preimage))
}

/// Store-verified request for the sole pre-standing signing route, MSG-02.
///
/// The request borrows the exact same-snapshot authority, admitted
/// implementation, grant, inert candidate, and descriptor-authenticated
/// custody proof. It is noncloneable and nonserializable. Its scalar
/// projections are signing inputs only and have no reverse authority
/// constructor.
pub(crate) struct VerifiedInitialPossessionRequestV1<'request, 'store> {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    authority_snapshot: &'request StoreC2AuthoritySnapshotV1<'store>,
    admitted_manifest: &'request StoreAdmittedSignerImplementationManifestV1<'request, 'store>,
    grant_adoption: &'request StoreAdoptedBootstrapGrantV1,
    candidate: &'request StoreIntegrityEnrollmentCandidateV1,
    custody: &'request VerifiedFoundationalCustodyV1<'request>,
    challenge_identity: SignerIdentityV1,
    public_key_identity: SignerIdentityV1,
    pre_generation_scope_identity: SignerIdentityV1,
    event_cut: u64,
    frontier_namespace_identity: SignerIdentityV1,
    predecessor_frontier_identity: SignerIdentityV1,
    exact_content_identity: SignerIdentityV1,
    creator_pid: u32,
}

impl VerifiedInitialPossessionRequestV1<'_, '_> {
    const fn grant(&self) -> &VerifiedBootstrapGrantV1 {
        self.grant_adoption.verified()
    }

    /// Re-establish that this sealed request still belongs to the exact
    /// unmodified Store actor that minted it. Scalar coordinates alone cannot
    /// satisfy this check.
    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        actor
            .verify_authority_lineage(self.authority_snapshot)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if actor.actor_instance_identity() != &self.actor_instance_identity
            || actor.current_snapshot_identity() != &self.actor_snapshot_identity
            || actor.effect_epoch() != self.actor_effect_epoch
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        verify_initial_possession_request_v1(self)
    }

    pub(crate) fn occurrence_id(&self) -> &str {
        &self.candidate.coordinates.occurrence
    }

    pub(crate) fn occurrence_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        text_coordinate_identity(
            b"nq.c2.store_occurrence.identity.v1\0",
            self.occurrence_id(),
        )
    }

    pub(crate) fn resident_identity(&self) -> &str {
        &self.candidate.coordinates.resident
    }

    pub(crate) const fn resident_generation(&self) -> u64 {
        self.candidate.coordinates.resident_generation
    }

    pub(crate) fn host_role(&self) -> &str {
        &self.candidate.coordinates.role
    }

    pub(crate) fn role_manifest_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(&self.candidate.coordinates.role_manifest)
    }

    pub(crate) const fn role_manifest_generation(&self) -> u64 {
        self.candidate.coordinates.role_manifest_generation
    }

    pub(crate) fn authority_domain(&self) -> &str {
        &self.candidate.coordinates.authority_domain
    }

    pub(crate) fn terminal_a1_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        let identity = Sha256Digest::parse(self.grant().issuer().digest.clone())
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        digest_identity(&identity)
    }

    pub(crate) fn current_a2_snapshot_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(
            self.authority_snapshot
                .current_activation()
                .controlling_tip_activation_digest(),
        )
    }

    pub(crate) const fn grant_identity(&self) -> SignerIdentityV1 {
        *self.grant().grant_identity().bytes()
    }

    pub(crate) const fn candidate_identity(&self) -> SignerIdentityV1 {
        self.candidate.identity
    }

    pub(crate) const fn proposal_identity(&self) -> SignerIdentityV1 {
        self.candidate.proposal_identity
    }

    pub(crate) const fn challenge_identity(&self) -> SignerIdentityV1 {
        self.challenge_identity
    }

    pub(crate) const fn public_key(&self) -> [u8; 32] {
        self.candidate.public_key
    }

    pub(crate) const fn public_key_identity(&self) -> SignerIdentityV1 {
        self.public_key_identity
    }

    pub(crate) const fn signer_key_generation(&self) -> u64 {
        self.candidate.key_generation
    }

    pub(crate) fn signer_key_generation_identity(&self) -> SignerIdentityV1 {
        self.custody.key_generation_identity()
    }

    pub(crate) const fn signer_scope_identity(&self) -> SignerIdentityV1 {
        self.pre_generation_scope_identity
    }

    pub(crate) fn signer_scope_policy_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(&self.candidate.coordinates.signer_scope_policy)
    }

    pub(crate) const fn signer_scope_policy_version(&self) -> u64 {
        self.candidate.coordinates.signer_scope_policy_version
    }

    pub(crate) const fn active_store_policy_identity(&self) -> SignerIdentityV1 {
        self.candidate.active_policy
    }

    pub(crate) const fn active_store_policy_generation(&self) -> u64 {
        self.candidate.active_policy_generation
    }

    pub(crate) const fn active_store_policy_digest(&self) -> SignerIdentityV1 {
        self.candidate.active_policy
    }

    pub(crate) const fn attempt_identity(&self) -> SignerIdentityV1 {
        self.candidate.attempt_identity
    }

    pub(crate) const fn event_cut(&self) -> u64 {
        self.event_cut
    }

    pub(crate) const fn predecessor_event_identity(&self) -> SignerIdentityV1 {
        self.candidate.identity
    }

    pub(crate) const fn transaction_intent_identity(&self) -> SignerIdentityV1 {
        self.candidate.attempt_identity
    }

    pub(crate) fn implementation_manifest_identity(
        &self,
    ) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(self.admitted_manifest.manifest_identity())
    }

    pub(crate) fn manifest_admission_correspondence_identity(
        &self,
    ) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(&self.admitted_manifest.correspondence_identity())
    }

    pub(crate) fn qualified_candidate_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(self.admitted_manifest.qualified_candidate_identity())
    }

    pub(crate) fn source_tree_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(self.admitted_manifest.source_tree_identity())
    }

    pub(crate) fn runtime_artifact_identity(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(self.admitted_manifest.runtime_artifact_identity())
    }

    pub(crate) const fn frontier_namespace_identity(&self) -> SignerIdentityV1 {
        self.frontier_namespace_identity
    }

    pub(crate) const fn predecessor_frontier_identity(&self) -> SignerIdentityV1 {
        self.predecessor_frontier_identity
    }

    pub(crate) const fn exact_content_identity(&self) -> SignerIdentityV1 {
        self.exact_content_identity
    }

    pub(crate) const fn store_snapshot_identity(&self) -> &Sha256Digest {
        self.authority_snapshot
            .admission_basis()
            .store_snapshot_identity()
    }

    pub(crate) const fn store_instance_identity(&self) -> &Sha256Digest {
        self.authority_snapshot
            .admission_basis()
            .store_instance_identity()
    }

    pub(crate) const fn process_identity(&self) -> &Sha256Digest {
        self.authority_snapshot.admission_basis().process_identity()
    }

    /// Exact verified custody borrowed by this request. This remains a sealed
    /// process-local proof; scalar callers cannot replace it.
    pub(super) const fn custody(&self) -> &VerifiedFoundationalCustodyV1<'_> {
        self.custody
    }
}

/// Mint an exact MSG-02 request. No foundational enrollment, signer
/// acceptance, or standing exists at this point; the request permits only the
/// proposed key's possession proof through the closed MSG-02 route.
pub(crate) fn construct_verified_initial_possession_request_v1<'request, 'store>(
    actor: &StoreC2SnapshotActorV1<'store>,
    authority_snapshot: &'request StoreC2AuthoritySnapshotV1<'store>,
    admitted_manifest: &'request StoreAdmittedSignerImplementationManifestV1<'request, 'store>,
    grant_adoption: &'request StoreAdoptedBootstrapGrantV1,
    candidate: &'request StoreIntegrityEnrollmentCandidateV1,
    custody: &'request VerifiedFoundationalCustodyV1<'request>,
) -> Result<VerifiedInitialPossessionRequestV1<'request, 'store>, SignerRefusalV2> {
    actor
        .verify_authority_lineage(authority_snapshot)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    authority_snapshot
        .verify_same_process_and_snapshot()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    verify_store_admitted_signer_implementation_manifest_basis_v1(
        admitted_manifest,
        authority_snapshot.admission_basis(),
    )
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    verify_sg_rec_05a_candidate(candidate)?;
    grant_adoption.verify_for_actor(actor)?;
    let grant = grant_adoption.verified();
    custody.verify_same_process()?;
    let current = authority_snapshot.current_activation();
    let scope = pre_generation_scope_identity_v1(&candidate.coordinates)?;
    let proposal = digest_identity(custody.proposal_identity())?;
    let active_policy = digest_identity(&candidate.coordinates.active_store_policy)?;
    if candidate.grant_identity != *grant.grant_identity().bytes()
        || candidate.grant_request_identity != *grant.request_identity().bytes()
        || candidate.proposal_identity != proposal
        || candidate.proposal_identity != grant.proposal_identity_bytes()
        || candidate.public_key != custody.public_key()
        || candidate.public_key != grant.store_integrity_public_key()
        || candidate.key_generation != custody.key_generation()
        || candidate.key_generation != grant.proposed_key_generation()
        || candidate.active_policy != active_policy
        || candidate.active_policy != grant.installed_policy_calculation_identity()
        || candidate.active_policy_generation
            != candidate.coordinates.active_store_policy_generation
        || candidate.coordinates.occurrence != grant.occurrence_id()
        || candidate.coordinates.occurrence != current.occurrence_id()
        || candidate.coordinates.a2_chain_root.as_str() != grant.a2_chain_root()
        || &candidate.coordinates.a2_chain_root != current.chain_root_activation_digest()
        || candidate.coordinates.controlling_activation.as_str() != grant.controlling_activation()
        || &candidate.coordinates.controlling_activation
            != current.controlling_tip_activation_digest()
        || &candidate.coordinates.dependency_anchor != current.trust_anchor_id()
        || candidate.coordinates.resident != grant.resident_identity()
        || candidate.coordinates.resident != current.resident_identity()
        || candidate.coordinates.resident_generation != grant.resident_generation()
        || candidate.coordinates.resident_generation != current.resident_generation()
        || candidate.coordinates.role != grant.host_role()
        || candidate.coordinates.role != current.host_role()
        || candidate.coordinates.role_manifest_generation != grant.role_manifest_generation()
        || candidate.coordinates.role_manifest_generation != current.role_manifest_generation()
        || candidate.coordinates.authority_domain != grant.authority_domain()
        || candidate.coordinates.authority_domain != current.domain()
        || candidate.coordinates.signer_scope_policy.as_str() != grant.signer_scope_policy()
        || candidate.coordinates.signer_scope_policy_version != grant.signer_scope_policy_version()
        || candidate.coordinates.activation_policy_version != grant.activation_policy_version()
        || candidate.coordinates.activation_policy_version != current.policy_version()
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }

    let event_cut = candidate
        .candidate_cut
        .checked_add(1)
        .filter(|cut| *cut <= IJSON_SAFE_INTEGER)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let snapshot = digest_identity(
        authority_snapshot
            .admission_basis()
            .store_snapshot_identity(),
    )?;
    let process = digest_identity(authority_snapshot.admission_basis().process_identity())?;
    let store_instance = digest_identity(
        authority_snapshot
            .admission_basis()
            .store_instance_identity(),
    )?;
    let manifest = digest_identity(admitted_manifest.manifest_identity())?;
    let challenge_identity = exact_identity(
        b"nq.c2.store_integrity_initial_pop.challenge.identity.v1",
        &[
            &snapshot,
            &process,
            &candidate.grant_identity,
            &candidate.identity,
            &candidate.proposal_identity,
            &candidate.attempt_identity,
        ],
    );
    let public_key_identity = exact_identity(
        b"nq.c2.store_integrity_public_key.identity.v1",
        &[&candidate.public_key],
    );
    let frontier_namespace_identity = exact_identity(
        b"nq.c2.store_integrity_initial_pop.frontier_namespace.identity.v1",
        &[&store_instance, &scope, &candidate.attempt_identity],
    );
    let predecessor_frontier_identity = exact_identity(
        b"nq.c2.store_integrity_initial_pop.predecessor_frontier.identity.v1",
        &[&candidate.grant_identity, &candidate.identity],
    );
    let exact_content_identity = exact_identity(
        b"nq.c2.store_integrity_initial_pop.exact_content.identity.v1",
        &[
            &grant.canonical_carrier_digest(),
            &candidate.identity,
            &candidate.proposal_identity,
            &digest_identity(custody.custody_evidence_identity())?,
            &scope,
            &challenge_identity,
            &manifest,
            &snapshot,
        ],
    );
    let request = VerifiedInitialPossessionRequestV1 {
        actor_instance_identity: actor.actor_instance_identity().clone(),
        actor_snapshot_identity: actor.current_snapshot_identity().clone(),
        actor_effect_epoch: actor.effect_epoch(),
        authority_snapshot,
        admitted_manifest,
        grant_adoption,
        candidate,
        custody,
        challenge_identity,
        public_key_identity,
        pre_generation_scope_identity: scope,
        event_cut,
        frontier_namespace_identity,
        predecessor_frontier_identity,
        exact_content_identity,
        creator_pid: std::process::id(),
    };
    verify_initial_possession_request_v1(&request)?;
    Ok(request)
}

pub(crate) fn verify_initial_possession_request_v1(
    request: &VerifiedInitialPossessionRequestV1<'_, '_>,
) -> Result<(), SignerRefusalV2> {
    if request.creator_pid != std::process::id() {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    request
        .authority_snapshot
        .verify_same_process_and_snapshot()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    // The immutable authority snapshot remains the operation's A2/manifest
    // lineage root, while durable MSG-01 ingress advances the actor snapshot
    // before MSG-02 can be constructed.  Bind the possession request to that
    // exact post-adoption cut; equating it to the pre-ingress admission
    // snapshot makes the production continuation uninhabitable.
    if request.actor_snapshot_identity
        != *request
            .grant_adoption
            .post_adoption_snapshot_identity()
        || request.actor_effect_epoch != request.grant_adoption.post_adoption_effect_epoch()
        || request.actor_effect_epoch > IJSON_SAFE_INTEGER
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_store_admitted_signer_implementation_manifest_basis_v1(
        request.admitted_manifest,
        request.authority_snapshot.admission_basis(),
    )
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    request.custody.verify_same_process()?;
    verify_sg_rec_05a_candidate(request.candidate)?;
    if request.event_cut <= request.candidate.candidate_cut
        || request.pre_generation_scope_identity
            != pre_generation_scope_identity_v1(&request.candidate.coordinates)?
        || request.public_key() != request.custody.public_key()
        || request.signer_key_generation() != request.custody.key_generation()
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

/// Mechanically derive the canonical pre-generation foundational enrollment
/// from the exact actor-bound MSG-02 result.
///
/// The caller selects only the install-policy retention maximum. Every
/// authority, candidate, custody, signature, identity and cut coordinate is
/// projected from the already verified request/MSG-01/MSG-02 chain. The
/// resulting value remains inert evidence; only the Store adoption method can
/// consume it into the later signer-acceptance transition.
pub(crate) fn derive_initial_foundational_enrollment_v1(
    consumed: &ConsumedInitialProposalPoPV1<'_, '_>,
    maximum_key_generations: u32,
) -> Result<StoreIntegrityKeyEnrollmentV1, SignerRefusalV2> {
    let request = consumed.request();
    verify_initial_possession_request_v1(request)?;
    let candidate = request.candidate;
    let grant = request.grant();
    let coordinates = &candidate.coordinates;
    let enrollment_cut = consumed
        .event_cut()
        .checked_add(1)
        .filter(|cut| *cut <= IJSON_SAFE_INTEGER)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let key_generation = u32::try_from(candidate.key_generation)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let issuer_identity = Sha256Digest::parse(grant.issuer().digest.clone())
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let input = StoreIntegrityKeyEnrollmentInputV1 {
        occurrence: StoreOccurrenceIdentityV1::new(coordinates.occurrence.clone())
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?,
        signer_scope_policy: SignerScopePolicyIdentityV1::new(
            coordinates.signer_scope_policy.clone(),
        ),
        signer_scope_policy_version: coordinates.signer_scope_policy_version,
        a2_chain_root: A2ChainRootIdentityV1::new(coordinates.a2_chain_root.clone()),
        controlling_activation: ControllingActivationIdentityV1::new(
            coordinates.controlling_activation.clone(),
        ),
        dependency_anchor: DependencyAnchorIdentityV1::new(coordinates.dependency_anchor.clone()),
        resident: ResidentIdentityV1::new(coordinates.resident.clone())
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?,
        resident_generation: coordinates.resident_generation,
        role: coordinates.role.clone(),
        role_manifest: RoleManifestIdentityV1::new(coordinates.role_manifest.clone()),
        role_manifest_generation: coordinates.role_manifest_generation,
        domain: coordinates.authority_domain.clone(),
        activation_policy_version: coordinates.activation_policy_version,
        active_store_policy: ActiveStorePolicyIdentityV1::new(
            coordinates.active_store_policy.clone(),
        ),
        active_store_policy_generation: coordinates.active_store_policy_generation,
        authority_cut: C2StructuralCutV1 {
            ledger_position: grant.lifecycle_cut(),
            effect_position: 0,
        },
        candidate_cut: C2StructuralCutV1 {
            ledger_position: candidate.candidate_cut,
            effect_position: 0,
        },
        pop_cut: C2StructuralCutV1 {
            ledger_position: consumed.event_cut(),
            effect_position: 0,
        },
        enrollment_cut: C2StructuralCutV1 {
            ledger_position: enrollment_cut,
            effect_position: 0,
        },
        public_key: Ed25519StoreIntegrityPublicKeyV1::from_lower_hex(hex::encode(
            candidate.public_key,
        ))
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?,
        key_generation: StoreIntegrityKeyGenerationV1::new(key_generation)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?,
        predecessor_enrollment: None,
        maximum_retained_key_generations: maximum_key_generations,
        provenance_purposes: BTreeSet::from([
            EnrollmentProvenancePurposeV1::PhysicalGenerationBootstrapVerification,
            EnrollmentProvenancePurposeV1::ActivePolicyFrameVerification,
            EnrollmentProvenancePurposeV1::InstallationFrameVerification,
        ]),
        bootstrap_grant_request: BootstrapGrantRequestIdentityV1::new(identity_digest(
            grant.request_identity().bytes(),
        )?),
        bootstrap_grant: BootstrapGrantIdentityV1::new(identity_digest(
            grant.grant_identity().bytes(),
        )?),
        bootstrap_grant_signature: Ed25519SignatureBytesV1::from_lower_hex(hex::encode(
            grant.canonical_signature(),
        ))
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?,
        bootstrap_issuer: TerminalA1IssuerIdentityV1::new(issuer_identity),
        bootstrap_issuer_key_generation: grant.issuer().key_generation,
        attempt_identity: StoreIntegrityEnrollmentAttemptIdentityV1::new(identity_digest(
            &candidate.attempt_identity,
        )?),
        proposal_identity: StoreIntegrityProposalIdentityV1::new(identity_digest(
            &candidate.proposal_identity,
        )?),
        candidate_identity: StoreIntegrityEnrollmentCandidateIdentityV1::new(identity_digest(
            &candidate.identity,
        )?),
        custody_evidence_identity: StoreIntegrityCustodyEvidenceIdentityV1::new(
            request.custody.custody_evidence_identity().clone(),
        ),
        proof_of_possession_identity: StoreIntegrityProofOfPossessionIdentityV1::new(
            identity_digest(&consumed.message_identity())?,
        ),
        interpretation_policy: A2ApplicabilityInterpretationIdentityV1::new(
            grant.interpretation_policy(),
        )
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?,
        predecessor_grant: None,
        superseded_grant: None,
    };
    let foundational = construct_n_18_key_enrollment(input)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    verify_n_18_key_enrollment(&foundational)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    Ok(foundational)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreIntegritySignerFoundationBodyV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    algorithm: String,
    public_key: String,
    key_generation: u64,
    custody_evidence_identity: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreIntegritySignerFoundationWireV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    foundation_identity: Sha256Digest,
    algorithm: String,
    public_key: String,
    key_generation: u64,
    custody_evidence_identity: Sha256Digest,
}

/// Canonical durable definition of one stable semantic key/custody foundation.
///
/// This record deliberately contains no adoption lineage, Store cut, grant,
/// candidate, process, snapshot, standing, or permit.  Possessing or decoding
/// it yields inert evidence only.  A restore event may therefore refer to this
/// exact identity again while recording a distinct adoption-event identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreIntegritySignerFoundationV1 {
    wire: StoreIntegritySignerFoundationWireV1,
    canonical_bytes: Vec<u8>,
}

impl Serialize for StoreIntegritySignerFoundationV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.wire.serialize(serializer)
    }
}

impl StoreIntegritySignerFoundationV1 {
    pub(crate) const fn identity(&self) -> &Sha256Digest {
        &self.wire.foundation_identity
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn public_key(&self) -> Result<[u8; 32], SignerRefusalV2> {
        hex::decode(&self.wire.public_key)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?
            .try_into()
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)
    }

    pub(crate) const fn key_generation(&self) -> u64 {
        self.wire.key_generation
    }

    pub(crate) const fn custody_evidence_identity(&self) -> &Sha256Digest {
        &self.wire.custody_evidence_identity
    }

    fn public_key_identity(&self) -> Result<Sha256Digest, SignerRefusalV2> {
        stable_public_key_identity_v1(&self.public_key()?)
    }

    fn key_generation_identity(&self) -> Result<Sha256Digest, SignerRefusalV2> {
        stable_key_generation_identity_v1(&self.public_key()?, self.wire.key_generation)
    }
}

fn signer_foundation_body_v1(
    public_key: [u8; 32],
    key_generation: u64,
    custody_evidence_identity: Sha256Digest,
) -> StoreIntegritySignerFoundationBodyV1 {
    StoreIntegritySignerFoundationBodyV1 {
        schema: SIGNER_FOUNDATION_SCHEMA_V1.to_owned(),
        schema_version: 1,
        identity_domain: SIGNER_FOUNDATION_IDENTITY_DOMAIN_V1.to_owned(),
        algorithm: "ed25519".to_owned(),
        public_key: hex::encode(public_key),
        key_generation,
        custody_evidence_identity,
    }
}

/// Construct inert canonical foundation evidence from an exact key/custody
/// basis.  This is intentionally not an authority constructor.
pub(crate) fn construct_store_integrity_signer_foundation_v1(
    public_key: [u8; 32],
    key_generation: u64,
    custody_evidence_identity: Sha256Digest,
) -> Result<StoreIntegritySignerFoundationV1, SignerRefusalV2> {
    if key_generation > IJSON_SAFE_INTEGER {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let body = signer_foundation_body_v1(public_key, key_generation, custody_evidence_identity);
    let foundation_identity =
        semantic_digest(&body).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let wire = StoreIntegritySignerFoundationWireV1 {
        schema: body.schema,
        schema_version: body.schema_version,
        identity_domain: body.identity_domain,
        foundation_identity,
        algorithm: body.algorithm,
        public_key: body.public_key,
        key_generation: body.key_generation,
        custody_evidence_identity: body.custody_evidence_identity,
    };
    let canonical_bytes =
        canonical_json_bytes(&wire).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let foundation = StoreIntegritySignerFoundationV1 {
        wire,
        canonical_bytes,
    };
    verify_store_integrity_signer_foundation_v1(&foundation)?;
    Ok(foundation)
}

pub(crate) fn verify_store_integrity_signer_foundation_v1(
    foundation: &StoreIntegritySignerFoundationV1,
) -> Result<(), SignerRefusalV2> {
    let public_key = foundation
        .public_key()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if foundation.wire.schema != SIGNER_FOUNDATION_SCHEMA_V1
        || foundation.wire.schema_version != 1
        || foundation.wire.identity_domain != SIGNER_FOUNDATION_IDENTITY_DOMAIN_V1
        || foundation.wire.algorithm != "ed25519"
        || foundation.wire.public_key != hex::encode(public_key)
        || foundation.wire.key_generation > IJSON_SAFE_INTEGER
        || canonical_json_bytes(&foundation.wire)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
            != foundation.canonical_bytes
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let body = signer_foundation_body_v1(
        public_key,
        foundation.wire.key_generation,
        foundation.wire.custody_evidence_identity.clone(),
    );
    if semantic_digest(&body).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
        != foundation.wire.foundation_identity
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

pub(crate) fn decode_store_integrity_signer_foundation_v1(
    bytes: &[u8],
) -> Result<StoreIntegritySignerFoundationV1, SignerRefusalV2> {
    let wire: StoreIntegritySignerFoundationWireV1 =
        serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let canonical_bytes =
        canonical_json_bytes(&wire).map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    if canonical_bytes != bytes {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }
    let foundation = StoreIntegritySignerFoundationV1 {
        wire,
        canonical_bytes,
    };
    verify_store_integrity_signer_foundation_v1(&foundation)
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    Ok(foundation)
}

fn stable_public_key_identity_v1(public_key: &[u8; 32]) -> Result<Sha256Digest, SignerRefusalV2> {
    identity_digest(&exact_identity(
        b"nq.c2.store_integrity_public_key.identity.v1",
        &[public_key],
    ))
}

fn stable_key_generation_identity_v1(
    public_key: &[u8; 32],
    key_generation: u64,
) -> Result<Sha256Digest, SignerRefusalV2> {
    identity_digest(&exact_identity(
        b"nq.c2.store_integrity_stable_key_generation.identity.v1",
        &[public_key, &key_generation.to_be_bytes()],
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FoundationalAdoptionBodyV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    foundation_identity: Sha256Digest,
    lineage: FoundationalAdoptionLineageV1,
    lineage_reference_identity: Sha256Digest,
    authority_reference_identity: Sha256Digest,
    store_identity: Sha256Digest,
    occurrence_identity: Sha256Digest,
    signer_scope_identity: Sha256Digest,
    physical_generation_identity: Option<Sha256Digest>,
    lifecycle_root_identity: Option<Sha256Digest>,
    frontier_identity: Option<Sha256Digest>,
    current_predecessor_identity: Option<Sha256Digest>,
    transition_identity: Option<Sha256Digest>,
    transaction_identity: Sha256Digest,
    policy_basis_identity: Sha256Digest,
    applicability_basis_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    candidate_identity: Sha256Digest,
    proposal_identity: Sha256Digest,
    challenge_identity: Sha256Digest,
    proof_of_possession_identity: Sha256Digest,
    custody_evidence_identity: Sha256Digest,
    public_key_identity: Sha256Digest,
    key_generation_identity: Sha256Digest,
    enrollment_cut: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FoundationalAdoptionWireV1 {
    adoption_identity: Sha256Digest,
    #[serde(flatten)]
    body: FoundationalAdoptionBodyV1,
}

/// One canonical durable adoption event.  Its identity is distinct from the
/// stable foundation identity and binds the complete lineage, Store cut, and
/// exact semantic coordinates selected for this event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreIntegrityFoundationalAdoptionV1 {
    wire: FoundationalAdoptionWireV1,
    canonical_bytes: Vec<u8>,
}

impl Serialize for StoreIntegrityFoundationalAdoptionV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.wire.serialize(serializer)
    }
}

impl StoreIntegrityFoundationalAdoptionV1 {
    pub(crate) const fn identity(&self) -> &Sha256Digest {
        &self.wire.adoption_identity
    }

    pub(crate) const fn foundation_identity(&self) -> &Sha256Digest {
        &self.wire.body.foundation_identity
    }

    pub(crate) const fn lineage(&self) -> FoundationalAdoptionLineageV1 {
        self.wire.body.lineage
    }

    pub(crate) const fn enrollment_cut(&self) -> u64 {
        self.wire.body.enrollment_cut
    }

    pub(crate) const fn lineage_reference_identity(&self) -> &Sha256Digest {
        &self.wire.body.lineage_reference_identity
    }

    pub(crate) const fn authority_reference_identity(&self) -> &Sha256Digest {
        &self.wire.body.authority_reference_identity
    }

    pub(crate) const fn store_identity(&self) -> &Sha256Digest {
        &self.wire.body.store_identity
    }

    pub(crate) const fn occurrence_identity(&self) -> &Sha256Digest {
        &self.wire.body.occurrence_identity
    }

    pub(crate) const fn signer_scope_identity(&self) -> &Sha256Digest {
        &self.wire.body.signer_scope_identity
    }

    pub(crate) const fn physical_generation_identity(&self) -> Option<&Sha256Digest> {
        self.wire.body.physical_generation_identity.as_ref()
    }

    pub(crate) const fn lifecycle_root_identity(&self) -> Option<&Sha256Digest> {
        self.wire.body.lifecycle_root_identity.as_ref()
    }

    pub(crate) const fn frontier_identity(&self) -> Option<&Sha256Digest> {
        self.wire.body.frontier_identity.as_ref()
    }

    pub(crate) const fn current_predecessor_identity(&self) -> Option<&Sha256Digest> {
        self.wire.body.current_predecessor_identity.as_ref()
    }

    pub(crate) const fn transition_identity(&self) -> Option<&Sha256Digest> {
        self.wire.body.transition_identity.as_ref()
    }

    pub(crate) const fn transaction_identity(&self) -> &Sha256Digest {
        &self.wire.body.transaction_identity
    }

    pub(crate) const fn policy_basis_identity(&self) -> &Sha256Digest {
        &self.wire.body.policy_basis_identity
    }

    pub(crate) const fn applicability_basis_identity(&self) -> &Sha256Digest {
        &self.wire.body.applicability_basis_identity
    }

    pub(crate) const fn attempt_identity(&self) -> &Sha256Digest {
        &self.wire.body.attempt_identity
    }

    pub(crate) const fn candidate_identity(&self) -> &Sha256Digest {
        &self.wire.body.candidate_identity
    }

    pub(crate) const fn proposal_identity(&self) -> &Sha256Digest {
        &self.wire.body.proposal_identity
    }

    pub(crate) const fn challenge_identity(&self) -> &Sha256Digest {
        &self.wire.body.challenge_identity
    }

    pub(crate) const fn proof_of_possession_identity(&self) -> &Sha256Digest {
        &self.wire.body.proof_of_possession_identity
    }

    pub(crate) const fn custody_evidence_identity(&self) -> &Sha256Digest {
        &self.wire.body.custody_evidence_identity
    }

    pub(crate) const fn public_key_identity(&self) -> &Sha256Digest {
        &self.wire.body.public_key_identity
    }

    pub(crate) const fn key_generation_identity(&self) -> &Sha256Digest {
        &self.wire.body.key_generation_identity
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

fn construct_foundational_adoption_record_v1(
    foundation: &StoreIntegritySignerFoundationV1,
    body: FoundationalAdoptionBodyV1,
) -> Result<StoreIntegrityFoundationalAdoptionV1, SignerRefusalV2> {
    verify_store_integrity_signer_foundation_v1(foundation)?;
    let adoption_identity =
        semantic_digest(&body).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let wire = FoundationalAdoptionWireV1 {
        adoption_identity,
        body,
    };
    let canonical_bytes =
        canonical_json_bytes(&wire).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let adoption = StoreIntegrityFoundationalAdoptionV1 {
        wire,
        canonical_bytes,
    };
    verify_foundational_adoption_record_v1(&adoption, foundation)?;
    Ok(adoption)
}

fn verify_foundational_adoption_record_v1(
    adoption: &StoreIntegrityFoundationalAdoptionV1,
    foundation: &StoreIntegritySignerFoundationV1,
) -> Result<(), SignerRefusalV2> {
    verify_store_integrity_signer_foundation_v1(foundation)?;
    let body = &adoption.wire.body;
    let generation_bound = [
        &body.physical_generation_identity,
        &body.lifecycle_root_identity,
        &body.frontier_identity,
        &body.current_predecessor_identity,
        &body.transition_identity,
    ];
    let shape_is_exact = match body.lineage {
        FoundationalAdoptionLineageV1::InitialExternal => {
            generation_bound
                .iter()
                .all(|coordinate| coordinate.is_none())
                && body.lineage_reference_identity == body.authority_reference_identity
        }
        FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity
        | FoundationalAdoptionLineageV1::RestoreHistorical
        | FoundationalAdoptionLineageV1::RecoveryNewFoundation => generation_bound
            .iter()
            .all(|coordinate| coordinate.is_some()),
    };
    if body.schema != FOUNDATIONAL_ADOPTION_SCHEMA_V1
        || body.schema_version != 1
        || body.identity_domain != FOUNDATIONAL_ADOPTION_IDENTITY_DOMAIN_V1
        || body.foundation_identity != *foundation.identity()
        || body.custody_evidence_identity != *foundation.custody_evidence_identity()
        || body.public_key_identity != foundation.public_key_identity()?
        || body.key_generation_identity != foundation.key_generation_identity()?
        || body.enrollment_cut == 0
        || body.enrollment_cut > IJSON_SAFE_INTEGER
        || !shape_is_exact
        || semantic_digest(body).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
            != adoption.wire.adoption_identity
        || canonical_json_bytes(&adoption.wire)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
            != adoption.canonical_bytes
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

fn decode_foundational_adoption_record_v1(
    bytes: &[u8],
    foundation: &StoreIntegritySignerFoundationV1,
) -> Result<StoreIntegrityFoundationalAdoptionV1, SignerRefusalV2> {
    let wire: FoundationalAdoptionWireV1 =
        serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let canonical_bytes =
        canonical_json_bytes(&wire).map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    if canonical_bytes != bytes {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }
    let adoption = StoreIntegrityFoundationalAdoptionV1 {
        wire,
        canonical_bytes,
    };
    verify_foundational_adoption_record_v1(&adoption, foundation)
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    Ok(adoption)
}

/// Store-private process-local adoption of exact foundational evidence.
///
/// The default provenance is the narrow initial/bootstrap route so existing
/// bootstrap consumers can only observe N18/MSG-02 facts on that type.  The
/// non-initial provenance can be constructed only by consuming the opaque
/// Store authority minted by the live-C2 resolver.  Neither provenance is
/// cloneable or serializable, and scalar identities cannot construct either.
pub(crate) struct InitialExternalFoundationalAdoptionProvenanceV1 {
    foundational: StoreIntegrityKeyEnrollmentV1,
    candidate: StoreIntegrityEnrollmentCandidateV1,
    challenge_identity: SignerIdentityV1,
    pop_identity: SignerIdentityV1,
    pop_cut: u64,
    msg02_append_identity: Sha256Digest,
    msg02_effect_receipt_identity: Sha256Digest,
    msg02_resulting_frontier_identity: SignerIdentityV1,
}

/// Opaque non-initial provenance.  Its sole field has no raw-parts
/// constructor and is itself a consumed, process-local Store authority.
pub(crate) struct StoreConsumedFoundationalAdoptionProvenanceV1 {
    authority: ConsumedStoreFoundationAdoptionAuthorityV1,
}

mod foundational_adoption_provenance_sealed {
    pub trait Sealed {}
}

use foundational_adoption_provenance_sealed::Sealed as SealedAdoptionProvenanceV1;

impl SealedAdoptionProvenanceV1 for InitialExternalFoundationalAdoptionProvenanceV1 {}
impl SealedAdoptionProvenanceV1 for StoreConsumedFoundationalAdoptionProvenanceV1 {}

pub(crate) struct FoundationalAdoptionMaterialViewV1<'adoption> {
    adoption_identity: &'adoption Sha256Digest,
    foundation: &'adoption StoreIntegritySignerFoundationV1,
    adoption_record: &'adoption StoreIntegrityFoundationalAdoptionV1,
    custody_evidence_identity: &'adoption Sha256Digest,
    pre_effect_store_snapshot_identity: &'adoption Sha256Digest,
}

pub(crate) trait FoundationalAdoptionProvenanceV1: SealedAdoptionProvenanceV1 {
    fn candidate_identity(&self) -> SignerIdentityV1;
    fn attempt_identity(&self) -> SignerIdentityV1;
    fn proof_of_possession_identity(&self) -> SignerIdentityV1;
    fn candidate_cut(&self) -> u64;
    fn proof_cut(&self) -> u64;
    fn initial(&self) -> Option<&InitialExternalFoundationalAdoptionProvenanceV1> {
        None
    }
    fn verify_material(
        &self,
        view: &FoundationalAdoptionMaterialViewV1<'_>,
    ) -> Result<(), SignerRefusalV2>;
}

pub(crate) struct StoreAdoptedFoundationalEnrollmentV1<
    Provenance = InitialExternalFoundationalAdoptionProvenanceV1,
> where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    adoption_identity: Sha256Digest,
    adoption_effect_identity: Sha256Digest,
    adoption_receipt_identity: Sha256Digest,
    foundation: StoreIntegritySignerFoundationV1,
    adoption_record: StoreIntegrityFoundationalAdoptionV1,
    provenance: Provenance,
    custody_evidence_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    // The adoption transaction is bound to the snapshot that existed before
    // its append.  `store_snapshot_identity` advances when the actor seals the
    // append and therefore cannot serve as this durable transaction premise.
    pre_effect_store_snapshot_identity: Sha256Digest,
    store_snapshot_identity: Sha256Digest,
    process_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

impl<Provenance> StoreAdoptedFoundationalEnrollmentV1<Provenance>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    pub(crate) const fn adoption_identity(&self) -> &Sha256Digest {
        &self.adoption_identity
    }

    pub(crate) const fn adoption_effect_identity(&self) -> &Sha256Digest {
        &self.adoption_effect_identity
    }

    pub(crate) const fn adoption_receipt_identity(&self) -> &Sha256Digest {
        &self.adoption_receipt_identity
    }

    pub(crate) const fn foundation(&self) -> &StoreIntegritySignerFoundationV1 {
        &self.foundation
    }

    pub(crate) const fn adoption_record(&self) -> &StoreIntegrityFoundationalAdoptionV1 {
        &self.adoption_record
    }

    pub(crate) const fn store_snapshot_identity(&self) -> &Sha256Digest {
        &self.store_snapshot_identity
    }

    pub(crate) const fn process_identity(&self) -> &Sha256Digest {
        &self.process_identity
    }

    pub(crate) const fn custody_evidence_identity(&self) -> &Sha256Digest {
        &self.custody_evidence_identity
    }

    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        verify_foundational_adoption_material_v1(self)?;
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if self.creator_pid != std::process::id()
            || actor.actor_instance_identity() != &self.actor_instance_identity
            || actor.current_snapshot_identity() != &self.store_snapshot_identity
            || actor.effect_epoch() != self.actor_effect_epoch
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }
}

impl StoreAdoptedFoundationalEnrollmentV1<InitialExternalFoundationalAdoptionProvenanceV1> {
    pub(crate) const fn foundational(&self) -> &StoreIntegrityKeyEnrollmentV1 {
        &self.provenance.foundational
    }

    pub(crate) const fn candidate_identity(&self) -> SignerIdentityV1 {
        self.provenance.candidate.identity
    }

    pub(crate) const fn pop_identity(&self) -> SignerIdentityV1 {
        self.provenance.pop_identity
    }

    pub(crate) const fn pop_cut(&self) -> u64 {
        self.provenance.pop_cut
    }

    pub(crate) const fn attempt_identity(&self) -> SignerIdentityV1 {
        self.provenance.candidate.attempt_identity
    }

    pub(crate) const fn candidate(&self) -> &StoreIntegrityEnrollmentCandidateV1 {
        &self.provenance.candidate
    }

    pub(crate) const fn msg02_append_identity(&self) -> &Sha256Digest {
        &self.provenance.msg02_append_identity
    }

    pub(crate) const fn msg02_effect_receipt_identity(&self) -> &Sha256Digest {
        &self.provenance.msg02_effect_receipt_identity
    }

    pub(crate) const fn msg02_resulting_frontier_identity(&self) -> SignerIdentityV1 {
        self.provenance.msg02_resulting_frontier_identity
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InitialAdoptionTransactionIdentityBodyV1 {
    schema: &'static str,
    identity_domain: &'static str,
    store_identity: Sha256Digest,
    pre_effect_store_snapshot_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    msg02_append_identity: Sha256Digest,
    enrollment_cut: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InitialAdoptionApplicabilityIdentityBodyV1 {
    schema: &'static str,
    identity_domain: &'static str,
    interpretation: &'static str,
    active_policy_identity: Sha256Digest,
    active_policy_generation: u64,
    controlling_activation_identity: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FoundationalAdoptionEffectBodyV1 {
    schema: &'static str,
    identity_domain: &'static str,
    adoption_identity: Sha256Digest,
}

fn foundational_adoption_effect_identity_v1(
    adoption_identity: &Sha256Digest,
) -> Result<Sha256Digest, SignerRefusalV2> {
    semantic_digest(&FoundationalAdoptionEffectBodyV1 {
        schema: "nq.c2_foundational_enrollment_adoption_effect_identity_preimage.v1",
        identity_domain: "nq.c2.foundational_enrollment_adoption_effect.identity.v1",
        adoption_identity: adoption_identity.clone(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FoundationalAdoptionReceiptV1 {
    schema: &'static str,
    adoption_identity: Sha256Digest,
    effect_identity: Sha256Digest,
    foundation_identity: Sha256Digest,
    lineage: FoundationalAdoptionLineageV1,
    proof_of_possession_identity: Sha256Digest,
    enrollment_cut: u64,
}

/// Opaque, actor-bound foundational adoption ready for the actor's private
/// transaction. It is not adopted authority until the durable append and
/// post-effect seal both succeed.
pub(crate) struct PreparedFoundationalEnrollmentAdoptionV1<
    Provenance = InitialExternalFoundationalAdoptionProvenanceV1,
> where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    adoption: StoreAdoptedFoundationalEnrollmentV1<Provenance>,
    receipt_bytes: Vec<u8>,
}

impl<Provenance> PreparedFoundationalEnrollmentAdoptionV1<Provenance>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        self.adoption.verify_for_actor(actor)
    }
}

/// Inert durable result returned by the private transaction append. The actor
/// must still seal it against its exact post-effect snapshot.
pub(crate) struct PersistedFoundationalEnrollmentAdoptionV1 {
    pub(crate) disposition: EnrollmentBridgeAppendDispositionV1,
    adoption_identity: Sha256Digest,
    effect_identity: Sha256Digest,
    receipt_identity: Sha256Digest,
}

impl FoundationalAdoptionProvenanceV1 for InitialExternalFoundationalAdoptionProvenanceV1 {
    fn candidate_identity(&self) -> SignerIdentityV1 {
        self.candidate.identity
    }

    fn attempt_identity(&self) -> SignerIdentityV1 {
        self.candidate.attempt_identity
    }

    fn proof_of_possession_identity(&self) -> SignerIdentityV1 {
        self.pop_identity
    }

    fn candidate_cut(&self) -> u64 {
        self.candidate.candidate_cut
    }

    fn proof_cut(&self) -> u64 {
        self.pop_cut
    }

    fn initial(&self) -> Option<&InitialExternalFoundationalAdoptionProvenanceV1> {
        Some(self)
    }

    fn verify_material(
        &self,
        view: &FoundationalAdoptionMaterialViewV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        verify_n_18_key_enrollment(&self.foundational)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        verify_sg_rec_05a_candidate(&self.candidate)?;
        let initial = &self.foundational;
        let durable = &view.adoption_record.wire.body;
        let candidate = &self.candidate;
        let candidate_identity = identity_digest(&candidate.identity)?;
        let pop_identity = identity_digest(&self.pop_identity)?;
        let challenge_identity = identity_digest(&self.challenge_identity)?;
        let attempt_identity = identity_digest(&candidate.attempt_identity)?;
        let proposal_identity = identity_digest(&candidate.proposal_identity)?;
        let grant_identity = identity_digest(&candidate.grant_identity)?;
        let scope_identity =
            identity_digest(&pre_generation_scope_identity_v1(&candidate.coordinates)?)?;
        let occurrence_identity = identity_digest(&text_coordinate_identity(
            b"nq.c2.store_occurrence.identity.v1\0",
            &candidate.coordinates.occurrence,
        )?)?;
        let expected_applicability = semantic_digest(&InitialAdoptionApplicabilityIdentityBodyV1 {
            schema: "nq.c2_initial_foundational_adoption_applicability_identity_preimage.v1",
            identity_domain: "nq.c2.initial_foundational_adoption_applicability.identity.v1",
            interpretation: A2ApplicabilityInterpretationIdentityV1::EXACT,
            active_policy_identity: candidate.coordinates.active_store_policy.clone(),
            active_policy_generation: candidate.coordinates.active_store_policy_generation,
            controlling_activation_identity: candidate.coordinates.controlling_activation.clone(),
        })
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let expected_transaction = semantic_digest(&InitialAdoptionTransactionIdentityBodyV1 {
            schema: "nq.c2_initial_foundational_adoption_transaction_identity_preimage.v1",
            identity_domain: "nq.c2.initial_foundational_adoption_transaction.identity.v1",
            store_identity: durable.store_identity.clone(),
            pre_effect_store_snapshot_identity: view.pre_effect_store_snapshot_identity.clone(),
            attempt_identity: attempt_identity.clone(),
            msg02_append_identity: self.msg02_append_identity.clone(),
            enrollment_cut: initial.enrollment_cut().ledger_position,
        })
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if self
            .msg02_resulting_frontier_identity
            .iter()
            .all(|byte| *byte == 0)
            || self.pop_cut != initial.pop_cut().ledger_position
            || initial.candidate_identity().digest() != &candidate_identity
            || initial.proof_of_possession_identity().digest() != &pop_identity
            || initial.attempt_identity().digest() != &attempt_identity
            || initial.proposal_identity().digest() != &proposal_identity
            || initial.bootstrap_grant().digest() != &grant_identity
            || initial.custody_evidence_identity().digest() != view.custody_evidence_identity
            || initial.public_key().as_str() != hex::encode(candidate.public_key)
            || u64::from(initial.key_generation().get()) != candidate.key_generation
            || !exact_scope_matches_foundation(&candidate.coordinates, initial)?
            || view.foundation.public_key()? != candidate.public_key
            || view.foundation.key_generation() != candidate.key_generation
            || view.foundation.custody_evidence_identity() != view.custody_evidence_identity
            || view.adoption_identity != view.adoption_record.identity()
            || durable.lineage != FoundationalAdoptionLineageV1::InitialExternal
            || durable.lineage_reference_identity != grant_identity
            || durable.authority_reference_identity != grant_identity
            || durable.occurrence_identity != occurrence_identity
            || durable.signer_scope_identity != scope_identity
            || durable.transaction_identity != expected_transaction
            || durable.policy_basis_identity != identity_digest(&candidate.active_policy)?
            || durable.applicability_basis_identity != expected_applicability
            || durable.attempt_identity != attempt_identity
            || durable.candidate_identity != candidate_identity
            || durable.proposal_identity != proposal_identity
            || durable.challenge_identity != challenge_identity
            || durable.proof_of_possession_identity != pop_identity
            || &durable.custody_evidence_identity != view.custody_evidence_identity
            || durable.enrollment_cut != initial.enrollment_cut().ledger_position
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }
}

impl FoundationalAdoptionProvenanceV1 for StoreConsumedFoundationalAdoptionProvenanceV1 {
    fn candidate_identity(&self) -> SignerIdentityV1 {
        self.authority.candidate_identity()
    }

    fn attempt_identity(&self) -> SignerIdentityV1 {
        self.authority.attempt_identity()
    }

    fn proof_of_possession_identity(&self) -> SignerIdentityV1 {
        self.authority.proof_of_possession_identity()
    }

    fn candidate_cut(&self) -> u64 {
        self.authority.candidate_cut()
    }

    fn proof_cut(&self) -> u64 {
        self.authority.proof_cut()
    }

    fn verify_material(
        &self,
        view: &FoundationalAdoptionMaterialViewV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        let authority = &self.authority;
        let durable = &view.adoption_record.wire.body;
        let lineage = authority.lineage();
        let historical_shape_is_exact = match lineage {
            FoundationalAdoptionLineageV1::InitialExternal => false,
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity => {
                authority.historical().is_none()
            }
            FoundationalAdoptionLineageV1::RestoreHistorical => {
                let Some(historical) = authority.historical() else {
                    return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
                };
                historical.foundation().identity() == view.foundation.identity()
                    && digest_identity(historical.acceptance().identity())?
                        == authority.predecessor_enrollment_identity()
            }
            FoundationalAdoptionLineageV1::RecoveryNewFoundation => {
                let Some(historical) = authority.historical() else {
                    return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
                };
                historical.foundation().identity() != view.foundation.identity()
                    && historical.foundation().public_key()? != view.foundation.public_key()?
                    && historical.foundation().key_generation() != view.foundation.key_generation()
                    && historical.foundation().custody_evidence_identity()
                        != view.foundation.custody_evidence_identity()
                    && digest_identity(historical.acceptance().identity())?
                        == authority.predecessor_enrollment_identity()
            }
        };
        if !historical_shape_is_exact
            || authority.candidate_cut() == 0
            || authority.candidate_cut() > IJSON_SAFE_INTEGER
            || authority.proof_cut() <= authority.candidate_cut()
            || authority.proof_cut() > IJSON_SAFE_INTEGER
            || authority.enrollment_cut() <= authority.proof_cut()
            || authority.enrollment_cut() > IJSON_SAFE_INTEGER
            || view.foundation.public_key()? != authority.public_key()
            || view.foundation.key_generation() != authority.key_generation()
            || view.foundation.custody_evidence_identity() != authority.custody_evidence_identity()
            || view.custody_evidence_identity != authority.custody_evidence_identity()
            || durable.lineage != lineage
            || durable.foundation_identity != *view.foundation.identity()
            || durable.store_identity != *authority.store_identity()
            || durable.occurrence_identity != identity_digest(&authority.occurrence_identity())?
            || durable.signer_scope_identity != identity_digest(&authority.signer_scope_identity())?
            || durable.physical_generation_identity
                != Some(identity_digest(&authority.physical_generation_identity())?)
            || durable.lifecycle_root_identity
                != Some(identity_digest(&authority.lifecycle_root_identity())?)
            || durable.frontier_identity != Some(identity_digest(&authority.frontier_identity())?)
            || durable.current_predecessor_identity
                != Some(identity_digest(&authority.current_predecessor_identity())?)
            || durable.transition_identity
                != Some(identity_digest(&authority.transition_identity())?)
            || durable.lineage_reference_identity
                != identity_digest(&authority.lineage_reference_identity())?
            || durable.authority_reference_identity
                != identity_digest(&authority.authority_reference_identity())?
            || durable.transaction_identity != identity_digest(&authority.transaction_identity())?
            || durable.policy_basis_identity != identity_digest(&authority.policy_basis_identity())?
            || durable.applicability_basis_identity
                != identity_digest(&authority.applicability_basis_identity())?
            || durable.attempt_identity != identity_digest(&authority.attempt_identity())?
            || durable.candidate_identity != identity_digest(&authority.candidate_identity())?
            || durable.proposal_identity != identity_digest(&authority.proposal_identity())?
            || durable.challenge_identity != identity_digest(&authority.challenge_identity())?
            || durable.proof_of_possession_identity
                != identity_digest(&authority.proof_of_possession_identity())?
            || durable.custody_evidence_identity != *authority.custody_evidence_identity()
            || durable.public_key_identity
                != stable_public_key_identity_v1(&authority.public_key())?
            || durable.key_generation_identity
                != identity_digest(&authority.key_generation_identity())?
            || durable.enrollment_cut != authority.enrollment_cut()
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }
}

fn verify_foundational_adoption_material_v1<Provenance>(
    adoption: &StoreAdoptedFoundationalEnrollmentV1<Provenance>,
) -> Result<(), SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    verify_store_integrity_signer_foundation_v1(&adoption.foundation)?;
    verify_foundational_adoption_record_v1(&adoption.adoption_record, &adoption.foundation)?;
    if adoption.creator_pid != std::process::id()
        || adoption.actor_effect_epoch > IJSON_SAFE_INTEGER
        || adoption.custody_evidence_identity != *adoption.foundation.custody_evidence_identity()
        || adoption.adoption_identity != *adoption.adoption_record.identity()
        || adoption.adoption_record.candidate_identity()
            != &identity_digest(&adoption.provenance.candidate_identity())?
        || adoption.adoption_record.attempt_identity()
            != &identity_digest(&adoption.provenance.attempt_identity())?
        || adoption.adoption_record.proof_of_possession_identity()
            != &identity_digest(&adoption.provenance.proof_of_possession_identity())?
        || adoption.adoption_record.enrollment_cut() <= adoption.provenance.proof_cut()
        || adoption.provenance.proof_cut() <= adoption.provenance.candidate_cut()
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    adoption
        .provenance
        .verify_material(&FoundationalAdoptionMaterialViewV1 {
            adoption_identity: &adoption.adoption_identity,
            foundation: &adoption.foundation,
            adoption_record: &adoption.adoption_record,
            custody_evidence_identity: &adoption.custody_evidence_identity,
            pre_effect_store_snapshot_identity: &adoption.pre_effect_store_snapshot_identity,
        })?;
    let expected_adoption_identity = adoption.adoption_record.identity().clone();
    let expected_effect_identity =
        foundational_adoption_effect_identity_v1(&expected_adoption_identity)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let expected_receipt_bytes = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
        schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
        adoption_identity: expected_adoption_identity.clone(),
        effect_identity: expected_effect_identity.clone(),
        foundation_identity: adoption.foundation.identity().clone(),
        lineage: adoption.adoption_record.lineage(),
        proof_of_possession_identity: adoption
            .adoption_record
            .proof_of_possession_identity()
            .clone(),
        enrollment_cut: adoption.adoption_record.enrollment_cut(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if adoption.adoption_identity != expected_adoption_identity
        || adoption.adoption_effect_identity != expected_effect_identity
        || adoption.adoption_receipt_identity != sha256_bytes(&expected_receipt_bytes)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

fn exact_scope_matches_foundation(
    coordinates: &PreGenerationSignerCoordinatesV1,
    foundational: &StoreIntegrityKeyEnrollmentV1,
) -> Result<bool, SignerRefusalV2> {
    Ok(coordinates.occurrence == foundational.occurrence().as_str()
        && &coordinates.signer_scope_policy == foundational.signer_scope_policy().digest()
        && coordinates.signer_scope_policy_version == foundational.signer_scope_policy_version()
        && &coordinates.a2_chain_root == foundational.a2_chain_root().digest()
        && &coordinates.controlling_activation == foundational.controlling_activation().digest()
        && &coordinates.dependency_anchor == foundational.dependency_anchor().digest()
        && coordinates.resident == foundational.resident().as_str()
        && coordinates.resident_generation == foundational.resident_generation()
        && coordinates.role == foundational.role()
        && &coordinates.role_manifest == foundational.role_manifest().digest()
        && coordinates.role_manifest_generation == foundational.role_manifest_generation()
        && coordinates.authority_domain == foundational.authority_domain()
        && coordinates.activation_policy_version == foundational.activation_policy_version()
        && &coordinates.active_store_policy == foundational.active_store_policy().digest()
        && coordinates.active_store_policy_generation
            == foundational.active_store_policy_generation())
}

/// Adopt foundational enrollment only in the legal forward direction from a
/// Store-actor-bound, durably consumed MSG-02 result.  No raw signature,
/// digest, or legacy PoP record enters this constructor.
pub(crate) fn prepare_store_foundational_enrollment_adoption_v1<'request, 'store>(
    actor: &StoreC2SnapshotActorV1<'_>,
    foundational: StoreIntegrityKeyEnrollmentV1,
    consumed: ConsumedInitialProposalPoPV1<'request, 'store>,
) -> Result<PreparedFoundationalEnrollmentAdoptionV1, SignerRefusalV2> {
    consumed.verify_for_actor(actor)?;
    let request = consumed.request();
    verify_initial_possession_request_v1(request)?;
    let authority_snapshot = request.authority_snapshot;
    let grant = request.grant();
    let candidate = request.candidate;
    let custody = request.custody;
    authority_snapshot
        .verify_same_process_and_snapshot()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let store_basis = authority_snapshot.admission_basis();
    let current = authority_snapshot.current_activation();
    verify_n_18_key_enrollment(&foundational)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    verify_sg_rec_05a_candidate(candidate)?;
    custody.verify_same_process()?;

    let candidate_digest = identity_digest(&candidate.identity)?;
    let pop_identity = consumed.message_identity();
    let pop_digest = identity_digest(&pop_identity)?;
    let attempt_digest = identity_digest(&candidate.attempt_identity)?;
    let proposal_digest = identity_digest(&candidate.proposal_identity)?;
    let custody_digest = custody.custody_evidence_identity();
    let public_key = hex::encode(candidate.public_key);
    let grant_request_digest = identity_digest(grant.request_identity().bytes())?;
    let grant_digest = identity_digest(grant.grant_identity().bytes())?;
    let grant_issuer_digest = Sha256Digest::parse(grant.issuer().digest.clone())
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let grant_policy_digest = identity_digest(&grant.installed_policy_calculation_identity())?;
    let grant_custody_digest = identity_digest(&grant.custody_instance_identity())?;
    let msg02_append_identity = Sha256Digest::parse(consumed.append_identity().to_owned())
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let msg02_effect_receipt_identity =
        Sha256Digest::parse(consumed.effect_receipt_identity().to_owned())
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let cuts_are_exact = foundational.authority_cut().effect_position == 0
        && foundational.candidate_cut().effect_position == 0
        && foundational.pop_cut().effect_position == 0
        && foundational.enrollment_cut().effect_position == 0
        && foundational.authority_cut().ledger_position == grant.lifecycle_cut()
        && foundational.candidate_cut().ledger_position == candidate.candidate_cut
        && foundational.pop_cut().ledger_position == consumed.event_cut();

    if !cuts_are_exact
        || !exact_scope_matches_foundation(&candidate.coordinates, &foundational)?
        || candidate.active_policy != digest_identity(&candidate.coordinates.active_store_policy)?
        || candidate.active_policy_generation
            != candidate.coordinates.active_store_policy_generation
        || digest_identity(custody.proposal_identity())? != candidate.proposal_identity
        || custody.public_key() != candidate.public_key
        || custody.key_generation() != candidate.key_generation
        || foundational.candidate_identity().digest() != &candidate_digest
        || foundational.proof_of_possession_identity().digest() != &pop_digest
        || foundational.attempt_identity().digest() != &attempt_digest
        || foundational.proposal_identity().digest() != &proposal_digest
        || foundational.custody_evidence_identity().digest() != custody_digest
        || foundational.public_key().as_str() != public_key
        || u64::from(foundational.key_generation().get()) != candidate.key_generation
        || foundational.bootstrap_grant_request().digest() != &grant_request_digest
        || foundational.bootstrap_grant().digest() != &grant_digest
        || foundational.bootstrap_issuer().digest() != &grant_issuer_digest
        || foundational.bootstrap_issuer_key_generation() != grant.issuer().key_generation
        || foundational.bootstrap_grant_signature() != hex::encode(grant.canonical_signature())
        || foundational.signer_scope_policy().digest().as_str() != grant.signer_scope_policy()
        || foundational.signer_scope_policy_version() != grant.signer_scope_policy_version()
        || foundational.activation_policy_version() != grant.activation_policy_version()
        || foundational.a2_chain_root().digest().as_str() != grant.a2_chain_root()
        || foundational.controlling_activation().digest().as_str() != grant.controlling_activation()
        || foundational.resident().as_str() != grant.resident_identity()
        || foundational.resident_generation() != grant.resident_generation()
        || foundational.role() != grant.host_role()
        || foundational.role_manifest_generation() != grant.role_manifest_generation()
        || foundational.authority_domain() != grant.authority_domain()
        || foundational.active_store_policy().digest() != &grant_policy_digest
        || foundational.custody_evidence_identity().digest() != &grant_custody_digest
        || store_basis.occurrence_id() != foundational.occurrence().as_str()
        || grant.occurrence_id() != current.occurrence_id()
        || grant.a2_chain_root() != current.chain_root_activation_digest().as_str()
        || grant.controlling_activation() != current.controlling_tip_activation_digest().as_str()
        || grant.resident_identity() != current.resident_identity()
        || grant.resident_generation() != current.resident_generation()
        || grant.host_role() != current.host_role()
        || grant.role_manifest_generation() != current.role_manifest_generation()
        || grant.authority_domain() != current.domain()
        || grant.activation_policy_version() != current.policy_version()
        || grant.issuer().issued_against_candidate_set != current.candidate_set_digest().as_str()
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }

    let grant_identity = identity_digest(&candidate.grant_identity)?;
    let candidate_identity = identity_digest(&candidate.identity)?;
    let attempt_identity = identity_digest(&candidate.attempt_identity)?;
    let proposal_identity = identity_digest(&candidate.proposal_identity)?;
    let challenge_identity = identity_digest(&request.challenge_identity())?;
    let pre_generation_scope_identity =
        identity_digest(&pre_generation_scope_identity_v1(&candidate.coordinates)?)?;
    let occurrence_identity = identity_digest(&request.occurrence_identity()?)?;
    let store_identity = request.store_instance_identity().clone();
    let transaction_identity = semantic_digest(&InitialAdoptionTransactionIdentityBodyV1 {
        schema: "nq.c2_initial_foundational_adoption_transaction_identity_preimage.v1",
        identity_domain: "nq.c2.initial_foundational_adoption_transaction.identity.v1",
        store_identity: store_identity.clone(),
        pre_effect_store_snapshot_identity: actor.current_snapshot_identity().clone(),
        attempt_identity: attempt_identity.clone(),
        msg02_append_identity: msg02_append_identity.clone(),
        enrollment_cut: foundational.enrollment_cut().ledger_position,
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let applicability_basis_identity =
        semantic_digest(&InitialAdoptionApplicabilityIdentityBodyV1 {
            schema: "nq.c2_initial_foundational_adoption_applicability_identity_preimage.v1",
            identity_domain: "nq.c2.initial_foundational_adoption_applicability.identity.v1",
            interpretation: A2ApplicabilityInterpretationIdentityV1::EXACT,
            active_policy_identity: candidate.coordinates.active_store_policy.clone(),
            active_policy_generation: candidate.coordinates.active_store_policy_generation,
            controlling_activation_identity: candidate.coordinates.controlling_activation.clone(),
        })
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let foundation = construct_store_integrity_signer_foundation_v1(
        candidate.public_key,
        candidate.key_generation,
        custody.custody_evidence_identity().clone(),
    )?;
    let adoption_record = construct_foundational_adoption_record_v1(
        &foundation,
        FoundationalAdoptionBodyV1 {
            schema: FOUNDATIONAL_ADOPTION_SCHEMA_V1.to_owned(),
            schema_version: 1,
            identity_domain: FOUNDATIONAL_ADOPTION_IDENTITY_DOMAIN_V1.to_owned(),
            foundation_identity: foundation.identity().clone(),
            lineage: FoundationalAdoptionLineageV1::InitialExternal,
            lineage_reference_identity: grant_identity.clone(),
            authority_reference_identity: grant_identity,
            store_identity,
            occurrence_identity,
            signer_scope_identity: pre_generation_scope_identity,
            physical_generation_identity: None,
            lifecycle_root_identity: None,
            frontier_identity: None,
            current_predecessor_identity: None,
            transition_identity: None,
            transaction_identity,
            policy_basis_identity: candidate.coordinates.active_store_policy.clone(),
            applicability_basis_identity,
            attempt_identity,
            candidate_identity,
            proposal_identity,
            challenge_identity,
            proof_of_possession_identity: pop_digest,
            custody_evidence_identity: custody.custody_evidence_identity().clone(),
            public_key_identity: foundation.public_key_identity()?,
            key_generation_identity: foundation.key_generation_identity()?,
            enrollment_cut: foundational.enrollment_cut().ledger_position,
        },
    )?;
    let adoption_identity = adoption_record.identity().clone();
    let adoption_effect_identity = foundational_adoption_effect_identity_v1(&adoption_identity)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let receipt_bytes = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
        schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
        adoption_identity: adoption_identity.clone(),
        effect_identity: adoption_effect_identity.clone(),
        foundation_identity: foundation.identity().clone(),
        lineage: adoption_record.lineage(),
        proof_of_possession_identity: identity_digest(&pop_identity)?,
        enrollment_cut: foundational.enrollment_cut().ledger_position,
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let adoption_receipt_identity = sha256_bytes(&receipt_bytes);
    let adoption = StoreAdoptedFoundationalEnrollmentV1 {
        adoption_identity,
        adoption_effect_identity,
        adoption_receipt_identity,
        foundation,
        adoption_record,
        provenance: InitialExternalFoundationalAdoptionProvenanceV1 {
            foundational,
            candidate: candidate.clone(),
            challenge_identity: request.challenge_identity(),
            pop_identity,
            pop_cut: consumed.event_cut(),
            msg02_append_identity,
            msg02_effect_receipt_identity,
            msg02_resulting_frontier_identity: consumed.resulting_frontier_identity(),
        },
        custody_evidence_identity: custody.custody_evidence_identity().clone(),
        actor_instance_identity: actor.actor_instance_identity().clone(),
        pre_effect_store_snapshot_identity: actor.current_snapshot_identity().clone(),
        store_snapshot_identity: actor.current_snapshot_identity().clone(),
        process_identity: request.process_identity().clone(),
        actor_effect_epoch: actor.effect_epoch(),
        creator_pid: std::process::id(),
    };
    Ok(PreparedFoundationalEnrollmentAdoptionV1 {
        adoption,
        receipt_bytes,
    })
}

/// Prepare a non-initial foundational adoption exclusively from the opaque
/// authority consumed from one Store-owned live resolver.  The caller cannot
/// select a lineage or provide record coordinates: both are projected from
/// the consumed authority after same-snapshot/process verification.
pub(crate) fn prepare_store_consumed_foundational_enrollment_adoption_v1<'store>(
    actor: &StoreC2SnapshotActorV1<'store>,
    authority_snapshot: &StoreC2AuthoritySnapshotV1<'store>,
    consumed: ConsumedStoreFoundationAdoptionAuthorityV1,
) -> Result<
    PreparedFoundationalEnrollmentAdoptionV1<StoreConsumedFoundationalAdoptionProvenanceV1>,
    SignerRefusalV2,
> {
    actor
        .verify_authority_lineage(authority_snapshot)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    consumed
        .verify_for_actor(actor)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let basis = authority_snapshot.admission_basis();
    if consumed.lineage() == FoundationalAdoptionLineageV1::InitialExternal
        || consumed.store_identity() != basis.store_instance_identity()
        || consumed.occurrence_id() != basis.occurrence_id()
        || consumed.qualified_candidate_identity()
            != digest_identity(basis.qualified_candidate_identity())?
        || consumed.source_tree_identity() != digest_identity(basis.source_tree_identity())?
        || consumed.runtime_artifact_identity()
            != digest_identity(basis.measured_runtime_artifact_identity())?
        || consumed.implementation_manifest_identity()
            != digest_identity(basis.qualified_manifest_identity())?
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }

    let foundation = construct_store_integrity_signer_foundation_v1(
        consumed.public_key(),
        consumed.key_generation(),
        consumed.custody_evidence_identity().clone(),
    )?;
    let adoption_record = construct_foundational_adoption_record_v1(
        &foundation,
        FoundationalAdoptionBodyV1 {
            schema: FOUNDATIONAL_ADOPTION_SCHEMA_V1.to_owned(),
            schema_version: 1,
            identity_domain: FOUNDATIONAL_ADOPTION_IDENTITY_DOMAIN_V1.to_owned(),
            foundation_identity: foundation.identity().clone(),
            lineage: consumed.lineage(),
            lineage_reference_identity: identity_digest(&consumed.lineage_reference_identity())?,
            authority_reference_identity: identity_digest(
                &consumed.authority_reference_identity(),
            )?,
            store_identity: consumed.store_identity().clone(),
            occurrence_identity: identity_digest(&consumed.occurrence_identity())?,
            signer_scope_identity: identity_digest(&consumed.signer_scope_identity())?,
            physical_generation_identity: Some(identity_digest(
                &consumed.physical_generation_identity(),
            )?),
            lifecycle_root_identity: Some(identity_digest(&consumed.lifecycle_root_identity())?),
            frontier_identity: Some(identity_digest(&consumed.frontier_identity())?),
            current_predecessor_identity: Some(identity_digest(
                &consumed.current_predecessor_identity(),
            )?),
            transition_identity: Some(identity_digest(&consumed.transition_identity())?),
            transaction_identity: identity_digest(&consumed.transaction_identity())?,
            policy_basis_identity: identity_digest(&consumed.policy_basis_identity())?,
            applicability_basis_identity: identity_digest(
                &consumed.applicability_basis_identity(),
            )?,
            attempt_identity: identity_digest(&consumed.attempt_identity())?,
            candidate_identity: identity_digest(&consumed.candidate_identity())?,
            proposal_identity: identity_digest(&consumed.proposal_identity())?,
            challenge_identity: identity_digest(&consumed.challenge_identity())?,
            proof_of_possession_identity: identity_digest(
                &consumed.proof_of_possession_identity(),
            )?,
            custody_evidence_identity: consumed.custody_evidence_identity().clone(),
            public_key_identity: stable_public_key_identity_v1(&consumed.public_key())?,
            key_generation_identity: identity_digest(&consumed.key_generation_identity())?,
            enrollment_cut: consumed.enrollment_cut(),
        },
    )?;
    let adoption_identity = adoption_record.identity().clone();
    let adoption_effect_identity = foundational_adoption_effect_identity_v1(&adoption_identity)?;
    let receipt_bytes = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
        schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
        adoption_identity: adoption_identity.clone(),
        effect_identity: adoption_effect_identity.clone(),
        foundation_identity: foundation.identity().clone(),
        lineage: adoption_record.lineage(),
        proof_of_possession_identity: adoption_record.proof_of_possession_identity().clone(),
        enrollment_cut: adoption_record.enrollment_cut(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let adoption_receipt_identity = sha256_bytes(&receipt_bytes);
    let custody_evidence_identity = adoption_record.custody_evidence_identity().clone();
    let adoption = StoreAdoptedFoundationalEnrollmentV1 {
        adoption_identity,
        adoption_effect_identity,
        adoption_receipt_identity,
        foundation,
        adoption_record,
        provenance: StoreConsumedFoundationalAdoptionProvenanceV1 {
            authority: consumed,
        },
        custody_evidence_identity,
        actor_instance_identity: actor.actor_instance_identity().clone(),
        pre_effect_store_snapshot_identity: actor.current_snapshot_identity().clone(),
        store_snapshot_identity: actor.current_snapshot_identity().clone(),
        process_identity: basis.process_identity().clone(),
        actor_effect_epoch: actor.effect_epoch(),
        creator_pid: std::process::id(),
    };
    verify_foundational_adoption_material_v1(&adoption)?;
    Ok(PreparedFoundationalEnrollmentAdoptionV1 {
        adoption,
        receipt_bytes,
    })
}

struct ExistingFoundationalAdoptionV1 {
    adoption_identity: String,
    foundation_identity: String,
    adoption_canonical_bytes: Vec<u8>,
    adoption_canonical_sha256: String,
    lineage: String,
    foundational_enrollment_identity: Option<String>,
    canonical_bytes: Option<Vec<u8>>,
    canonical_sha256: Option<String>,
    msg02_message_identity: Option<Vec<u8>>,
    msg02_append_identity: Option<String>,
    msg02_effect_receipt_identity: Option<String>,
    grant_identity: Option<Vec<u8>>,
    candidate_identity: Vec<u8>,
    attempt_identity: Vec<u8>,
    custody_evidence_identity: Vec<u8>,
    pre_generation_scope_identity: Vec<u8>,
    enrollment_cut: u64,
    effect_identity: String,
    receipt_identity: String,
    receipt_bytes: Vec<u8>,
}

/// Append exact foundational adoption evidence inside the actor-owned
/// transaction. Persisted actor/process coordinates are audit evidence only.
pub(crate) fn append_prepared_foundational_enrollment_adoption_v1(
    transaction: &Transaction<'_>,
    prepared: &PreparedFoundationalEnrollmentAdoptionV1<impl FoundationalAdoptionProvenanceV1>,
) -> Result<PersistedFoundationalEnrollmentAdoptionV1, SignerRefusalV2> {
    let adoption = &prepared.adoption;
    verify_foundational_adoption_material_v1(adoption)?;
    let initial = adoption.provenance.initial();
    let foundational_identity =
        initial.map(|source| source.foundational.canonical_identity().as_str().to_owned());
    let canonical_bytes = initial.map(|source| source.foundational.canonical_bytes().to_vec());
    let canonical_sha256 = canonical_bytes
        .as_ref()
        .map(|bytes| sha256_bytes(bytes).to_string());
    let msg02_message_identity = initial.map(|source| source.pop_identity.to_vec());
    let msg02_append_identity =
        initial.map(|source| source.msg02_append_identity.as_str().to_owned());
    let msg02_effect_receipt_identity =
        initial.map(|source| source.msg02_effect_receipt_identity.as_str().to_owned());
    let grant_identity = initial.map(|source| source.candidate.grant_identity.to_vec());
    let foundation_identity = adoption.foundation.identity().as_str();
    let foundation_canonical_bytes = adoption.foundation.canonical_bytes();
    let foundation_canonical_sha256 = sha256_bytes(foundation_canonical_bytes).to_string();
    let adoption_canonical_bytes = adoption.adoption_record.canonical_bytes();
    let adoption_canonical_sha256 = sha256_bytes(adoption_canonical_bytes).to_string();
    let lineage = adoption.adoption_record.lineage().as_str();
    let adoption_identity = adoption.adoption_identity.as_str();
    let effect_identity = adoption.adoption_effect_identity.as_str();
    let receipt_identity = adoption.adoption_receipt_identity.as_str();
    let custody_identity = digest_identity(&adoption.custody_evidence_identity)?;
    let public_key = adoption.foundation.public_key()?;
    let key_generation = adoption.foundation.key_generation();
    let candidate_identity = digest_identity(adoption.adoption_record.candidate_identity())?;
    let attempt_identity = digest_identity(adoption.adoption_record.attempt_identity())?;
    let signer_scope_identity = digest_identity(adoption.adoption_record.signer_scope_identity())?;

    let foundation_rows = transaction
        .prepare(
            "SELECT foundation_identity, foundation_canonical_bytes,
                    foundation_canonical_sha256, algorithm, public_key,
                    key_generation, custody_evidence_identity
             FROM c2_signer_foundations
             WHERE foundation_identity = ?1
                OR (public_key = ?2 AND key_generation = ?3
                    AND custody_evidence_identity = ?4)",
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?
        .query_map(
            params![
                foundation_identity,
                &public_key[..],
                key_generation,
                &custody_identity[..],
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    if foundation_rows.is_empty() {
        transaction
            .execute(
                "INSERT INTO c2_signer_foundations (
                    foundation_identity, foundation_canonical_bytes,
                    foundation_canonical_sha256, algorithm, public_key,
                    key_generation, custody_evidence_identity, committed_at
                 ) VALUES (?1, ?2, ?3, 'ed25519', ?4, ?5, ?6, ?7)",
                params![
                    foundation_identity,
                    foundation_canonical_bytes,
                    foundation_canonical_sha256,
                    &public_key[..],
                    key_generation,
                    &custody_identity[..],
                    Utc::now().to_rfc3339(),
                ],
            )
            .map_err(|_| SignerRefusalV2::SignerStateIo)?;
        #[cfg(test)]
        crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-57");
    } else if foundation_rows.len() != 1
        || foundation_rows[0].0 != foundation_identity
        || foundation_rows[0].1 != foundation_canonical_bytes
        || foundation_rows[0].2 != foundation_canonical_sha256
        || foundation_rows[0].3 != "ed25519"
        || foundation_rows[0].4 != public_key
        || foundation_rows[0].5 != key_generation
        || foundation_rows[0].6 != custody_identity
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    let mut statement = transaction
        .prepare(
            "SELECT adoption_identity, foundation_identity,
                    adoption_canonical_bytes, adoption_canonical_sha256, lineage,
                    foundational_enrollment_identity,
                    foundational_enrollment_canonical_bytes,
                    foundational_enrollment_canonical_sha256,
                    msg02_message_identity, msg02_append_identity,
                    msg02_effect_receipt_identity, grant_identity,
                    candidate_identity, attempt_identity,
                    custody_evidence_identity, pre_generation_scope_identity,
                    enrollment_cut, effect_identity, receipt_identity, receipt_bytes
             FROM c2_foundational_enrollment_adoptions
             WHERE attempt_identity = ?1 OR candidate_identity = ?2
                OR (?3 IS NOT NULL AND msg02_message_identity = ?3)
                OR adoption_identity = ?4",
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    let rows = statement
        .query_map(
            params![
                &attempt_identity[..],
                &candidate_identity[..],
                msg02_message_identity.as_deref(),
                adoption_identity,
            ],
            |row| {
                Ok(ExistingFoundationalAdoptionV1 {
                    adoption_identity: row.get(0)?,
                    foundation_identity: row.get(1)?,
                    adoption_canonical_bytes: row.get(2)?,
                    adoption_canonical_sha256: row.get(3)?,
                    lineage: row.get(4)?,
                    foundational_enrollment_identity: row.get(5)?,
                    canonical_bytes: row.get(6)?,
                    canonical_sha256: row.get(7)?,
                    msg02_message_identity: row.get(8)?,
                    msg02_append_identity: row.get(9)?,
                    msg02_effect_receipt_identity: row.get(10)?,
                    grant_identity: row.get(11)?,
                    candidate_identity: row.get(12)?,
                    attempt_identity: row.get(13)?,
                    custody_evidence_identity: row.get(14)?,
                    pre_generation_scope_identity: row.get(15)?,
                    enrollment_cut: row.get(16)?,
                    effect_identity: row.get(17)?,
                    receipt_identity: row.get(18)?,
                    receipt_bytes: row.get(19)?,
                })
            },
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    if !rows.is_empty() {
        if rows.len() == 1 {
            let existing = &rows[0];
            if existing.adoption_identity == adoption_identity
                && existing.foundation_identity == foundation_identity
                && existing.adoption_canonical_bytes == adoption_canonical_bytes
                && existing.adoption_canonical_sha256 == adoption_canonical_sha256
                && existing.lineage == lineage
                && existing.foundational_enrollment_identity == foundational_identity
                && existing.canonical_bytes == canonical_bytes
                && existing.canonical_sha256 == canonical_sha256
                && existing.msg02_message_identity == msg02_message_identity
                && existing.msg02_append_identity == msg02_append_identity
                && existing.msg02_effect_receipt_identity == msg02_effect_receipt_identity
                && existing.grant_identity == grant_identity
                && existing.candidate_identity == candidate_identity
                && existing.attempt_identity == attempt_identity
                && existing.custody_evidence_identity == custody_identity
                && existing.pre_generation_scope_identity == signer_scope_identity
                && existing.enrollment_cut == adoption.adoption_record.enrollment_cut()
                && existing.effect_identity == effect_identity
                && existing.receipt_identity == receipt_identity
                && existing.receipt_bytes == prepared.receipt_bytes
            {
                return Ok(PersistedFoundationalEnrollmentAdoptionV1 {
                    disposition: EnrollmentBridgeAppendDispositionV1::ExactReplay,
                    adoption_identity: adoption.adoption_identity.clone(),
                    effect_identity: adoption.adoption_effect_identity.clone(),
                    receipt_identity: adoption.adoption_receipt_identity.clone(),
                });
            }
        }
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    let adoption_sequence = transaction
        .query_row(
            "SELECT COALESCE(MAX(adoption_sequence), 0) + 1
             FROM c2_foundational_enrollment_adoptions",
            [],
            |row| row.get::<_, u64>(0),
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    transaction
        .execute(
            "INSERT INTO c2_foundational_enrollment_adoptions (
                adoption_sequence, adoption_identity,
                foundation_identity, adoption_canonical_bytes,
                adoption_canonical_sha256, lineage,
                foundational_enrollment_identity,
                foundational_enrollment_canonical_bytes,
                foundational_enrollment_canonical_sha256,
                msg02_message_identity, msg02_append_identity,
                msg02_effect_receipt_identity, grant_identity,
                candidate_identity, attempt_identity, custody_evidence_identity,
                pre_generation_scope_identity, pre_effect_store_snapshot_identity,
                process_identity, actor_instance_identity, actor_effect_epoch,
                enrollment_cut, effect_identity, receipt_identity, receipt_bytes,
                committed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                       ?22, ?23, ?24, ?25, ?26)",
            params![
                adoption_sequence,
                adoption_identity,
                foundation_identity,
                adoption_canonical_bytes,
                adoption_canonical_sha256,
                lineage,
                foundational_identity.as_deref(),
                canonical_bytes.as_deref(),
                canonical_sha256.as_deref(),
                msg02_message_identity.as_deref(),
                msg02_append_identity.as_deref(),
                msg02_effect_receipt_identity.as_deref(),
                grant_identity.as_deref(),
                &candidate_identity[..],
                &attempt_identity[..],
                &custody_identity[..],
                &signer_scope_identity[..],
                adoption.pre_effect_store_snapshot_identity.as_str(),
                adoption.process_identity.as_str(),
                adoption.actor_instance_identity.as_str(),
                adoption.actor_effect_epoch,
                adoption.adoption_record.enrollment_cut(),
                effect_identity,
                receipt_identity,
                prepared.receipt_bytes,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-58");
    Ok(PersistedFoundationalEnrollmentAdoptionV1 {
        disposition: EnrollmentBridgeAppendDispositionV1::Appended,
        adoption_identity: adoption.adoption_identity.clone(),
        effect_identity: adoption.adoption_effect_identity.clone(),
        receipt_identity: adoption.adoption_receipt_identity.clone(),
    })
}

/// Mint process-local adopted authority only after the private transaction
/// append and actor post-state update have both completed.
pub(crate) fn seal_store_adopted_foundational_enrollment_v1<Provenance>(
    actor: &StoreC2SnapshotActorV1<'_>,
    mut prepared: PreparedFoundationalEnrollmentAdoptionV1<Provenance>,
    persisted: PersistedFoundationalEnrollmentAdoptionV1,
) -> Result<StoreAdoptedFoundationalEnrollmentV1<Provenance>, SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    actor
        .verify_same_snapshot()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let expected_epoch = prepared
        .adoption
        .actor_effect_epoch
        .checked_add(1)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if actor.actor_instance_identity() != &prepared.adoption.actor_instance_identity
        || actor.effect_epoch() != expected_epoch
        || persisted.adoption_identity != prepared.adoption.adoption_identity
        || persisted.effect_identity != prepared.adoption.adoption_effect_identity
        || persisted.receipt_identity != prepared.adoption.adoption_receipt_identity
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    prepared.adoption.store_snapshot_identity = actor.current_snapshot_identity().clone();
    prepared.adoption.actor_effect_epoch = actor.effect_epoch();
    prepared.adoption.creator_pid = std::process::id();
    verify_foundational_adoption_material_v1(&prepared.adoption)?;
    Ok(prepared.adoption)
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreIntegrityEnrollmentBodyV2 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    foundational_enrollment_identity: Sha256Digest,
    candidate_identity: Sha256Digest,
    pop_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    accepted_cut: u64,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreIntegrityEnrollmentWireV2 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    enrollment_identity: Sha256Digest,
    foundational_enrollment_identity: Sha256Digest,
    candidate_identity: Sha256Digest,
    pop_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    accepted_cut: u64,
}

/// Canonical durable signer-lifecycle acceptance evidence.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct StoreIntegrityEnrollmentV2 {
    wire: StoreIntegrityEnrollmentWireV2,
    canonical_bytes: Vec<u8>,
}

impl Serialize for StoreIntegrityEnrollmentV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.wire.serialize(serializer)
    }
}

impl StoreIntegrityEnrollmentV2 {
    pub(crate) const fn identity(&self) -> &Sha256Digest {
        &self.wire.enrollment_identity
    }

    pub(crate) fn identity_bytes(&self) -> Result<SignerIdentityV1, SignerRefusalV2> {
        digest_identity(&self.wire.enrollment_identity)
    }

    pub(crate) const fn foundational_enrollment_identity(&self) -> &Sha256Digest {
        &self.wire.foundational_enrollment_identity
    }

    pub(crate) const fn accepted_cut(&self) -> u64 {
        self.wire.accepted_cut
    }

    pub(crate) const fn candidate_identity(&self) -> &Sha256Digest {
        &self.wire.candidate_identity
    }

    pub(crate) const fn proof_of_possession_identity(&self) -> &Sha256Digest {
        &self.wire.pop_identity
    }

    pub(crate) const fn attempt_identity(&self) -> &Sha256Digest {
        &self.wire.attempt_identity
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

fn acceptance_body(
    foundational_enrollment_identity: Sha256Digest,
    candidate_identity: Sha256Digest,
    pop_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    accepted_cut: u64,
) -> StoreIntegrityEnrollmentBodyV2 {
    StoreIntegrityEnrollmentBodyV2 {
        schema: ENROLLMENT_SCHEMA_V2.to_owned(),
        schema_version: 2,
        identity_domain: ENROLLMENT_IDENTITY_DOMAIN_V2.to_owned(),
        foundational_enrollment_identity,
        candidate_identity,
        pop_identity,
        attempt_identity,
        accepted_cut,
    }
}

fn construct_durable_signer_acceptance<Provenance>(
    adoption: &StoreAdoptedFoundationalEnrollmentV1<Provenance>,
    accepted_cut: u64,
) -> Result<StoreIntegrityEnrollmentV2, SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    if accepted_cut <= adoption.adoption_record.enrollment_cut()
        || accepted_cut <= adoption.provenance.candidate_cut()
        || accepted_cut <= adoption.provenance.proof_cut()
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let body = acceptance_body(
        adoption.adoption_identity().clone(),
        identity_digest(&adoption.provenance.candidate_identity())?,
        identity_digest(&adoption.provenance.proof_of_possession_identity())?,
        identity_digest(&adoption.provenance.attempt_identity())?,
        accepted_cut,
    );
    let enrollment_identity =
        semantic_digest(&body).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let wire = StoreIntegrityEnrollmentWireV2 {
        schema: body.schema,
        schema_version: body.schema_version,
        identity_domain: body.identity_domain,
        enrollment_identity,
        foundational_enrollment_identity: body.foundational_enrollment_identity,
        candidate_identity: body.candidate_identity,
        pop_identity: body.pop_identity,
        attempt_identity: body.attempt_identity,
        accepted_cut,
    };
    let canonical_bytes =
        canonical_json_bytes(&wire).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    Ok(StoreIntegrityEnrollmentV2 {
        wire,
        canonical_bytes,
    })
}

pub(crate) fn verify_store_integrity_enrollment_v2(
    enrollment: &StoreIntegrityEnrollmentV2,
) -> Result<(), SignerRefusalV2> {
    if enrollment.wire.schema != ENROLLMENT_SCHEMA_V2
        || enrollment.wire.schema_version != 2
        || enrollment.wire.identity_domain != ENROLLMENT_IDENTITY_DOMAIN_V2
        || enrollment.wire.accepted_cut == 0
        || enrollment.wire.accepted_cut > IJSON_SAFE_INTEGER
        || canonical_json_bytes(&enrollment.wire)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
            != enrollment.canonical_bytes
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let body = acceptance_body(
        enrollment.wire.foundational_enrollment_identity.clone(),
        enrollment.wire.candidate_identity.clone(),
        enrollment.wire.pop_identity.clone(),
        enrollment.wire.attempt_identity.clone(),
        enrollment.wire.accepted_cut,
    );
    if semantic_digest(&body).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
        != enrollment.wire.enrollment_identity
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

/// Decode exact canonical signer-acceptance evidence without reconstructing
/// its process-local accepted wrapper or foundational adoption.
pub(crate) fn decode_store_integrity_enrollment_v2(
    bytes: &[u8],
) -> Result<StoreIntegrityEnrollmentV2, SignerRefusalV2> {
    let wire: StoreIntegrityEnrollmentWireV2 =
        serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let canonical_bytes =
        canonical_json_bytes(&wire).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if canonical_bytes != bytes {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let enrollment = StoreIntegrityEnrollmentV2 {
        wire,
        canonical_bytes,
    };
    verify_store_integrity_enrollment_v2(&enrollment)?;
    Ok(enrollment)
}

/// Process-local verified acceptance linked to the exact Store adoption.
pub(crate) struct StoreAcceptedSignerEnrollmentV1<
    Provenance = InitialExternalFoundationalAdoptionProvenanceV1,
> where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    record: StoreIntegrityEnrollmentV2,
    adoption: StoreAdoptedFoundationalEnrollmentV1<Provenance>,
    acceptance_effect_identity: Sha256Digest,
    acceptance_receipt_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    store_snapshot_identity: Sha256Digest,
    process_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

impl<Provenance> StoreAcceptedSignerEnrollmentV1<Provenance>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    pub(crate) const fn record(&self) -> &StoreIntegrityEnrollmentV2 {
        &self.record
    }

    pub(crate) const fn adoption(&self) -> &StoreAdoptedFoundationalEnrollmentV1<Provenance> {
        &self.adoption
    }

    pub(crate) const fn acceptance_effect_identity(&self) -> &Sha256Digest {
        &self.acceptance_effect_identity
    }

    pub(crate) const fn acceptance_receipt_identity(&self) -> &Sha256Digest {
        &self.acceptance_receipt_identity
    }

    pub(crate) const fn store_snapshot_identity(&self) -> &Sha256Digest {
        &self.store_snapshot_identity
    }

    pub(crate) const fn process_identity(&self) -> &Sha256Digest {
        &self.process_identity
    }

    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if self.creator_pid != std::process::id()
            || actor.actor_instance_identity() != &self.actor_instance_identity
            || actor.current_snapshot_identity() != &self.store_snapshot_identity
            || actor.effect_epoch() != self.actor_effect_epoch
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        verify_store_accepted_signer_enrollment_v1(self)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SignerAcceptanceEffectBodyV1 {
    schema: &'static str,
    identity_domain: &'static str,
    signer_enrollment_identity: Sha256Digest,
    foundational_adoption_identity: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SignerAcceptanceReceiptV1 {
    schema: &'static str,
    acceptance_effect_identity: Sha256Digest,
    signer_enrollment_identity: Sha256Digest,
    foundational_adoption_identity: Sha256Digest,
    accepted_cut: u64,
}

/// Opaque later-cut signer acceptance ready for the actor's private
/// transaction. It owns (consumes) the prior adoption proof.
pub(crate) struct PreparedSignerEnrollmentAcceptanceV1<
    Provenance = InitialExternalFoundationalAdoptionProvenanceV1,
> where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    accepted: StoreAcceptedSignerEnrollmentV1<Provenance>,
    receipt_bytes: Vec<u8>,
}

impl<Provenance> PreparedSignerEnrollmentAcceptanceV1<Provenance>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        self.accepted.adoption.verify_for_actor(actor)
    }
}

/// Inert durable acceptance append result awaiting a post-effect actor seal.
pub(crate) struct PersistedSignerEnrollmentAcceptanceV1 {
    pub(crate) disposition: EnrollmentBridgeAppendDispositionV1,
    signer_enrollment_identity: Sha256Digest,
    acceptance_effect_identity: Sha256Digest,
    receipt_identity: Sha256Digest,
}

/// The only signer-acceptance constructor consumes sealed Store adoption and
/// derives the unique next legal cut. No caller-selected ordinal enters the
/// production path.
pub(crate) fn prepare_store_signer_enrollment_acceptance_v1<Provenance>(
    actor: &StoreC2SnapshotActorV1<'_>,
    adoption: StoreAdoptedFoundationalEnrollmentV1<Provenance>,
) -> Result<PreparedSignerEnrollmentAcceptanceV1<Provenance>, SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    adoption.verify_for_actor(actor)?;
    let accepted_cut = adoption
        .adoption_record
        .enrollment_cut()
        .checked_add(1)
        .filter(|cut| *cut <= IJSON_SAFE_INTEGER)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let record = construct_durable_signer_acceptance(&adoption, accepted_cut)?;
    let process_identity = adoption.process_identity().clone();
    let acceptance_effect_identity = semantic_digest(&SignerAcceptanceEffectBodyV1 {
        schema: "nq.c2_signer_enrollment_acceptance_effect_identity_preimage.v1",
        identity_domain: "nq.c2.signer_enrollment_acceptance_effect.identity.v1",
        signer_enrollment_identity: record.identity().clone(),
        foundational_adoption_identity: adoption.adoption_identity().clone(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let receipt_bytes = canonical_json_bytes(&SignerAcceptanceReceiptV1 {
        schema: "nq.c2_signer_enrollment_acceptance_receipt.v1",
        acceptance_effect_identity: acceptance_effect_identity.clone(),
        signer_enrollment_identity: record.identity().clone(),
        foundational_adoption_identity: adoption.adoption_identity().clone(),
        accepted_cut,
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let acceptance_receipt_identity = sha256_bytes(&receipt_bytes);
    let accepted = StoreAcceptedSignerEnrollmentV1 {
        record,
        adoption,
        acceptance_effect_identity,
        acceptance_receipt_identity,
        actor_instance_identity: actor.actor_instance_identity().clone(),
        store_snapshot_identity: actor.current_snapshot_identity().clone(),
        process_identity,
        actor_effect_epoch: actor.effect_epoch(),
        creator_pid: std::process::id(),
    };
    Ok(PreparedSignerEnrollmentAcceptanceV1 {
        accepted,
        receipt_bytes,
    })
}

struct ExistingSignerAcceptanceV1 {
    acceptance_effect_identity: String,
    signer_enrollment_identity: String,
    canonical_bytes: Vec<u8>,
    canonical_sha256: String,
    foundational_adoption_identity: String,
    accepted_cut: u64,
    receipt_identity: String,
    receipt_bytes: Vec<u8>,
}

/// Append signer acceptance evidence inside the actor-owned transaction. The
/// foreign key is the durable enforcement of the one-way foundation bridge.
pub(crate) fn append_prepared_signer_enrollment_acceptance_v1<Provenance>(
    transaction: &Transaction<'_>,
    prepared: &PreparedSignerEnrollmentAcceptanceV1<Provenance>,
) -> Result<PersistedSignerEnrollmentAcceptanceV1, SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    let accepted = &prepared.accepted;
    let enrollment = &accepted.record;
    let enrollment_identity = enrollment.identity().as_str();
    let adoption_identity = accepted.adoption.adoption_identity().as_str();
    let effect_identity = accepted.acceptance_effect_identity.as_str();
    let receipt_identity = accepted.acceptance_receipt_identity.as_str();
    let canonical_sha256 = sha256_bytes(enrollment.canonical_bytes()).to_string();
    let existing = transaction
        .query_row(
            "SELECT acceptance_effect_identity, signer_enrollment_identity,
                    signer_enrollment_canonical_bytes,
                    signer_enrollment_canonical_sha256,
                    foundational_adoption_identity, accepted_cut,
                    receipt_identity, receipt_bytes
             FROM c2_signer_enrollment_acceptances
             WHERE foundational_adoption_identity = ?1
                OR signer_enrollment_identity = ?2",
            params![adoption_identity, enrollment_identity],
            |row| {
                Ok(ExistingSignerAcceptanceV1 {
                    acceptance_effect_identity: row.get(0)?,
                    signer_enrollment_identity: row.get(1)?,
                    canonical_bytes: row.get(2)?,
                    canonical_sha256: row.get(3)?,
                    foundational_adoption_identity: row.get(4)?,
                    accepted_cut: row.get(5)?,
                    receipt_identity: row.get(6)?,
                    receipt_bytes: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    if let Some(existing) = existing {
        if existing.acceptance_effect_identity == effect_identity
            && existing.signer_enrollment_identity == enrollment_identity
            && existing.canonical_bytes == enrollment.canonical_bytes()
            && existing.canonical_sha256 == canonical_sha256
            && existing.foundational_adoption_identity == adoption_identity
            && existing.accepted_cut == enrollment.accepted_cut()
            && existing.receipt_identity == receipt_identity
            && existing.receipt_bytes == prepared.receipt_bytes
        {
            return Ok(PersistedSignerEnrollmentAcceptanceV1 {
                disposition: EnrollmentBridgeAppendDispositionV1::ExactReplay,
                signer_enrollment_identity: enrollment.identity().clone(),
                acceptance_effect_identity: accepted.acceptance_effect_identity.clone(),
                receipt_identity: accepted.acceptance_receipt_identity.clone(),
            });
        }
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    let acceptance_sequence = transaction
        .query_row(
            "SELECT COALESCE(MAX(acceptance_sequence), 0) + 1
             FROM c2_signer_enrollment_acceptances",
            [],
            |row| row.get::<_, u64>(0),
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    transaction
        .execute(
            "INSERT INTO c2_signer_enrollment_acceptances (
                acceptance_sequence, acceptance_effect_identity,
                signer_enrollment_identity, signer_enrollment_canonical_bytes,
                signer_enrollment_canonical_sha256,
                foundational_adoption_identity, pre_effect_store_snapshot_identity,
                process_identity, actor_instance_identity, actor_effect_epoch,
                accepted_cut, receipt_identity, receipt_bytes, committed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       ?12, ?13, ?14)",
            params![
                acceptance_sequence,
                effect_identity,
                enrollment_identity,
                enrollment.canonical_bytes(),
                canonical_sha256,
                adoption_identity,
                accepted.store_snapshot_identity.as_str(),
                accepted.process_identity.as_str(),
                accepted.actor_instance_identity.as_str(),
                accepted.actor_effect_epoch,
                enrollment.accepted_cut(),
                receipt_identity,
                &prepared.receipt_bytes,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-59");
    Ok(PersistedSignerEnrollmentAcceptanceV1 {
        disposition: EnrollmentBridgeAppendDispositionV1::Appended,
        signer_enrollment_identity: enrollment.identity().clone(),
        acceptance_effect_identity: accepted.acceptance_effect_identity.clone(),
        receipt_identity: accepted.acceptance_receipt_identity.clone(),
    })
}

/// Mint process-local accepted signer evidence only after durable append and
/// post-effect actor update. Persisted rows remain evidence on restart.
pub(crate) fn seal_store_accepted_signer_enrollment_v1<Provenance>(
    actor: &StoreC2SnapshotActorV1<'_>,
    mut prepared: PreparedSignerEnrollmentAcceptanceV1<Provenance>,
    persisted: PersistedSignerEnrollmentAcceptanceV1,
) -> Result<StoreAcceptedSignerEnrollmentV1<Provenance>, SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    actor
        .verify_same_snapshot()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let expected_epoch = prepared
        .accepted
        .actor_effect_epoch
        .checked_add(1)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if actor.actor_instance_identity() != &prepared.accepted.actor_instance_identity
        || actor.effect_epoch() != expected_epoch
        || persisted.signer_enrollment_identity != *prepared.accepted.record.identity()
        || persisted.acceptance_effect_identity != prepared.accepted.acceptance_effect_identity
        || persisted.receipt_identity != prepared.accepted.acceptance_receipt_identity
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    prepared.accepted.store_snapshot_identity = actor.current_snapshot_identity().clone();
    prepared.accepted.actor_effect_epoch = actor.effect_epoch();
    prepared.accepted.creator_pid = std::process::id();
    verify_store_accepted_signer_enrollment_v1(&prepared.accepted)?;
    Ok(prepared.accepted)
}

struct DurableFoundationRowV1 {
    adoption_identity: String,
    foundation_identity: String,
    foundation_canonical_bytes: Vec<u8>,
    foundation_canonical_sha256: String,
    adoption_canonical_bytes: Vec<u8>,
    adoption_canonical_sha256: String,
    lineage: String,
    foundational_enrollment_identity: String,
    canonical_bytes: Vec<u8>,
    canonical_sha256: String,
    msg02_message_identity: Vec<u8>,
    msg02_append_identity: String,
    msg02_effect_receipt_identity: String,
    grant_identity: Vec<u8>,
    candidate_identity: Vec<u8>,
    attempt_identity: Vec<u8>,
    custody_evidence_identity: Vec<u8>,
    pre_generation_scope_identity: Vec<u8>,
    pre_effect_store_snapshot_identity: String,
    enrollment_cut: u64,
    effect_identity: String,
    receipt_identity: String,
    receipt_bytes: Vec<u8>,
}

struct DurableAcceptanceRowV1 {
    acceptance_effect_identity: String,
    signer_enrollment_identity: String,
    canonical_bytes: Vec<u8>,
    canonical_sha256: String,
    foundational_adoption_identity: String,
    accepted_cut: u64,
    receipt_identity: String,
    receipt_bytes: Vec<u8>,
}

struct DurableSignerEnrollmentEvidenceRowV1 {
    signer_enrollment_identity: String,
    signer_enrollment_canonical_bytes: Vec<u8>,
    signer_enrollment_canonical_sha256: String,
    foundational_adoption_identity: String,
    accepted_cut: u64,
    acceptance_effect_identity: String,
    acceptance_receipt_identity: String,
    acceptance_receipt_bytes: Vec<u8>,
    acceptance_pre_effect_store_snapshot_identity: String,
    adoption_identity: String,
    foundation_identity: String,
    foundation_canonical_bytes: Vec<u8>,
    foundation_canonical_sha256: String,
    adoption_canonical_bytes: Vec<u8>,
    adoption_canonical_sha256: String,
    lineage: String,
    candidate_identity: Vec<u8>,
    attempt_identity: Vec<u8>,
    custody_evidence_identity: Vec<u8>,
    signer_scope_identity: Vec<u8>,
    adoption_pre_effect_store_snapshot_identity: String,
    enrollment_cut: u64,
    adoption_effect_identity: String,
    adoption_receipt_identity: String,
    adoption_receipt_bytes: Vec<u8>,
}

/// Inert durable evidence common to all four foundational-adoption lineages.
///
/// This value proves exact canonical-record and durable-row correspondence.
/// It contains no live Store actor, predecessor authority, discontinuity entry,
/// custody descriptor, phase brand, currentness, or standing constructor.
pub(crate) struct StoreVerifiedDurableSignerEnrollmentV1 {
    foundation: StoreIntegritySignerFoundationV1,
    adoption: StoreIntegrityFoundationalAdoptionV1,
    acceptance: StoreIntegrityEnrollmentV2,
    adoption_effect_identity: Sha256Digest,
    adoption_receipt_identity: Sha256Digest,
    acceptance_effect_identity: Sha256Digest,
    acceptance_receipt_identity: Sha256Digest,
    adoption_pre_effect_store_snapshot_identity: Sha256Digest,
    acceptance_pre_effect_store_snapshot_identity: Sha256Digest,
}

impl StoreVerifiedDurableSignerEnrollmentV1 {
    pub(crate) const fn foundation(&self) -> &StoreIntegritySignerFoundationV1 {
        &self.foundation
    }

    pub(crate) const fn adoption(&self) -> &StoreIntegrityFoundationalAdoptionV1 {
        &self.adoption
    }

    pub(crate) const fn acceptance(&self) -> &StoreIntegrityEnrollmentV2 {
        &self.acceptance
    }

    pub(crate) const fn adoption_effect_identity(&self) -> &Sha256Digest {
        &self.adoption_effect_identity
    }

    pub(crate) const fn adoption_receipt_identity(&self) -> &Sha256Digest {
        &self.adoption_receipt_identity
    }

    pub(crate) const fn acceptance_effect_identity(&self) -> &Sha256Digest {
        &self.acceptance_effect_identity
    }

    pub(crate) const fn acceptance_receipt_identity(&self) -> &Sha256Digest {
        &self.acceptance_receipt_identity
    }

    pub(crate) const fn adoption_pre_effect_store_snapshot_identity(&self) -> &Sha256Digest {
        &self.adoption_pre_effect_store_snapshot_identity
    }

    pub(crate) const fn acceptance_pre_effect_store_snapshot_identity(&self) -> &Sha256Digest {
        &self.acceptance_pre_effect_store_snapshot_identity
    }
}

struct DurableMsg02RowV1 {
    family: String,
    route: String,
    identity_domain: String,
    signature_domain: String,
    message_identity: Vec<u8>,
    append_identity: String,
    signer_public_key: Vec<u8>,
    signer_key_generation: u64,
    event_cut: u64,
    canonical_message: Vec<u8>,
    canonical_message_sha256: String,
    signing_preimage: Vec<u8>,
    signing_preimage_sha256: String,
    signature: Vec<u8>,
    resulting_frontier_identity: Vec<u8>,
    effect_receipt_identity: String,
    effect_receipt_bytes: Vec<u8>,
}

/// Inert, exactly reverified durable foundation/acceptance/MSG-02 bridge.
///
/// Loading this value does not recreate adoption, signer acceptance, custody,
/// currentness, or standing. A Store actor must combine it with fresh live
/// authority and custody verification before minting process-local wrappers.
pub(crate) struct StoreVerifiedDurableEnrollmentBridgeV1 {
    foundation: StoreIntegritySignerFoundationV1,
    adoption_record: StoreIntegrityFoundationalAdoptionV1,
    foundational: StoreIntegrityKeyEnrollmentV1,
    acceptance: StoreIntegrityEnrollmentV2,
    adoption_identity: Sha256Digest,
    adoption_effect_identity: Sha256Digest,
    adoption_receipt_identity: Sha256Digest,
    msg02_append_identity: Sha256Digest,
    msg02_effect_receipt_identity: Sha256Digest,
    msg02_resulting_frontier_identity: SignerIdentityV1,
    candidate_identity: SignerIdentityV1,
    challenge_identity: SignerIdentityV1,
    attempt_identity: SignerIdentityV1,
    custody_evidence_identity: Sha256Digest,
    pre_generation_scope_identity: SignerIdentityV1,
    pre_effect_store_snapshot_identity: Sha256Digest,
}

impl StoreVerifiedDurableEnrollmentBridgeV1 {
    pub(crate) const fn foundation(&self) -> &StoreIntegritySignerFoundationV1 {
        &self.foundation
    }

    pub(crate) const fn adoption_record(&self) -> &StoreIntegrityFoundationalAdoptionV1 {
        &self.adoption_record
    }

    pub(crate) const fn foundational(&self) -> &StoreIntegrityKeyEnrollmentV1 {
        &self.foundational
    }

    pub(crate) const fn acceptance(&self) -> &StoreIntegrityEnrollmentV2 {
        &self.acceptance
    }

    pub(crate) const fn adoption_identity(&self) -> &Sha256Digest {
        &self.adoption_identity
    }

    pub(crate) const fn msg02_resulting_frontier_identity(&self) -> SignerIdentityV1 {
        self.msg02_resulting_frontier_identity
    }

    pub(crate) const fn candidate_identity(&self) -> SignerIdentityV1 {
        self.candidate_identity
    }

    pub(crate) const fn attempt_identity(&self) -> SignerIdentityV1 {
        self.attempt_identity
    }

    pub(crate) const fn custody_evidence_identity(&self) -> &Sha256Digest {
        &self.custody_evidence_identity
    }

    pub(crate) const fn pre_generation_scope_identity(&self) -> SignerIdentityV1 {
        self.pre_generation_scope_identity
    }
}

fn exact_identity_bytes(value: Vec<u8>) -> Result<SignerIdentityV1, SignerRefusalV2> {
    value
        .try_into()
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)
}

fn parsed_digest(value: String) -> Result<Sha256Digest, SignerRefusalV2> {
    Sha256Digest::parse(value).map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)
}

fn json_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, SignerRefusalV2> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)
}

/// Reverify lineage-neutral durable signer-enrollment evidence.
///
/// The canonical adoption record supplies the closed lineage variant; callers
/// do not select or pass a raw lineage tag.  Loading succeeds for any of the
/// four exact record shapes and never reconstructs the live authority that
/// originally permitted the adoption or acceptance.
pub(crate) fn load_verified_durable_signer_enrollment_v1(
    transaction: &Transaction<'_>,
    signer_enrollment_identity: &Sha256Digest,
) -> Result<StoreVerifiedDurableSignerEnrollmentV1, SignerRefusalV2> {
    let row = transaction
        .query_row(
            "SELECT acceptance.signer_enrollment_identity,
                    acceptance.signer_enrollment_canonical_bytes,
                    acceptance.signer_enrollment_canonical_sha256,
                    acceptance.foundational_adoption_identity,
                    acceptance.accepted_cut,
                    acceptance.acceptance_effect_identity,
                    acceptance.receipt_identity, acceptance.receipt_bytes,
                    acceptance.pre_effect_store_snapshot_identity,
                    adoption.adoption_identity, adoption.foundation_identity,
                    foundation.foundation_canonical_bytes,
                    foundation.foundation_canonical_sha256,
                    adoption.adoption_canonical_bytes,
                    adoption.adoption_canonical_sha256, adoption.lineage,
                    adoption.candidate_identity, adoption.attempt_identity,
                    adoption.custody_evidence_identity,
                    adoption.pre_generation_scope_identity,
                    adoption.pre_effect_store_snapshot_identity,
                    adoption.enrollment_cut, adoption.effect_identity,
                    adoption.receipt_identity, adoption.receipt_bytes
             FROM c2_signer_enrollment_acceptances AS acceptance
             JOIN c2_foundational_enrollment_adoptions AS adoption
               ON adoption.adoption_identity = acceptance.foundational_adoption_identity
             JOIN c2_signer_foundations AS foundation
               ON foundation.foundation_identity = adoption.foundation_identity
             WHERE acceptance.signer_enrollment_identity = ?1",
            params![signer_enrollment_identity.as_str()],
            |row| {
                Ok(DurableSignerEnrollmentEvidenceRowV1 {
                    signer_enrollment_identity: row.get(0)?,
                    signer_enrollment_canonical_bytes: row.get(1)?,
                    signer_enrollment_canonical_sha256: row.get(2)?,
                    foundational_adoption_identity: row.get(3)?,
                    accepted_cut: row.get(4)?,
                    acceptance_effect_identity: row.get(5)?,
                    acceptance_receipt_identity: row.get(6)?,
                    acceptance_receipt_bytes: row.get(7)?,
                    acceptance_pre_effect_store_snapshot_identity: row.get(8)?,
                    adoption_identity: row.get(9)?,
                    foundation_identity: row.get(10)?,
                    foundation_canonical_bytes: row.get(11)?,
                    foundation_canonical_sha256: row.get(12)?,
                    adoption_canonical_bytes: row.get(13)?,
                    adoption_canonical_sha256: row.get(14)?,
                    lineage: row.get(15)?,
                    candidate_identity: row.get(16)?,
                    attempt_identity: row.get(17)?,
                    custody_evidence_identity: row.get(18)?,
                    signer_scope_identity: row.get(19)?,
                    adoption_pre_effect_store_snapshot_identity: row.get(20)?,
                    enrollment_cut: row.get(21)?,
                    adoption_effect_identity: row.get(22)?,
                    adoption_receipt_identity: row.get(23)?,
                    adoption_receipt_bytes: row.get(24)?,
                })
            },
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;

    let foundation = decode_store_integrity_signer_foundation_v1(&row.foundation_canonical_bytes)?;
    let adoption =
        decode_foundational_adoption_record_v1(&row.adoption_canonical_bytes, &foundation)?;
    let acceptance = decode_store_integrity_enrollment_v2(&row.signer_enrollment_canonical_bytes)?;
    let adoption_identity = parsed_digest(row.adoption_identity.clone())?;
    let adoption_effect_identity = parsed_digest(row.adoption_effect_identity.clone())?;
    let adoption_receipt_identity = parsed_digest(row.adoption_receipt_identity.clone())?;
    let acceptance_effect_identity = parsed_digest(row.acceptance_effect_identity.clone())?;
    let acceptance_receipt_identity = parsed_digest(row.acceptance_receipt_identity.clone())?;
    let adoption_pre_effect_store_snapshot_identity =
        parsed_digest(row.adoption_pre_effect_store_snapshot_identity.clone())?;
    let acceptance_pre_effect_store_snapshot_identity =
        parsed_digest(row.acceptance_pre_effect_store_snapshot_identity.clone())?;
    let candidate_identity = identity_digest(&exact_identity_bytes(row.candidate_identity)?)?;
    let attempt_identity = identity_digest(&exact_identity_bytes(row.attempt_identity)?)?;
    let custody_evidence_identity =
        identity_digest(&exact_identity_bytes(row.custody_evidence_identity)?)?;
    let signer_scope_identity = identity_digest(&exact_identity_bytes(row.signer_scope_identity)?)?;

    let expected_adoption_effect = foundational_adoption_effect_identity_v1(&adoption_identity)?;
    let expected_adoption_receipt = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
        schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
        adoption_identity: adoption_identity.clone(),
        effect_identity: expected_adoption_effect.clone(),
        foundation_identity: foundation.identity().clone(),
        lineage: adoption.lineage(),
        proof_of_possession_identity: adoption.proof_of_possession_identity().clone(),
        enrollment_cut: adoption.enrollment_cut(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let expected_acceptance_effect = semantic_digest(&SignerAcceptanceEffectBodyV1 {
        schema: "nq.c2_signer_enrollment_acceptance_effect_identity_preimage.v1",
        identity_domain: "nq.c2.signer_enrollment_acceptance_effect.identity.v1",
        signer_enrollment_identity: acceptance.identity().clone(),
        foundational_adoption_identity: adoption_identity.clone(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let expected_acceptance_receipt = canonical_json_bytes(&SignerAcceptanceReceiptV1 {
        schema: "nq.c2_signer_enrollment_acceptance_receipt.v1",
        acceptance_effect_identity: expected_acceptance_effect.clone(),
        signer_enrollment_identity: acceptance.identity().clone(),
        foundational_adoption_identity: adoption_identity.clone(),
        accepted_cut: acceptance.accepted_cut(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;

    if row.signer_enrollment_identity != signer_enrollment_identity.as_str()
        || acceptance.identity() != signer_enrollment_identity
        || row.signer_enrollment_canonical_sha256
            != sha256_bytes(&row.signer_enrollment_canonical_bytes).as_str()
        || row.foundational_adoption_identity != adoption_identity.as_str()
        || row.foundation_identity != foundation.identity().as_str()
        || row.foundation_canonical_sha256 != sha256_bytes(&row.foundation_canonical_bytes).as_str()
        || row.adoption_canonical_sha256 != sha256_bytes(&row.adoption_canonical_bytes).as_str()
        || row.lineage != adoption.lineage().as_str()
        || adoption.identity() != &adoption_identity
        || adoption.foundation_identity() != foundation.identity()
        || adoption.candidate_identity() != &candidate_identity
        || adoption.attempt_identity() != &attempt_identity
        || adoption.custody_evidence_identity() != &custody_evidence_identity
        || adoption.signer_scope_identity() != &signer_scope_identity
        || row.enrollment_cut != adoption.enrollment_cut()
        || acceptance.foundational_enrollment_identity() != &adoption_identity
        || acceptance.candidate_identity() != adoption.candidate_identity()
        || acceptance.proof_of_possession_identity() != adoption.proof_of_possession_identity()
        || acceptance.attempt_identity() != adoption.attempt_identity()
        || acceptance.accepted_cut() != row.accepted_cut
        || acceptance.accepted_cut() <= adoption.enrollment_cut()
        || adoption_effect_identity != expected_adoption_effect
        || row.adoption_receipt_bytes != expected_adoption_receipt
        || adoption_receipt_identity != sha256_bytes(&row.adoption_receipt_bytes)
        || acceptance_effect_identity != expected_acceptance_effect
        || row.acceptance_receipt_bytes != expected_acceptance_receipt
        || acceptance_receipt_identity != sha256_bytes(&row.acceptance_receipt_bytes)
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    Ok(StoreVerifiedDurableSignerEnrollmentV1 {
        foundation,
        adoption,
        acceptance,
        adoption_effect_identity,
        adoption_receipt_identity,
        acceptance_effect_identity,
        acceptance_receipt_identity,
        adoption_pre_effect_store_snapshot_identity,
        acceptance_pre_effect_store_snapshot_identity,
    })
}

/// Reverify the initial/bootstrap-only durable forward bridge in one Store
/// snapshot. This narrow projection additionally proves the legacy N-18 and
/// exact consumed MSG-02 correspondence needed by bootstrap reopen. It is not
/// the lineage-neutral loader and refuses every successor lineage.
pub(crate) fn load_verified_durable_enrollment_bridge_v1(
    transaction: &Transaction<'_>,
    signer_enrollment_identity: &Sha256Digest,
) -> Result<StoreVerifiedDurableEnrollmentBridgeV1, SignerRefusalV2> {
    let durable =
        load_verified_durable_signer_enrollment_v1(transaction, signer_enrollment_identity)?;
    if durable.adoption().lineage() != FoundationalAdoptionLineageV1::InitialExternal {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }
    let acceptance_row = transaction
        .query_row(
            "SELECT acceptance_effect_identity, signer_enrollment_identity,
                    signer_enrollment_canonical_bytes,
                    signer_enrollment_canonical_sha256,
                    foundational_adoption_identity, accepted_cut,
                    receipt_identity, receipt_bytes
             FROM c2_signer_enrollment_acceptances
             WHERE signer_enrollment_identity = ?1",
            params![signer_enrollment_identity.as_str()],
            |row| {
                Ok(DurableAcceptanceRowV1 {
                    acceptance_effect_identity: row.get(0)?,
                    signer_enrollment_identity: row.get(1)?,
                    canonical_bytes: row.get(2)?,
                    canonical_sha256: row.get(3)?,
                    foundational_adoption_identity: row.get(4)?,
                    accepted_cut: row.get(5)?,
                    receipt_identity: row.get(6)?,
                    receipt_bytes: row.get(7)?,
                })
            },
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    let foundation_row = transaction
        .query_row(
            "SELECT adoption.adoption_identity, adoption.foundation_identity,
                    foundation.foundation_canonical_bytes,
                    foundation.foundation_canonical_sha256,
                    adoption.adoption_canonical_bytes,
                    adoption.adoption_canonical_sha256, adoption.lineage,
                    adoption.foundational_enrollment_identity,
                    adoption.foundational_enrollment_canonical_bytes,
                    adoption.foundational_enrollment_canonical_sha256,
                    adoption.msg02_message_identity, adoption.msg02_append_identity,
                    adoption.msg02_effect_receipt_identity, adoption.grant_identity,
                    adoption.candidate_identity, adoption.attempt_identity,
                    adoption.custody_evidence_identity,
                    adoption.pre_generation_scope_identity,
                    adoption.pre_effect_store_snapshot_identity,
                    adoption.enrollment_cut, adoption.effect_identity,
                    adoption.receipt_identity, adoption.receipt_bytes
             FROM c2_foundational_enrollment_adoptions AS adoption
             JOIN c2_signer_foundations AS foundation
               ON foundation.foundation_identity = adoption.foundation_identity
             WHERE adoption.adoption_identity = ?1",
            params![acceptance_row.foundational_adoption_identity],
            |row| {
                Ok(DurableFoundationRowV1 {
                    adoption_identity: row.get(0)?,
                    foundation_identity: row.get(1)?,
                    foundation_canonical_bytes: row.get(2)?,
                    foundation_canonical_sha256: row.get(3)?,
                    adoption_canonical_bytes: row.get(4)?,
                    adoption_canonical_sha256: row.get(5)?,
                    lineage: row.get(6)?,
                    foundational_enrollment_identity: row.get(7)?,
                    canonical_bytes: row.get(8)?,
                    canonical_sha256: row.get(9)?,
                    msg02_message_identity: row.get(10)?,
                    msg02_append_identity: row.get(11)?,
                    msg02_effect_receipt_identity: row.get(12)?,
                    grant_identity: row.get(13)?,
                    candidate_identity: row.get(14)?,
                    attempt_identity: row.get(15)?,
                    custody_evidence_identity: row.get(16)?,
                    pre_generation_scope_identity: row.get(17)?,
                    pre_effect_store_snapshot_identity: row.get(18)?,
                    enrollment_cut: row.get(19)?,
                    effect_identity: row.get(20)?,
                    receipt_identity: row.get(21)?,
                    receipt_bytes: row.get(22)?,
                })
            },
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    let msg02_row = transaction
        .query_row(
            "SELECT family, route, identity_domain, signature_domain,
                    message_identity, append_identity, signer_public_key,
                    signer_key_generation, event_cut, canonical_message,
                    canonical_message_sha256, signing_preimage,
                    signing_preimage_sha256, signature,
                    resulting_frontier_identity, effect_receipt_identity,
                    effect_receipt_bytes
             FROM c2_signer_message_appends WHERE append_identity = ?1",
            params![foundation_row.msg02_append_identity],
            |row| {
                Ok(DurableMsg02RowV1 {
                    family: row.get(0)?,
                    route: row.get(1)?,
                    identity_domain: row.get(2)?,
                    signature_domain: row.get(3)?,
                    message_identity: row.get(4)?,
                    append_identity: row.get(5)?,
                    signer_public_key: row.get(6)?,
                    signer_key_generation: row.get(7)?,
                    event_cut: row.get(8)?,
                    canonical_message: row.get(9)?,
                    canonical_message_sha256: row.get(10)?,
                    signing_preimage: row.get(11)?,
                    signing_preimage_sha256: row.get(12)?,
                    signature: row.get(13)?,
                    resulting_frontier_identity: row.get(14)?,
                    effect_receipt_identity: row.get(15)?,
                    effect_receipt_bytes: row.get(16)?,
                })
            },
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;

    let foundational = decode_store_integrity_key_enrollment_v1(&foundation_row.canonical_bytes)
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let foundation =
        decode_store_integrity_signer_foundation_v1(&foundation_row.foundation_canonical_bytes)?;
    let adoption_record = decode_foundational_adoption_record_v1(
        &foundation_row.adoption_canonical_bytes,
        &foundation,
    )?;
    let acceptance = decode_store_integrity_enrollment_v2(&acceptance_row.canonical_bytes)?;
    let adoption_identity = parsed_digest(foundation_row.adoption_identity)?;
    let adoption_effect_identity = parsed_digest(foundation_row.effect_identity)?;
    let adoption_receipt_identity = parsed_digest(foundation_row.receipt_identity)?;
    let msg02_append_identity = parsed_digest(foundation_row.msg02_append_identity)?;
    let msg02_effect_receipt_identity =
        parsed_digest(foundation_row.msg02_effect_receipt_identity)?;
    let acceptance_effect_identity = parsed_digest(acceptance_row.acceptance_effect_identity)?;
    let acceptance_receipt_identity = parsed_digest(acceptance_row.receipt_identity)?;
    let msg02_message_identity = exact_identity_bytes(foundation_row.msg02_message_identity)?;
    let grant_identity = exact_identity_bytes(foundation_row.grant_identity)?;
    let candidate_identity = exact_identity_bytes(foundation_row.candidate_identity)?;
    let attempt_identity = exact_identity_bytes(foundation_row.attempt_identity)?;
    let custody_identity_bytes = exact_identity_bytes(foundation_row.custody_evidence_identity)?;
    let custody_evidence_identity = identity_digest(&custody_identity_bytes)?;
    let pre_generation_scope_identity =
        exact_identity_bytes(foundation_row.pre_generation_scope_identity)?;
    let msg02_row_identity = exact_identity_bytes(msg02_row.message_identity)?;
    let msg02_resulting_frontier_identity =
        exact_identity_bytes(msg02_row.resulting_frontier_identity)?;
    let signer_public_key: [u8; 32] = msg02_row
        .signer_public_key
        .try_into()
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let signature: [u8; 64] = msg02_row
        .signature
        .try_into()
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;

    let coordinates = PreGenerationSignerCoordinatesV1 {
        occurrence: foundational.occurrence().as_str().to_owned(),
        signer_scope_policy: foundational.signer_scope_policy().digest().clone(),
        signer_scope_policy_version: foundational.signer_scope_policy_version(),
        a2_chain_root: foundational.a2_chain_root().digest().clone(),
        controlling_activation: foundational.controlling_activation().digest().clone(),
        dependency_anchor: foundational.dependency_anchor().digest().clone(),
        resident: foundational.resident().as_str().to_owned(),
        resident_generation: foundational.resident_generation(),
        role: foundational.role().to_owned(),
        role_manifest: foundational.role_manifest().digest().clone(),
        role_manifest_generation: foundational.role_manifest_generation(),
        authority_domain: foundational.authority_domain().to_owned(),
        activation_policy_version: foundational.activation_policy_version(),
        active_store_policy: foundational.active_store_policy().digest().clone(),
        active_store_policy_generation: foundational.active_store_policy_generation(),
    };
    let expected_scope = pre_generation_scope_identity_v1(&coordinates)?;
    let foundational_public_key: [u8; 32] = hex::decode(foundational.public_key().as_str())
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?
        .try_into()
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let adoption_body = &adoption_record.wire.body;
    let occurrence_identity = identity_digest(&text_coordinate_identity(
        b"nq.c2.store_occurrence.identity.v1\0",
        &coordinates.occurrence,
    )?)?;
    let pre_effect_store_snapshot_identity =
        parsed_digest(foundation_row.pre_effect_store_snapshot_identity.clone())?;
    let expected_transaction = semantic_digest(&InitialAdoptionTransactionIdentityBodyV1 {
        schema: "nq.c2_initial_foundational_adoption_transaction_identity_preimage.v1",
        identity_domain: "nq.c2.initial_foundational_adoption_transaction.identity.v1",
        store_identity: adoption_body.store_identity.clone(),
        pre_effect_store_snapshot_identity: pre_effect_store_snapshot_identity.clone(),
        attempt_identity: identity_digest(&attempt_identity)?,
        msg02_append_identity: msg02_append_identity.clone(),
        enrollment_cut: foundational.enrollment_cut().ledger_position,
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let expected_applicability = semantic_digest(&InitialAdoptionApplicabilityIdentityBodyV1 {
        schema: "nq.c2_initial_foundational_adoption_applicability_identity_preimage.v1",
        identity_domain: "nq.c2.initial_foundational_adoption_applicability.identity.v1",
        interpretation: A2ApplicabilityInterpretationIdentityV1::EXACT,
        active_policy_identity: foundational.active_store_policy().digest().clone(),
        active_policy_generation: foundational.active_store_policy_generation(),
        controlling_activation_identity: foundational.controlling_activation().digest().clone(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;

    if durable.foundation() != &foundation
        || durable.adoption() != &adoption_record
        || durable.acceptance() != &acceptance
        || acceptance_row.signer_enrollment_identity != signer_enrollment_identity.as_str()
        || acceptance.identity() != signer_enrollment_identity
        || acceptance_row.canonical_sha256 != sha256_bytes(&acceptance_row.canonical_bytes).as_str()
        || foundation_row.foundation_identity != foundation.identity().as_str()
        || foundation_row.foundation_canonical_sha256
            != sha256_bytes(&foundation_row.foundation_canonical_bytes).as_str()
        || foundation_row.adoption_canonical_sha256
            != sha256_bytes(&foundation_row.adoption_canonical_bytes).as_str()
        || foundation_row.lineage != adoption_record.lineage().as_str()
        || adoption_record.identity() != &adoption_identity
        || adoption_record.foundation_identity() != foundation.identity()
        || adoption_record.lineage() != FoundationalAdoptionLineageV1::InitialExternal
        || adoption_body.lineage_reference_identity != identity_digest(&grant_identity)?
        || adoption_body.authority_reference_identity != identity_digest(&grant_identity)?
        || adoption_body.occurrence_identity != occurrence_identity
        || adoption_body.signer_scope_identity != identity_digest(&expected_scope)?
        || adoption_body.transaction_identity != expected_transaction
        || adoption_body.policy_basis_identity
            != foundational.active_store_policy().digest().clone()
        || adoption_body.applicability_basis_identity != expected_applicability
        || adoption_body.attempt_identity != identity_digest(&attempt_identity)?
        || adoption_body.candidate_identity != identity_digest(&candidate_identity)?
        || adoption_body.proposal_identity != foundational.proposal_identity().digest().clone()
        || adoption_body.proof_of_possession_identity != identity_digest(&msg02_message_identity)?
        || adoption_body.custody_evidence_identity != custody_evidence_identity
        || adoption_body.public_key_identity
            != stable_public_key_identity_v1(&foundational_public_key)?
        || adoption_body.key_generation_identity
            != stable_key_generation_identity_v1(
                &foundational_public_key,
                u64::from(foundational.key_generation().get()),
            )?
        || adoption_body.enrollment_cut != foundational.enrollment_cut().ledger_position
        || foundation_row.foundational_enrollment_identity
            != foundational.canonical_identity().as_str()
        || foundation_row.canonical_sha256 != sha256_bytes(&foundation_row.canonical_bytes).as_str()
        || acceptance.foundational_enrollment_identity() != &adoption_identity
        || acceptance.wire.candidate_identity != identity_digest(&candidate_identity)?
        || acceptance.wire.pop_identity != identity_digest(&msg02_message_identity)?
        || acceptance.wire.attempt_identity != identity_digest(&attempt_identity)?
        || acceptance.accepted_cut() != acceptance_row.accepted_cut
        || acceptance.accepted_cut()
            != adoption_record
                .enrollment_cut()
                .checked_add(1)
                .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)?
        || foundational.candidate_identity().digest() != &identity_digest(&candidate_identity)?
        || foundational.proof_of_possession_identity().digest()
            != &identity_digest(&msg02_message_identity)?
        || foundational.attempt_identity().digest() != &identity_digest(&attempt_identity)?
        || foundational.bootstrap_grant().digest() != &identity_digest(&grant_identity)?
        || foundational.custody_evidence_identity().digest() != &custody_evidence_identity
        || foundation_row.enrollment_cut != foundational.enrollment_cut().ledger_position
        || foundation_row.enrollment_cut != adoption_record.enrollment_cut()
        || pre_generation_scope_identity != expected_scope
        || signer_public_key != foundational_public_key
        || foundation.public_key()? != foundational_public_key
        || foundation.key_generation() != u64::from(foundational.key_generation().get())
        || foundation.custody_evidence_identity() != &custody_evidence_identity
        || msg02_row.signer_key_generation != u64::from(foundational.key_generation().get())
        || msg02_row.event_cut != foundational.pop_cut().ledger_position
        || msg02_row_identity != msg02_message_identity
        || msg02_row.append_identity != msg02_append_identity.as_str()
        || msg02_row.effect_receipt_identity != msg02_effect_receipt_identity.as_str()
        || msg02_resulting_frontier_identity
            .iter()
            .all(|byte| *byte == 0)
        || msg02_row.family != "MSG-02"
        || msg02_row.route != "msg02_initial_pop"
        || msg02_row.identity_domain != "nq.c2.store_integrity_initial_pop.identity.v1"
        || msg02_row.signature_domain != "nq.c2.store_integrity_initial_pop.possession_signature.v1"
        || msg02_row.canonical_message_sha256 != sha256_bytes(&msg02_row.canonical_message).as_str()
        || msg02_row.signing_preimage_sha256 != sha256_bytes(&msg02_row.signing_preimage).as_str()
        || msg02_row.effect_receipt_identity
            != sha256_bytes(&msg02_row.effect_receipt_bytes).as_str()
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    let message_value: serde_json::Value = serde_json::from_slice(&msg02_row.canonical_message)
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    if canonical_json_bytes(&message_value)
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?
        != msg02_row.canonical_message
        || json_string(&message_value, "schema")? != "nq.c2_store_integrity_signing_message.v1"
        || json_string(&message_value, "family")? != "MSG-02"
        || json_string(&message_value, "route")? != "msg02_initial_pop"
        || json_string(&message_value, "identity_domain")? != msg02_row.identity_domain
        || json_string(&message_value, "signature_domain")? != msg02_row.signature_domain
        || json_string(&message_value, "message_identity")?
            != identity_digest(&msg02_message_identity)?.as_str()
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }
    let message_coordinates = message_value
        .get("coordinates")
        .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let verified_input = message_value
        .get("verified_input")
        .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let public_key_identity = exact_identity(
        b"nq.c2.store_integrity_public_key.identity.v1",
        &[&foundational_public_key],
    );
    if json_string(message_coordinates, "attempt_identity")?
        != identity_digest(&attempt_identity)?.as_str()
        || json_string(message_coordinates, "scope_identity")?
            != identity_digest(&expected_scope)?.as_str()
        || json_string(
            message_coordinates,
            "grant_or_predecessor_standing_identity",
        )? != identity_digest(&grant_identity)?.as_str()
        || json_string(message_coordinates, "proposed_candidate_identity")?
            != identity_digest(&candidate_identity)?.as_str()
        || json_string(message_coordinates, "signer_public_key")?
            != hex::encode(foundational_public_key)
        || json_string(verified_input, "grant_selected_proposal_identity")?
            != foundational.proposal_identity().digest().as_str()
        || json_string(verified_input, "candidate_identity")?
            != identity_digest(&candidate_identity)?.as_str()
        || json_string(verified_input, "challenge_identity")?
            != adoption_body.challenge_identity.as_str()
        || json_string(verified_input, "public_key_identity")?
            != identity_digest(&public_key_identity)?.as_str()
        || json_string(verified_input, "attempt_identity")?
            != identity_digest(&attempt_identity)?.as_str()
        || json_string(verified_input, "pre_generation_scope_identity")?
            != identity_digest(&expected_scope)?.as_str()
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    let mut body_value = message_value.clone();
    body_value
        .as_object_mut()
        .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)?
        .remove("message_identity")
        .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let canonical_body = canonical_json_bytes(&body_value)
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let mut identity_preimage = msg02_row.identity_domain.as_bytes().to_vec();
    identity_preimage.push(0);
    identity_preimage.extend_from_slice(&canonical_body);
    let mut exact_signing_preimage = msg02_row.signature_domain.as_bytes().to_vec();
    exact_signing_preimage.push(0);
    exact_signing_preimage.extend_from_slice(&msg02_row.canonical_message);
    if sha256_bytes(&identity_preimage) != identity_digest(&msg02_message_identity)?
        || exact_signing_preimage != msg02_row.signing_preimage
        || VerifyingKey::from_bytes(&signer_public_key)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?
            .verify_strict(
                &msg02_row.signing_preimage,
                &Signature::from_bytes(&signature),
            )
            .is_err()
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    let expected_adoption_identity = adoption_record.identity().clone();
    let expected_adoption_effect =
        foundational_adoption_effect_identity_v1(&expected_adoption_identity)?;
    let expected_adoption_receipt = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
        schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
        adoption_identity: expected_adoption_identity.clone(),
        effect_identity: expected_adoption_effect.clone(),
        foundation_identity: foundation.identity().clone(),
        lineage: adoption_record.lineage(),
        proof_of_possession_identity: identity_digest(&msg02_message_identity)?,
        enrollment_cut: adoption_record.enrollment_cut(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let expected_acceptance_effect = semantic_digest(&SignerAcceptanceEffectBodyV1 {
        schema: "nq.c2_signer_enrollment_acceptance_effect_identity_preimage.v1",
        identity_domain: "nq.c2.signer_enrollment_acceptance_effect.identity.v1",
        signer_enrollment_identity: acceptance.identity().clone(),
        foundational_adoption_identity: expected_adoption_identity.clone(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    let expected_acceptance_receipt = canonical_json_bytes(&SignerAcceptanceReceiptV1 {
        schema: "nq.c2_signer_enrollment_acceptance_receipt.v1",
        acceptance_effect_identity: expected_acceptance_effect.clone(),
        signer_enrollment_identity: acceptance.identity().clone(),
        foundational_adoption_identity: expected_adoption_identity.clone(),
        accepted_cut: acceptance.accepted_cut(),
    })
    .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
    if adoption_identity != expected_adoption_identity
        || adoption_effect_identity != expected_adoption_effect
        || foundation_row.receipt_bytes != expected_adoption_receipt
        || adoption_receipt_identity != sha256_bytes(&foundation_row.receipt_bytes)
        || acceptance_effect_identity != expected_acceptance_effect
        || acceptance_row.receipt_bytes != expected_acceptance_receipt
        || acceptance_receipt_identity != sha256_bytes(&acceptance_row.receipt_bytes)
    {
        return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
    }

    Ok(StoreVerifiedDurableEnrollmentBridgeV1 {
        challenge_identity: digest_identity(&adoption_body.challenge_identity)?,
        foundation,
        adoption_record,
        foundational,
        acceptance,
        adoption_identity,
        adoption_effect_identity,
        adoption_receipt_identity,
        msg02_append_identity,
        msg02_effect_receipt_identity,
        msg02_resulting_frontier_identity,
        candidate_identity,
        attempt_identity,
        custody_evidence_identity,
        pre_generation_scope_identity,
        pre_effect_store_snapshot_identity,
    })
}

/// Freshly rewrap exact durable enrollment evidence for the current process.
///
/// This is not a phase/currentness constructor. The caller must separately
/// resolve a complete GenerationCurrent state. Durable rows alone cannot call
/// this function: it also requires the actor's current authority projection,
/// a freshly verified governed bootstrap grant, and live descriptor-backed
/// custody.
pub(crate) fn rewrap_verified_durable_enrollment_bridge_v1<'store>(
    actor: &StoreC2SnapshotActorV1<'store>,
    authority_snapshot: &StoreC2AuthoritySnapshotV1<'store>,
    grant: &VerifiedBootstrapGrantV1,
    custody: &VerifiedFoundationalCustodyV1<'_>,
    bridge: StoreVerifiedDurableEnrollmentBridgeV1,
) -> Result<StoreAcceptedSignerEnrollmentV1, SignerRefusalV2> {
    actor
        .verify_authority_lineage(authority_snapshot)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    custody.verify_same_process()?;
    let foundation = bridge.foundation;
    let adoption_record = bridge.adoption_record;
    let challenge_identity = bridge.challenge_identity;
    let foundational = bridge.foundational;
    verify_n_18_key_enrollment(&foundational)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let coordinates = PreGenerationSignerCoordinatesV1 {
        occurrence: foundational.occurrence().as_str().to_owned(),
        signer_scope_policy: foundational.signer_scope_policy().digest().clone(),
        signer_scope_policy_version: foundational.signer_scope_policy_version(),
        a2_chain_root: foundational.a2_chain_root().digest().clone(),
        controlling_activation: foundational.controlling_activation().digest().clone(),
        dependency_anchor: foundational.dependency_anchor().digest().clone(),
        resident: foundational.resident().as_str().to_owned(),
        resident_generation: foundational.resident_generation(),
        role: foundational.role().to_owned(),
        role_manifest: foundational.role_manifest().digest().clone(),
        role_manifest_generation: foundational.role_manifest_generation(),
        authority_domain: foundational.authority_domain().to_owned(),
        activation_policy_version: foundational.activation_policy_version(),
        active_store_policy: foundational.active_store_policy().digest().clone(),
        active_store_policy_generation: foundational.active_store_policy_generation(),
    };
    let public_key: [u8; 32] = hex::decode(foundational.public_key().as_str())
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
        .try_into()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let candidate = construct_sg_rec_05a_candidate(
        foundational.candidate_cut().ledger_position,
        digest_identity(foundational.attempt_identity().digest())?,
        digest_identity(foundational.proposal_identity().digest())?,
        digest_identity(foundational.bootstrap_grant().digest())?,
        digest_identity(foundational.bootstrap_grant_request().digest())?,
        coordinates,
        public_key,
        u64::from(foundational.key_generation().get()),
        digest_identity(foundational.active_store_policy().digest())?,
        foundational.active_store_policy_generation(),
    )?;
    let store_basis = authority_snapshot.admission_basis();
    let current = authority_snapshot.current_activation();
    let grant_request_digest = identity_digest(grant.request_identity().bytes())?;
    let grant_digest = identity_digest(grant.grant_identity().bytes())?;
    let grant_issuer_digest = Sha256Digest::parse(grant.issuer().digest.clone())
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let grant_policy_digest = identity_digest(&grant.installed_policy_calculation_identity())?;
    let grant_custody_digest = identity_digest(&grant.custody_instance_identity())?;
    if candidate.identity != bridge.candidate_identity
        || candidate.attempt_identity != bridge.attempt_identity
        || pre_generation_scope_identity_v1(&candidate.coordinates)?
            != bridge.pre_generation_scope_identity
        || digest_identity(custody.proposal_identity())? != candidate.proposal_identity
        || custody.public_key() != candidate.public_key
        || custody.key_generation() != candidate.key_generation
        || custody.custody_evidence_identity() != &bridge.custody_evidence_identity
        || foundational.custody_evidence_identity().digest() != custody.custody_evidence_identity()
        || foundational.bootstrap_grant_request().digest() != &grant_request_digest
        || foundational.bootstrap_grant().digest() != &grant_digest
        || foundational.bootstrap_issuer().digest() != &grant_issuer_digest
        || foundational.bootstrap_issuer_key_generation() != grant.issuer().key_generation
        || foundational.bootstrap_grant_signature() != hex::encode(grant.canonical_signature())
        || foundational.signer_scope_policy().digest().as_str() != grant.signer_scope_policy()
        || foundational.signer_scope_policy_version() != grant.signer_scope_policy_version()
        || foundational.activation_policy_version() != grant.activation_policy_version()
        || foundational.a2_chain_root().digest().as_str() != grant.a2_chain_root()
        || foundational.controlling_activation().digest().as_str() != grant.controlling_activation()
        || foundational.resident().as_str() != grant.resident_identity()
        || foundational.resident_generation() != grant.resident_generation()
        || foundational.role() != grant.host_role()
        || foundational.role_manifest_generation() != grant.role_manifest_generation()
        || foundational.authority_domain() != grant.authority_domain()
        || foundational.active_store_policy().digest() != &grant_policy_digest
        || foundational.custody_evidence_identity().digest() != &grant_custody_digest
        || store_basis.occurrence_id() != foundational.occurrence().as_str()
        || grant.occurrence_id() != current.occurrence_id()
        || grant.a2_chain_root() != current.chain_root_activation_digest().as_str()
        || grant.controlling_activation() != current.controlling_tip_activation_digest().as_str()
        || grant.resident_identity() != current.resident_identity()
        || grant.resident_generation() != current.resident_generation()
        || grant.host_role() != current.host_role()
        || grant.role_manifest_generation() != current.role_manifest_generation()
        || grant.authority_domain() != current.domain()
        || grant.activation_policy_version() != current.policy_version()
        || grant.issuer().issued_against_candidate_set != current.candidate_set_digest().as_str()
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }

    let pop_identity = digest_identity(foundational.proof_of_possession_identity().digest())?;
    let pop_cut = foundational.pop_cut().ledger_position;
    let acceptance_record = bridge.acceptance;
    let acceptance_effect_identity = semantic_digest(&SignerAcceptanceEffectBodyV1 {
        schema: "nq.c2_signer_enrollment_acceptance_effect_identity_preimage.v1",
        identity_domain: "nq.c2.signer_enrollment_acceptance_effect.identity.v1",
        signer_enrollment_identity: acceptance_record.identity().clone(),
        foundational_adoption_identity: bridge.adoption_identity.clone(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let acceptance_receipt_bytes = canonical_json_bytes(&SignerAcceptanceReceiptV1 {
        schema: "nq.c2_signer_enrollment_acceptance_receipt.v1",
        acceptance_effect_identity: acceptance_effect_identity.clone(),
        signer_enrollment_identity: acceptance_record.identity().clone(),
        foundational_adoption_identity: bridge.adoption_identity.clone(),
        accepted_cut: acceptance_record.accepted_cut(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let adoption = StoreAdoptedFoundationalEnrollmentV1 {
        adoption_identity: bridge.adoption_identity,
        adoption_effect_identity: bridge.adoption_effect_identity,
        adoption_receipt_identity: bridge.adoption_receipt_identity,
        foundation,
        adoption_record,
        provenance: InitialExternalFoundationalAdoptionProvenanceV1 {
            foundational,
            candidate,
            challenge_identity,
            pop_identity,
            pop_cut,
            msg02_append_identity: bridge.msg02_append_identity,
            msg02_effect_receipt_identity: bridge.msg02_effect_receipt_identity,
            msg02_resulting_frontier_identity: bridge.msg02_resulting_frontier_identity,
        },
        custody_evidence_identity: bridge.custody_evidence_identity,
        actor_instance_identity: actor.actor_instance_identity().clone(),
        pre_effect_store_snapshot_identity: bridge.pre_effect_store_snapshot_identity,
        store_snapshot_identity: actor.current_snapshot_identity().clone(),
        process_identity: authority_snapshot
            .admission_basis()
            .process_identity()
            .clone(),
        actor_effect_epoch: actor.effect_epoch(),
        creator_pid: std::process::id(),
    };
    adoption.verify_for_actor(actor)?;
    let accepted = StoreAcceptedSignerEnrollmentV1 {
        record: acceptance_record,
        acceptance_effect_identity,
        acceptance_receipt_identity: sha256_bytes(&acceptance_receipt_bytes),
        adoption,
        actor_instance_identity: actor.actor_instance_identity().clone(),
        store_snapshot_identity: actor.current_snapshot_identity().clone(),
        process_identity: authority_snapshot
            .admission_basis()
            .process_identity()
            .clone(),
        actor_effect_epoch: actor.effect_epoch(),
        creator_pid: std::process::id(),
    };
    accepted.verify_for_actor(actor)?;
    Ok(accepted)
}

fn verify_store_accepted_signer_enrollment_v1<Provenance>(
    accepted: &StoreAcceptedSignerEnrollmentV1<Provenance>,
) -> Result<(), SignerRefusalV2>
where
    Provenance: FoundationalAdoptionProvenanceV1,
{
    verify_foundational_adoption_material_v1(&accepted.adoption)?;
    if accepted.creator_pid != std::process::id()
        || accepted.adoption.creator_pid != std::process::id()
        || accepted.record.foundational_enrollment_identity()
            != accepted.adoption.adoption_identity()
        || accepted.record.wire.candidate_identity
            != identity_digest(&accepted.adoption.provenance.candidate_identity())?
        || accepted.record.wire.pop_identity
            != identity_digest(&accepted.adoption.provenance.proof_of_possession_identity())?
        || accepted.record.wire.attempt_identity
            != identity_digest(&accepted.adoption.provenance.attempt_identity())?
        || accepted.record.accepted_cut()
            != accepted
                .adoption
                .adoption_record
                .enrollment_cut()
                .checked_add(1)
                .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_store_integrity_enrollment_v2(&accepted.record)?;
    let expected_effect_identity = semantic_digest(&SignerAcceptanceEffectBodyV1 {
        schema: "nq.c2_signer_enrollment_acceptance_effect_identity_preimage.v1",
        identity_domain: "nq.c2.signer_enrollment_acceptance_effect.identity.v1",
        signer_enrollment_identity: accepted.record.identity().clone(),
        foundational_adoption_identity: accepted.adoption.adoption_identity().clone(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let expected_receipt_bytes = canonical_json_bytes(&SignerAcceptanceReceiptV1 {
        schema: "nq.c2_signer_enrollment_acceptance_receipt.v1",
        acceptance_effect_identity: expected_effect_identity.clone(),
        signer_enrollment_identity: accepted.record.identity().clone(),
        foundational_adoption_identity: accepted.adoption.adoption_identity().clone(),
        accepted_cut: accepted.record.accepted_cut(),
    })
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if accepted.acceptance_effect_identity != expected_effect_identity
        || accepted.acceptance_receipt_identity != sha256_bytes(&expected_receipt_bytes)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

/// Narrow bootstrap verifier retained for SG-REC-05 and installation code.
/// Its default provenance parameter makes N18/MSG-02 projections impossible
/// to request from a non-initial accepted enrollment.
pub(crate) fn verify_sg_rec_05_accepted_wrapper(
    accepted: &StoreAcceptedSignerEnrollmentV1,
) -> Result<(), SignerRefusalV2> {
    verify_store_accepted_signer_enrollment_v1(accepted)
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
    use rusqlite::{Connection, params};
    use serde_json::Value;

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
            resident: "resident/node-a".to_owned(),
            resident_generation: 1,
            role: id(6),
            role_manifest_generation: 1,
            authority_domain: id(7),
            signer_policy: id(8),
            signer_policy_version: 1,
        }
    }

    fn pre_generation_coordinates() -> PreGenerationSignerCoordinatesV1 {
        PreGenerationSignerCoordinatesV1 {
            occurrence: "occurrence-1".into(),
            signer_scope_policy: sha256_bytes(b"signer-scope-policy"),
            signer_scope_policy_version: 1,
            a2_chain_root: sha256_bytes(b"a2-root"),
            controlling_activation: sha256_bytes(b"activation"),
            dependency_anchor: sha256_bytes(b"anchor"),
            resident: "resident/node-a".into(),
            resident_generation: 1,
            role: "nq.host_role.store.v1".into(),
            role_manifest: sha256_bytes(b"role-manifest"),
            role_manifest_generation: 1,
            authority_domain: "nq.store.v1".into(),
            activation_policy_version: 1,
            active_store_policy: sha256_bytes(b"active-policy"),
            active_store_policy_generation: 1,
        }
    }

    fn foundational_adoption_body(
        foundation: &StoreIntegritySignerFoundationV1,
        lineage: FoundationalAdoptionLineageV1,
        salt: u8,
    ) -> FoundationalAdoptionBodyV1 {
        let generation_coordinate = (lineage != FoundationalAdoptionLineageV1::InitialExternal)
            .then(|| sha256_bytes(&[salt, 1]));
        let lineage_reference_identity = sha256_bytes(&[salt, 2]);
        FoundationalAdoptionBodyV1 {
            schema: FOUNDATIONAL_ADOPTION_SCHEMA_V1.to_owned(),
            schema_version: 1,
            identity_domain: FOUNDATIONAL_ADOPTION_IDENTITY_DOMAIN_V1.to_owned(),
            foundation_identity: foundation.identity().clone(),
            lineage,
            lineage_reference_identity: lineage_reference_identity.clone(),
            authority_reference_identity: if lineage
                == FoundationalAdoptionLineageV1::InitialExternal
            {
                lineage_reference_identity
            } else {
                sha256_bytes(&[salt, 3])
            },
            store_identity: sha256_bytes(&[salt, 4]),
            occurrence_identity: sha256_bytes(&[salt, 5]),
            signer_scope_identity: sha256_bytes(&[salt, 6]),
            physical_generation_identity: generation_coordinate.clone(),
            lifecycle_root_identity: generation_coordinate.clone(),
            frontier_identity: generation_coordinate.clone(),
            current_predecessor_identity: generation_coordinate.clone(),
            transition_identity: generation_coordinate,
            transaction_identity: sha256_bytes(&[salt, 7]),
            policy_basis_identity: sha256_bytes(&[salt, 8]),
            applicability_basis_identity: sha256_bytes(&[salt, 9]),
            attempt_identity: sha256_bytes(&[salt, 10]),
            candidate_identity: sha256_bytes(&[salt, 11]),
            proposal_identity: sha256_bytes(&[salt, 12]),
            challenge_identity: sha256_bytes(&[salt, 13]),
            proof_of_possession_identity: sha256_bytes(&[salt, 14]),
            custody_evidence_identity: foundation.custody_evidence_identity().clone(),
            public_key_identity: foundation.public_key_identity().unwrap(),
            key_generation_identity: foundation.key_generation_identity().unwrap(),
            enrollment_cut: u64::from(salt) + 1,
        }
    }

    /// Test-only provenance lets the generic acceptance law be exercised
    /// without forging the production `ConsumedStoreFoundationAdoptionAuthorityV1`,
    /// whose fields and constructors remain sealed in the Store actor.
    struct TestClosedAdoptionProvenanceV1 {
        lineage: FoundationalAdoptionLineageV1,
        candidate_identity: SignerIdentityV1,
        attempt_identity: SignerIdentityV1,
        proof_identity: SignerIdentityV1,
        candidate_cut: u64,
        proof_cut: u64,
    }

    impl SealedAdoptionProvenanceV1 for TestClosedAdoptionProvenanceV1 {}

    impl FoundationalAdoptionProvenanceV1 for TestClosedAdoptionProvenanceV1 {
        fn candidate_identity(&self) -> SignerIdentityV1 {
            self.candidate_identity
        }

        fn attempt_identity(&self) -> SignerIdentityV1 {
            self.attempt_identity
        }

        fn proof_of_possession_identity(&self) -> SignerIdentityV1 {
            self.proof_identity
        }

        fn candidate_cut(&self) -> u64 {
            self.candidate_cut
        }

        fn proof_cut(&self) -> u64 {
            self.proof_cut
        }

        fn verify_material(
            &self,
            view: &FoundationalAdoptionMaterialViewV1<'_>,
        ) -> Result<(), SignerRefusalV2> {
            let record = view.adoption_record;
            if record.lineage() != self.lineage
                || record.candidate_identity() != &identity_digest(&self.candidate_identity)?
                || record.attempt_identity() != &identity_digest(&self.attempt_identity)?
                || record.proof_of_possession_identity() != &identity_digest(&self.proof_identity)?
                || record.foundation_identity() != view.foundation.identity()
                || record.custody_evidence_identity() != view.custody_evidence_identity
            {
                return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
            }
            Ok(())
        }
    }

    fn test_sealed_adoption(
        lineage: FoundationalAdoptionLineageV1,
        salt: u8,
    ) -> StoreAdoptedFoundationalEnrollmentV1<TestClosedAdoptionProvenanceV1> {
        let generation = if lineage == FoundationalAdoptionLineageV1::InitialExternal {
            0
        } else {
            u64::from(salt)
        };
        let foundation = construct_store_integrity_signer_foundation_v1(
            [salt; 32],
            generation,
            sha256_bytes(&[salt, 80]),
        )
        .unwrap();
        let adoption_record = construct_foundational_adoption_record_v1(
            &foundation,
            foundational_adoption_body(&foundation, lineage, salt),
        )
        .unwrap();
        let adoption_identity = adoption_record.identity().clone();
        let adoption_effect_identity =
            foundational_adoption_effect_identity_v1(&adoption_identity).unwrap();
        let receipt_bytes = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
            schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
            adoption_identity: adoption_identity.clone(),
            effect_identity: adoption_effect_identity.clone(),
            foundation_identity: foundation.identity().clone(),
            lineage,
            proof_of_possession_identity: adoption_record.proof_of_possession_identity().clone(),
            enrollment_cut: adoption_record.enrollment_cut(),
        })
        .unwrap();
        let provenance = TestClosedAdoptionProvenanceV1 {
            lineage,
            candidate_identity: digest_identity(adoption_record.candidate_identity()).unwrap(),
            attempt_identity: digest_identity(adoption_record.attempt_identity()).unwrap(),
            proof_identity: digest_identity(adoption_record.proof_of_possession_identity())
                .unwrap(),
            candidate_cut: adoption_record.enrollment_cut() - 2,
            proof_cut: adoption_record.enrollment_cut() - 1,
        };
        StoreAdoptedFoundationalEnrollmentV1 {
            adoption_identity,
            adoption_effect_identity,
            adoption_receipt_identity: sha256_bytes(&receipt_bytes),
            custody_evidence_identity: foundation.custody_evidence_identity().clone(),
            foundation,
            adoption_record,
            provenance,
            actor_instance_identity: sha256_bytes(&[salt, 81]),
            pre_effect_store_snapshot_identity: sha256_bytes(&[salt, 82]),
            store_snapshot_identity: sha256_bytes(&[salt, 83]),
            process_identity: sha256_bytes(&[salt, 84]),
            actor_effect_epoch: 1,
            creator_pid: std::process::id(),
        }
    }

    #[test]
    fn stable_foundation_is_canonical_deterministic_inert_evidence() {
        let custody = sha256_bytes(b"custody-a");
        let first =
            construct_store_integrity_signer_foundation_v1([7; 32], 3, custody.clone()).unwrap();
        let second =
            construct_store_integrity_signer_foundation_v1([7; 32], 3, custody.clone()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.identity(), second.identity());
        assert_eq!(
            decode_store_integrity_signer_foundation_v1(first.canonical_bytes()).unwrap(),
            first
        );

        // Stable evidence contains no adoption, Store, process, or live-authority
        // coordinate from which standing could be reconstructed.
        let value = serde_json::to_value(&first).unwrap();
        for forbidden in [
            "lineage",
            "store_identity",
            "store_snapshot_identity",
            "process_identity",
            "adoption_identity",
            "standing",
        ] {
            assert!(value.get(forbidden).is_none(), "unexpected {forbidden}");
        }

        let changed =
            construct_store_integrity_signer_foundation_v1([7; 32], 3, sha256_bytes(b"custody-b"))
                .unwrap();
        assert_ne!(first.identity(), changed.identity());

        let mut substituted = value;
        substituted["custody_evidence_identity"] =
            serde_json::to_value(sha256_bytes(b"custody-substituted")).unwrap();
        let substituted_bytes = canonical_json_bytes(&substituted).unwrap();
        assert!(decode_store_integrity_signer_foundation_v1(&substituted_bytes).is_err());
        assert!(
            decode_store_integrity_signer_foundation_v1(
                &serde_json::to_vec_pretty(&serde_json::to_value(&first).unwrap()).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn bootstrap_generation_zero_is_a_canonical_persistable_foundation() {
        let foundation = construct_store_integrity_signer_foundation_v1(
            [7; 32],
            0,
            sha256_bytes(b"bootstrap-generation-zero-custody"),
        )
        .unwrap();
        assert_eq!(foundation.key_generation(), 0);
        assert_eq!(
            decode_store_integrity_signer_foundation_v1(foundation.canonical_bytes()).unwrap(),
            foundation
        );

        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        connection
            .execute(
                "INSERT INTO c2_signer_foundations (
                    foundation_identity, foundation_canonical_bytes,
                    foundation_canonical_sha256, algorithm, public_key,
                    key_generation, custody_evidence_identity, committed_at
                 ) VALUES (?1, ?2, ?3, 'ed25519', ?4, 0, ?5, 'now')",
                params![
                    foundation.identity().as_str(),
                    foundation.canonical_bytes(),
                    sha256_bytes(foundation.canonical_bytes()).as_str(),
                    &foundation.public_key().unwrap()[..],
                    &digest_identity(foundation.custody_evidence_identity()).unwrap()[..],
                ],
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT key_generation FROM c2_signer_foundations
                     WHERE foundation_identity = ?1",
                    [foundation.identity().as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn signer_acceptance_consumes_a_sealed_adoption_for_each_closed_lineage() {
        for (index, lineage) in FoundationalAdoptionLineageV1::ALL.into_iter().enumerate() {
            // Salt starts at 3 so the fixture has two exact earlier cuts.
            let adoption = test_sealed_adoption(lineage, index as u8 + 3);
            verify_foundational_adoption_material_v1(&adoption).unwrap();
            let accepted_cut = adoption.adoption_record.enrollment_cut() + 1;
            let acceptance = construct_durable_signer_acceptance(&adoption, accepted_cut).unwrap();
            assert_eq!(
                acceptance.foundational_enrollment_identity(),
                adoption.adoption_record.identity()
            );
            assert_eq!(
                acceptance.candidate_identity(),
                adoption.adoption_record.candidate_identity()
            );
            assert_eq!(
                acceptance.proof_of_possession_identity(),
                adoption.adoption_record.proof_of_possession_identity()
            );
            assert_eq!(
                acceptance.attempt_identity(),
                adoption.adoption_record.attempt_identity()
            );
            assert_eq!(acceptance.accepted_cut(), accepted_cut);
        }
    }

    #[test]
    fn foundational_adoption_has_one_closed_lineage_and_exact_shape() {
        let foundation =
            construct_store_integrity_signer_foundation_v1([9; 32], 4, sha256_bytes(b"custody"))
                .unwrap();
        let expected = [
            (
                FoundationalAdoptionLineageV1::InitialExternal,
                "initialExternal",
            ),
            (
                FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
                "ordinarySuccessorContinuity",
            ),
            (
                FoundationalAdoptionLineageV1::RestoreHistorical,
                "restoreHistorical",
            ),
            (
                FoundationalAdoptionLineageV1::RecoveryNewFoundation,
                "recoveryNewFoundation",
            ),
        ];
        assert_eq!(
            FoundationalAdoptionLineageV1::ALL,
            expected.map(|entry| entry.0)
        );
        for (index, (lineage, wire_name)) in expected.into_iter().enumerate() {
            let adoption = construct_foundational_adoption_record_v1(
                &foundation,
                foundational_adoption_body(&foundation, lineage, index as u8 + 1),
            )
            .unwrap();
            assert_eq!(adoption.lineage(), lineage);
            assert_eq!(
                serde_json::to_value(&adoption).unwrap()["lineage"],
                wire_name
            );
            assert_eq!(
                decode_foundational_adoption_record_v1(adoption.canonical_bytes(), &foundation)
                    .unwrap(),
                adoption
            );
        }

        let mut malformed_initial = foundational_adoption_body(
            &foundation,
            FoundationalAdoptionLineageV1::InitialExternal,
            20,
        );
        malformed_initial.physical_generation_identity = Some(sha256_bytes(b"generation"));
        assert!(construct_foundational_adoption_record_v1(&foundation, malformed_initial).is_err());

        let mut malformed_successor = foundational_adoption_body(
            &foundation,
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
            21,
        );
        malformed_successor.transition_identity = None;
        assert!(
            construct_foundational_adoption_record_v1(&foundation, malformed_successor).is_err()
        );
    }

    #[test]
    fn every_legal_adoption_coordinate_mutation_changes_its_effect_identity() {
        let foundation = construct_store_integrity_signer_foundation_v1(
            [10; 32],
            10,
            sha256_bytes(b"coordinate-mutation-custody"),
        )
        .unwrap();
        let base_body = foundational_adoption_body(
            &foundation,
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
            10,
        );
        let base =
            construct_foundational_adoption_record_v1(&foundation, base_body.clone()).unwrap();
        let base_effect = foundational_adoption_effect_identity_v1(base.identity()).unwrap();
        let mut mutations = Vec::new();
        let mut changed =
            |label: &'static str, update: &dyn Fn(&mut FoundationalAdoptionBodyV1)| {
                let mut body = base_body.clone();
                update(&mut body);
                mutations.push((label, body));
            };
        changed("lineage", &|body| {
            body.lineage = FoundationalAdoptionLineageV1::RestoreHistorical;
        });
        changed("lineage reference", &|body| {
            body.lineage_reference_identity = sha256_bytes(b"changed lineage reference");
        });
        changed("authority reference", &|body| {
            body.authority_reference_identity = sha256_bytes(b"changed authority reference");
        });
        changed("Store", &|body| {
            body.store_identity = sha256_bytes(b"changed Store");
        });
        changed("occurrence", &|body| {
            body.occurrence_identity = sha256_bytes(b"changed occurrence");
        });
        changed("scope", &|body| {
            body.signer_scope_identity = sha256_bytes(b"changed scope");
        });
        changed("physical generation", &|body| {
            body.physical_generation_identity = Some(sha256_bytes(b"changed generation"));
        });
        changed("lifecycle root", &|body| {
            body.lifecycle_root_identity = Some(sha256_bytes(b"changed root"));
        });
        changed("frontier", &|body| {
            body.frontier_identity = Some(sha256_bytes(b"changed frontier"));
        });
        changed("current predecessor", &|body| {
            body.current_predecessor_identity = Some(sha256_bytes(b"changed predecessor"));
        });
        changed("transition", &|body| {
            body.transition_identity = Some(sha256_bytes(b"changed transition"));
        });
        changed("transaction", &|body| {
            body.transaction_identity = sha256_bytes(b"changed transaction");
        });
        changed("policy", &|body| {
            body.policy_basis_identity = sha256_bytes(b"changed policy");
        });
        changed("applicability", &|body| {
            body.applicability_basis_identity = sha256_bytes(b"changed applicability");
        });
        changed("attempt", &|body| {
            body.attempt_identity = sha256_bytes(b"changed attempt");
        });
        changed("candidate", &|body| {
            body.candidate_identity = sha256_bytes(b"changed candidate");
        });
        changed("proposal", &|body| {
            body.proposal_identity = sha256_bytes(b"changed proposal");
        });
        changed("challenge", &|body| {
            body.challenge_identity = sha256_bytes(b"changed challenge");
        });
        changed("PoP", &|body| {
            body.proof_of_possession_identity = sha256_bytes(b"changed PoP");
        });
        changed("cut", &|body| body.enrollment_cut += 1);
        for (label, body) in mutations {
            let adoption = construct_foundational_adoption_record_v1(&foundation, body).unwrap();
            assert_ne!(adoption.identity(), base.identity(), "{label}");
            assert_ne!(
                foundational_adoption_effect_identity_v1(adoption.identity()).unwrap(),
                base_effect,
                "{label}"
            );
        }

        // Foundation-bound key/custody coordinates move as one stable
        // semantic basis. A complete new basis changes the adoption/effect;
        // independently spliced coordinates are rejected before any effect.
        let new_foundation = construct_store_integrity_signer_foundation_v1(
            [11; 32],
            11,
            sha256_bytes(b"new coordinate-mutation-custody"),
        )
        .unwrap();
        let new_basis_adoption = construct_foundational_adoption_record_v1(
            &new_foundation,
            foundational_adoption_body(
                &new_foundation,
                FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
                10,
            ),
        )
        .unwrap();
        assert_ne!(
            foundational_adoption_effect_identity_v1(new_basis_adoption.identity()).unwrap(),
            base_effect
        );
        for splice in [0_u8, 1, 2] {
            let mut body = base_body.clone();
            match splice {
                0 => body.custody_evidence_identity = sha256_bytes(b"spliced custody"),
                1 => body.public_key_identity = sha256_bytes(b"spliced public key"),
                _ => body.key_generation_identity = sha256_bytes(b"spliced key generation"),
            }
            assert!(construct_foundational_adoption_record_v1(&foundation, body).is_err());
        }
    }

    #[test]
    fn restore_readopts_same_foundation_but_recovery_uses_new_foundation() {
        let historical = construct_store_integrity_signer_foundation_v1(
            [3; 32],
            8,
            sha256_bytes(b"historical-custody"),
        )
        .unwrap();
        let original = construct_foundational_adoption_record_v1(
            &historical,
            foundational_adoption_body(
                &historical,
                FoundationalAdoptionLineageV1::InitialExternal,
                1,
            ),
        )
        .unwrap();
        let restored = construct_foundational_adoption_record_v1(
            &historical,
            foundational_adoption_body(
                &historical,
                FoundationalAdoptionLineageV1::RestoreHistorical,
                2,
            ),
        )
        .unwrap();
        assert_eq!(
            original.foundation_identity(),
            restored.foundation_identity()
        );
        assert_ne!(original.identity(), restored.identity());

        let recovered = construct_store_integrity_signer_foundation_v1(
            [4; 32],
            9,
            sha256_bytes(b"recovery-custody"),
        )
        .unwrap();
        let recovery_adoption = construct_foundational_adoption_record_v1(
            &recovered,
            foundational_adoption_body(
                &recovered,
                FoundationalAdoptionLineageV1::RecoveryNewFoundation,
                3,
            ),
        )
        .unwrap();
        assert_ne!(historical.identity(), recovered.identity());
        assert_ne!(
            restored.foundation_identity(),
            recovery_adoption.foundation_identity()
        );
    }

    fn insert_durable_enrollment_fixture(
        transaction: &Transaction<'_>,
        foundation: &StoreIntegritySignerFoundationV1,
        lineage: FoundationalAdoptionLineageV1,
        salt: u8,
    ) -> (Sha256Digest, Sha256Digest) {
        transaction
            .execute(
                "INSERT OR IGNORE INTO c2_signer_foundations (
                    foundation_identity, foundation_canonical_bytes,
                    foundation_canonical_sha256, algorithm, public_key,
                    key_generation, custody_evidence_identity, committed_at
                 ) VALUES (?1, ?2, ?3, 'ed25519', ?4, ?5, ?6, 'now')",
                params![
                    foundation.identity().as_str(),
                    foundation.canonical_bytes(),
                    sha256_bytes(foundation.canonical_bytes()).as_str(),
                    &foundation.public_key().unwrap()[..],
                    foundation.key_generation(),
                    &digest_identity(foundation.custody_evidence_identity()).unwrap()[..],
                ],
            )
            .unwrap();

        let adoption = construct_foundational_adoption_record_v1(
            foundation,
            foundational_adoption_body(foundation, lineage, salt),
        )
        .unwrap();
        let adoption_identity = adoption.identity().clone();
        let adoption_effect_identity =
            foundational_adoption_effect_identity_v1(&adoption_identity).unwrap();
        let adoption_receipt_bytes = canonical_json_bytes(&FoundationalAdoptionReceiptV1 {
            schema: "nq.c2_foundational_enrollment_adoption_receipt.v1",
            adoption_identity: adoption_identity.clone(),
            effect_identity: adoption_effect_identity.clone(),
            foundation_identity: foundation.identity().clone(),
            lineage,
            proof_of_possession_identity: adoption.proof_of_possession_identity().clone(),
            enrollment_cut: adoption.enrollment_cut(),
        })
        .unwrap();
        let foundational_identity = (lineage == FoundationalAdoptionLineageV1::InitialExternal)
            .then(|| sha256_bytes(&[salt, 30]));
        let foundational_bytes = foundational_identity.as_ref().map(|_| b"{}".to_vec());
        let foundational_sha = foundational_bytes
            .as_ref()
            .map(|bytes| sha256_bytes(bytes).to_string());
        let msg02_identity = foundational_identity.as_ref().map(|_| {
            digest_identity(&sha256_bytes(&[salt, 31]))
                .unwrap()
                .to_vec()
        });
        let msg02_append = foundational_identity
            .as_ref()
            .map(|_| sha256_bytes(&[salt, 32]).to_string());
        let msg02_receipt = foundational_identity
            .as_ref()
            .map(|_| sha256_bytes(&[salt, 33]).to_string());
        let grant_identity = foundational_identity.as_ref().map(|_| {
            digest_identity(&sha256_bytes(&[salt, 34]))
                .unwrap()
                .to_vec()
        });
        transaction
            .execute(
                "INSERT INTO c2_foundational_enrollment_adoptions (
                    adoption_sequence, adoption_identity, foundation_identity,
                    adoption_canonical_bytes, adoption_canonical_sha256, lineage,
                    foundational_enrollment_identity,
                    foundational_enrollment_canonical_bytes,
                    foundational_enrollment_canonical_sha256,
                    msg02_message_identity, msg02_append_identity,
                    msg02_effect_receipt_identity, grant_identity,
                    candidate_identity, attempt_identity, custody_evidence_identity,
                    pre_generation_scope_identity, pre_effect_store_snapshot_identity,
                    process_identity, actor_instance_identity, actor_effect_epoch,
                    enrollment_cut, effect_identity, receipt_identity, receipt_bytes,
                    committed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                           ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
                           ?20, 0, ?21, ?22, ?23, ?24, 'now')",
                params![
                    u64::from(salt),
                    adoption_identity.as_str(),
                    foundation.identity().as_str(),
                    adoption.canonical_bytes(),
                    sha256_bytes(adoption.canonical_bytes()).as_str(),
                    lineage.as_str(),
                    foundational_identity.as_ref().map(Sha256Digest::as_str),
                    foundational_bytes,
                    foundational_sha,
                    msg02_identity,
                    msg02_append,
                    msg02_receipt,
                    grant_identity,
                    &digest_identity(adoption.candidate_identity()).unwrap()[..],
                    &digest_identity(adoption.attempt_identity()).unwrap()[..],
                    &digest_identity(adoption.custody_evidence_identity()).unwrap()[..],
                    &digest_identity(adoption.signer_scope_identity()).unwrap()[..],
                    sha256_bytes(&[salt, 40]).as_str(),
                    sha256_bytes(&[salt, 41]).as_str(),
                    sha256_bytes(&[salt, 42]).as_str(),
                    adoption.enrollment_cut(),
                    adoption_effect_identity.as_str(),
                    sha256_bytes(&adoption_receipt_bytes).as_str(),
                    adoption_receipt_bytes,
                ],
            )
            .unwrap();

        let acceptance_body = acceptance_body(
            adoption_identity.clone(),
            adoption.candidate_identity().clone(),
            adoption.proof_of_possession_identity().clone(),
            adoption.attempt_identity().clone(),
            adoption.enrollment_cut() + 1,
        );
        let acceptance_identity = semantic_digest(&acceptance_body).unwrap();
        let acceptance_wire = StoreIntegrityEnrollmentWireV2 {
            schema: acceptance_body.schema,
            schema_version: acceptance_body.schema_version,
            identity_domain: acceptance_body.identity_domain,
            enrollment_identity: acceptance_identity.clone(),
            foundational_enrollment_identity: adoption_identity.clone(),
            candidate_identity: acceptance_body.candidate_identity,
            pop_identity: acceptance_body.pop_identity,
            attempt_identity: acceptance_body.attempt_identity,
            accepted_cut: acceptance_body.accepted_cut,
        };
        let acceptance_bytes = canonical_json_bytes(&acceptance_wire).unwrap();
        let acceptance_effect_identity = semantic_digest(&SignerAcceptanceEffectBodyV1 {
            schema: "nq.c2_signer_enrollment_acceptance_effect_identity_preimage.v1",
            identity_domain: "nq.c2.signer_enrollment_acceptance_effect.identity.v1",
            signer_enrollment_identity: acceptance_identity.clone(),
            foundational_adoption_identity: adoption_identity.clone(),
        })
        .unwrap();
        let acceptance_receipt_bytes = canonical_json_bytes(&SignerAcceptanceReceiptV1 {
            schema: "nq.c2_signer_enrollment_acceptance_receipt.v1",
            acceptance_effect_identity: acceptance_effect_identity.clone(),
            signer_enrollment_identity: acceptance_identity.clone(),
            foundational_adoption_identity: adoption_identity.clone(),
            accepted_cut: acceptance_wire.accepted_cut,
        })
        .unwrap();
        transaction
            .execute(
                "INSERT INTO c2_signer_enrollment_acceptances (
                    acceptance_sequence, acceptance_effect_identity,
                    signer_enrollment_identity, signer_enrollment_canonical_bytes,
                    signer_enrollment_canonical_sha256,
                    foundational_adoption_identity, pre_effect_store_snapshot_identity,
                    process_identity, actor_instance_identity, actor_effect_epoch,
                    accepted_cut, receipt_identity, receipt_bytes, committed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10,
                           ?11, ?12, 'now')",
                params![
                    u64::from(salt),
                    acceptance_effect_identity.as_str(),
                    acceptance_identity.as_str(),
                    acceptance_bytes,
                    sha256_bytes(&acceptance_bytes).as_str(),
                    adoption_identity.as_str(),
                    sha256_bytes(&[salt, 43]).as_str(),
                    sha256_bytes(&[salt, 44]).as_str(),
                    sha256_bytes(&[salt, 45]).as_str(),
                    acceptance_wire.accepted_cut,
                    sha256_bytes(&acceptance_receipt_bytes).as_str(),
                    acceptance_receipt_bytes,
                ],
            )
            .unwrap();
        (acceptance_identity, adoption_identity)
    }

    fn lineage_neutral_loader_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        // Initial MSG-02 correspondence belongs to the narrow bootstrap
        // projection. These loader-only fixtures disable that one trigger and
        // FK enforcement so the common verifier can be exercised uniformly;
        // dedicated tests below retain the production trigger/FK checks.
        connection
            .execute_batch(
                "DROP TRIGGER c2_foundational_enrollment_requires_exact_msg02_append;
                 PRAGMA foreign_keys = OFF;",
            )
            .unwrap();
        connection
    }

    #[test]
    fn lineage_neutral_durable_loader_accepts_all_four_exact_shapes() {
        let mut connection = lineage_neutral_loader_connection();
        let transaction = connection.transaction().unwrap();
        for (index, lineage) in FoundationalAdoptionLineageV1::ALL.into_iter().enumerate() {
            let salt = index as u8 + 1;
            let foundation = construct_store_integrity_signer_foundation_v1(
                [salt; 32],
                u64::from(salt),
                sha256_bytes(&[salt, 50]),
            )
            .unwrap();
            let (acceptance_identity, adoption_identity) =
                insert_durable_enrollment_fixture(&transaction, &foundation, lineage, salt);
            let loaded =
                load_verified_durable_signer_enrollment_v1(&transaction, &acceptance_identity)
                    .unwrap();
            assert_eq!(loaded.foundation().identity(), foundation.identity());
            assert_eq!(loaded.adoption().identity(), &adoption_identity);
            assert_eq!(loaded.adoption().lineage(), lineage);
            assert_eq!(loaded.acceptance().identity(), &acceptance_identity);
            assert!(
                load_verified_durable_enrollment_bridge_v1(&transaction, &acceptance_identity)
                    .is_err(),
                "loader-only fixtures cannot satisfy the narrow bootstrap MSG-02 projection"
            );
        }
    }

    #[test]
    fn durable_restore_reuses_foundation_while_recovery_uses_a_new_one() {
        let mut connection = lineage_neutral_loader_connection();
        let transaction = connection.transaction().unwrap();
        let historical = construct_store_integrity_signer_foundation_v1(
            [21; 32],
            21,
            sha256_bytes(b"historical durable custody"),
        )
        .unwrap();
        let (original_acceptance, original_adoption) = insert_durable_enrollment_fixture(
            &transaction,
            &historical,
            FoundationalAdoptionLineageV1::InitialExternal,
            21,
        );
        let (restore_acceptance, restore_adoption) = insert_durable_enrollment_fixture(
            &transaction,
            &historical,
            FoundationalAdoptionLineageV1::RestoreHistorical,
            22,
        );
        let recovered = construct_store_integrity_signer_foundation_v1(
            [23; 32],
            23,
            sha256_bytes(b"new recovery custody"),
        )
        .unwrap();
        let (recovery_acceptance, _) = insert_durable_enrollment_fixture(
            &transaction,
            &recovered,
            FoundationalAdoptionLineageV1::RecoveryNewFoundation,
            23,
        );
        let original =
            load_verified_durable_signer_enrollment_v1(&transaction, &original_acceptance).unwrap();
        let restored =
            load_verified_durable_signer_enrollment_v1(&transaction, &restore_acceptance).unwrap();
        let recovery =
            load_verified_durable_signer_enrollment_v1(&transaction, &recovery_acceptance).unwrap();
        assert_eq!(
            original.foundation().identity(),
            restored.foundation().identity()
        );
        assert_ne!(original_adoption, restore_adoption);
        assert_ne!(
            restored.foundation().identity(),
            recovery.foundation().identity()
        );
    }

    fn one_durable_fixture(
        lineage: FoundationalAdoptionLineageV1,
        salt: u8,
    ) -> (Connection, Sha256Digest, Sha256Digest) {
        let mut connection = lineage_neutral_loader_connection();
        let transaction = connection.transaction().unwrap();
        let foundation = construct_store_integrity_signer_foundation_v1(
            [salt; 32],
            u64::from(salt),
            sha256_bytes(&[salt, 60]),
        )
        .unwrap();
        let (acceptance, adoption) =
            insert_durable_enrollment_fixture(&transaction, &foundation, lineage, salt);
        transaction.commit().unwrap();
        (connection, acceptance, adoption)
    }

    #[test]
    fn durable_loader_refuses_lineage_foundation_adoption_and_acceptance_collisions() {
        let (connection, acceptance, adoption) = one_durable_fixture(
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
            70,
        );
        connection
            .execute_batch(
                "DROP TRIGGER immutable_c2_foundational_enrollment_adoptions_update;
                 PRAGMA ignore_check_constraints = ON;",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE c2_foundational_enrollment_adoptions
                 SET lineage = 'restoreHistorical' WHERE adoption_identity = ?1",
                params![adoption.as_str()],
            )
            .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(
            load_verified_durable_signer_enrollment_v1(&transaction, &acceptance).is_err(),
            "a row-selected lineage cannot relabel the canonical adoption"
        );

        let (mut connection, first_acceptance, first_adoption) = one_durable_fixture(
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
            71,
        );
        let transaction = connection.transaction().unwrap();
        let other_foundation = construct_store_integrity_signer_foundation_v1(
            [72; 32],
            72,
            sha256_bytes(b"substituted foundation"),
        )
        .unwrap();
        let (other_acceptance, other_adoption) = insert_durable_enrollment_fixture(
            &transaction,
            &other_foundation,
            FoundationalAdoptionLineageV1::RecoveryNewFoundation,
            72,
        );
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER immutable_c2_foundational_enrollment_adoptions_update;
                 DROP TRIGGER immutable_c2_signer_enrollment_acceptances_update;
                 DROP TRIGGER immutable_c2_signer_enrollment_acceptances_delete;
                 PRAGMA ignore_check_constraints = ON;",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE c2_foundational_enrollment_adoptions
                 SET foundation_identity = ?1 WHERE adoption_identity = ?2",
                params![
                    other_foundation.identity().as_str(),
                    first_adoption.as_str()
                ],
            )
            .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(
            load_verified_durable_signer_enrollment_v1(&transaction, &first_acceptance).is_err(),
            "a different stable foundation cannot satisfy the canonical adoption"
        );
        transaction.rollback().unwrap();

        connection
            .execute(
                "DELETE FROM c2_signer_enrollment_acceptances
                 WHERE signer_enrollment_identity = ?1",
                params![other_acceptance.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE c2_signer_enrollment_acceptances
                 SET foundational_adoption_identity = ?1
                 WHERE signer_enrollment_identity = ?2",
                params![other_adoption.as_str(), first_acceptance.as_str()],
            )
            .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(
            load_verified_durable_signer_enrollment_v1(&transaction, &first_acceptance).is_err(),
            "an acceptance cannot be relinked to a different adoption"
        );

        let (connection, acceptance, _) =
            one_durable_fixture(FoundationalAdoptionLineageV1::RecoveryNewFoundation, 73);
        connection
            .execute_batch(
                "DROP TRIGGER immutable_c2_signer_enrollment_acceptances_update;
                 PRAGMA ignore_check_constraints = ON;",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE c2_signer_enrollment_acceptances
                 SET signer_enrollment_canonical_bytes = x'7b7d',
                     signer_enrollment_canonical_sha256 = ?1
                 WHERE signer_enrollment_identity = ?2",
                params![sha256_bytes(b"{}").as_str(), acceptance.as_str()],
            )
            .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(
            load_verified_durable_signer_enrollment_v1(&transaction, &acceptance).is_err(),
            "changed acceptance content cannot retain its former identity"
        );
    }

    #[test]
    fn pre_generation_candidate_has_no_generation_or_lifecycle_root() {
        let coordinates = pre_generation_coordinates();
        let value = serde_json::to_value(&coordinates).unwrap();
        assert!(value.get("physical_generation").is_none());
        assert!(value.get("lifecycle_root").is_none());
        assert!(coordinates.verify().is_ok());
    }

    fn durable_acceptance() -> StoreIntegrityEnrollmentV2 {
        let body = acceptance_body(
            sha256_bytes(b"foundation"),
            sha256_bytes(b"candidate"),
            sha256_bytes(b"pop"),
            sha256_bytes(b"attempt"),
            5,
        );
        let enrollment_identity = semantic_digest(&body).unwrap();
        let wire = StoreIntegrityEnrollmentWireV2 {
            schema: body.schema,
            schema_version: body.schema_version,
            identity_domain: body.identity_domain,
            enrollment_identity,
            foundational_enrollment_identity: body.foundational_enrollment_identity,
            candidate_identity: body.candidate_identity,
            pop_identity: body.pop_identity,
            attempt_identity: body.attempt_identity,
            accepted_cut: body.accepted_cut,
        };
        StoreIntegrityEnrollmentV2 {
            canonical_bytes: canonical_json_bytes(&wire).unwrap(),
            wire,
        }
    }

    #[test]
    fn durable_acceptance_is_canonical_evidence_with_exact_schema_parity() {
        let enrollment = durable_acceptance();
        assert!(verify_store_integrity_enrollment_v2(&enrollment).is_ok());
        let decoded = decode_store_integrity_enrollment_v2(enrollment.canonical_bytes()).unwrap();
        assert_eq!(decoded, enrollment);
        let runtime = serde_json::to_value(&enrollment).unwrap();
        assert!(runtime.get("physical_store_generation_identity").is_none());
        assert!(runtime.get("foundational_enrollment_identity").is_some());

        let schema: Value = serde_json::from_str(include_str!(
            "../../../../../schemas/c2/nq.c2_store_integrity_enrollment.v2.json"
        ))
        .unwrap();
        let required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        let properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let runtime_fields = runtime
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(required, properties);
        assert_eq!(required, runtime_fields);

        let pretty = serde_json::to_vec_pretty(&runtime).unwrap();
        assert!(decode_store_integrity_enrollment_v2(&pretty).is_err());
    }

    #[test]
    fn durable_acceptance_tampering_refuses() {
        let mut enrollment = durable_acceptance();
        enrollment.wire.candidate_identity = sha256_bytes(b"other-candidate");
        assert!(verify_store_integrity_enrollment_v2(&enrollment).is_err());
    }

    #[test]
    fn durable_foundational_adoption_requires_the_exact_msg02_append() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let digest = |byte: char| format!("sha256:{}", byte.to_string().repeat(64));
        let foundation_identity = digest('0');
        let foundation_bytes = canonical_json_bytes(&serde_json::json!({
            "algorithm": "ed25519",
            "custody_evidence_identity": digest('b'),
            "foundation_identity": foundation_identity,
            "identity_domain": SIGNER_FOUNDATION_IDENTITY_DOMAIN_V1,
            "key_generation": 1,
            "public_key": hex::encode([12_u8; 32]),
            "schema": SIGNER_FOUNDATION_SCHEMA_V1,
            "schema_version": 1
        }))
        .unwrap();
        transaction
            .execute(
                "INSERT INTO c2_signer_foundations (
                    foundation_identity, foundation_canonical_bytes,
                    foundation_canonical_sha256, algorithm, public_key,
                    key_generation, custody_evidence_identity, committed_at
                 ) VALUES (?1, ?2, ?3, 'ed25519', ?4, 1, ?5, 'now')",
                params![
                    digest('0'),
                    foundation_bytes,
                    sha256_bytes(&foundation_bytes).as_str(),
                    &[12_u8; 32][..],
                    &[13_u8; 32][..],
                ],
            )
            .unwrap();
        let adoption_bytes = canonical_json_bytes(&serde_json::json!({
            "adoption_identity": digest('1'),
            "foundation_identity": digest('0'),
            "lineage": "initialExternal",
            "enrollment_cut": 4,
            "physical_generation_identity": null,
            "lifecycle_root_identity": null,
            "frontier_identity": null,
            "current_predecessor_identity": null,
            "transition_identity": null
        }))
        .unwrap();
        let result = transaction.execute(
            "INSERT INTO c2_foundational_enrollment_adoptions (
                adoption_sequence, adoption_identity,
                foundation_identity, adoption_canonical_bytes,
                adoption_canonical_sha256, lineage,
                foundational_enrollment_identity,
                foundational_enrollment_canonical_bytes,
                foundational_enrollment_canonical_sha256,
                msg02_message_identity, msg02_append_identity,
                msg02_effect_receipt_identity, grant_identity,
                candidate_identity, attempt_identity, custody_evidence_identity,
                pre_generation_scope_identity, pre_effect_store_snapshot_identity,
                process_identity, actor_instance_identity, actor_effect_epoch,
                enrollment_cut, effect_identity, receipt_identity, receipt_bytes,
                committed_at
             ) VALUES (1, ?1, ?2, ?3, ?4, 'initialExternal', ?5, x'7b7d',
                       ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                       ?16, ?17, 0, 4, ?18, ?19, x'7b7d', 'now')",
            params![
                digest('1'),
                digest('0'),
                adoption_bytes,
                sha256_bytes(&adoption_bytes).as_str(),
                digest('2'),
                sha256_bytes(b"{}").as_str(),
                &[4_u8; 32][..],
                digest('5'),
                digest('6'),
                &[7_u8; 32][..],
                &[8_u8; 32][..],
                &[9_u8; 32][..],
                &[10_u8; 32][..],
                &[11_u8; 32][..],
                digest('c'),
                digest('d'),
                digest('e'),
                digest('f'),
                digest('a'),
            ],
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("requires its exact consumed MSG-02 append"),
            "unexpected refusal: {error}"
        );
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM c2_foundational_enrollment_adoptions",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn durable_signer_acceptance_cannot_synthesize_foundational_adoption() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let digest = |byte: char| format!("sha256:{}", byte.to_string().repeat(64));
        let result = transaction.execute(
            "INSERT INTO c2_signer_enrollment_acceptances (
                acceptance_sequence, acceptance_effect_identity,
                signer_enrollment_identity, signer_enrollment_canonical_bytes,
                signer_enrollment_canonical_sha256,
                foundational_adoption_identity, pre_effect_store_snapshot_identity,
                process_identity, actor_instance_identity, actor_effect_epoch,
                accepted_cut, receipt_identity, receipt_bytes, committed_at
             ) VALUES (1, ?1, ?2, x'7b7d', ?3, ?4, ?5, ?6, ?7, 1, 5,
                       ?8, x'7b7d', 'now')",
            params![
                digest('1'),
                digest('2'),
                digest('3'),
                digest('4'),
                digest('5'),
                digest('6'),
                digest('7'),
                digest('8'),
            ],
        );
        assert!(result.is_err());
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM c2_signer_enrollment_acceptances",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }
}
