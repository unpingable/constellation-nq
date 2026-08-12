//! Purpose-locked Store-integrity signer custody.
//!
//! Production custody is rooted at one literal directory, resolves children
//! through retained descriptors, commits canonical private carriers with a
//! no-replace rename, and exposes signing only to the private typed
//! coordinator.  Filesystem possession is never converted into standing.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ed25519_dalek::{Signer as _, SigningKey};
use nix::fcntl::{Flock, FlockArg};
use nq_helper_sandbox::C2ForkFence;
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, RenameFlags, StatxFlags, fchmod, fdatasync, flistxattr, fsync,
    mkdirat, open, openat, renameat_with, statx,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::coordinator::CoordinatorSigningPermitV1;
use super::external_governance::{
    StoreIntegrityBootstrapGrantRequestV1, StoreIntegrityRecoveryRequestV1,
    construct_bootstrap_grant_request, construct_recovery_request,
};
use super::messages::{ClosedMessageFamilyV1, SignerIdentityV1, SignerMessageV1};
use super::records::{
    FoundationalAdoptionLineageV1, StoreIntegritySignerFoundationV1,
    VerifiedInitialPossessionRequestV1, verify_store_integrity_signer_foundation_v1,
};
use super::result::{ProposalResultV2, SignerRefusalV2};
use crate::store_generation::live_c2::{
    C2LiveSignerContextV1, C2LiveSigningScopeV1, C2LiveSigningViewV1, GenerationCurrentV1,
    StoreC2InitialPossessionAppendPermitV1, StoreC2SignerAppendPermitV1, StoreC2SnapshotActorV1,
};
use crate::store_generation::records::{StoreIntegrityKeyEnrollmentV1, verify_n_18_key_enrollment};

pub(crate) const STORE_INTEGRITY_CUSTODY_ROOT_V1: &str = "/var/lib/nq/store-integrity-custody.v1";
const STORE_INTEGRITY_CUSTODY_CHILD_V1: &str = "store-integrity-custody.v1";
const KEY_PROPOSAL_SCHEMA_V1: &str = "nq.c2_store_integrity_key_proposal.v1";
const PRIVATE_CUSTODY_SCHEMA_V1: &str = "nq.c2_store_integrity_private_key_custody.v1";
const PRIVATE_CUSTODY_MAGIC_V1: &str = "NQC2SIK1";
const KEY_ALGORITHM_V1: &str = "ed25519_store_integrity_v1";
const SCOPE_DOMAIN_V1: &[u8] = b"nq.c2.store_integrity_custody_scope.path.v1\0";
const PROPOSAL_CORE_DOMAIN_V1: &[u8] = b"nq.c2.store_integrity_key_proposal_core.identity.v1\0";
const PROPOSAL_ID_DOMAIN_V1: &[u8] = b"nq.c2.store_integrity_key_proposal.identity.v1\0";
const SCOPE_DIRECTORY_DOMAIN_V1: &[u8] = b"nq.c2.store_integrity_custody_scope.directory.v1\0";
const PRIVATE_PAYLOAD_DOMAIN_V1: &[u8] = b"nq.c2.store_integrity_private_key_custody.payload.v1\0";
const KEY_GENERATION_DOMAIN_V1: &[u8] = b"nq.c2.store_integrity_key_generation.identity.v1\0";
const ORDINARY_SUCCESSOR_CUSTODY_PREPARATION_SCHEMA_V1: &str =
    "nq.c2_store_integrity_ordinary_successor_custody_preparation.v1";
const ORDINARY_SUCCESSOR_CUSTODY_PREPARATION_ID_DOMAIN_V1: &[u8] =
    b"nq.c2.store_integrity_ordinary_successor_custody_preparation.identity.v1\0";
pub(in crate::store_generation) const C2_CUSTODY_EMPTY_FRONTIER_DOMAIN_V1: &[u8] =
    b"nq.c2.custody_proposal_frontier.empty.v1\0";
pub(in crate::store_generation) const C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1: &[u8] =
    b"nq.c2.custody_proposal_frontier.step.v1\0";
const IJSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[cfg(test)]
thread_local! {
    /// Test-only descriptor substitution for the literal production custody
    /// root.  The override is thread-local and descriptor based so an
    /// executable Store-root test exercises every production custody check
    /// below `open_production_custody_root` without sharing authority across
    /// parallel tests or requiring `/var/lib/nq` mutation.
    static TEST_PRODUCTION_CUSTODY_ROOT_V1: RefCell<Option<File>> = const {
        RefCell::new(None)
    };
}

/// Run one executable Store-root test against an exact retained custody-root
/// descriptor.  This seam does not exist in non-test builds and cannot alter
/// the production path constant.
#[cfg(test)]
pub(in crate::store_generation) fn with_test_production_custody_root_v1<R>(
    root: &Path,
    operation: impl FnOnce() -> R,
) -> R {
    let descriptor = File::open(root).expect("open exact test custody root");
    validate_directory(&descriptor, 0o700).expect("safe exact test custody root");

    struct ClearOverride;
    impl Drop for ClearOverride {
        fn drop(&mut self) {
            TEST_PRODUCTION_CUSTODY_ROOT_V1.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }

    TEST_PRODUCTION_CUSTODY_ROOT_V1.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "nested production-custody test override"
        );
        *slot.borrow_mut() = Some(descriptor);
    });
    let _clear = ClearOverride;
    operation()
}

/// Closed provenance of a custody preparation that created one stable
/// foundation. Restore is intentionally absent: it reopens the exact durable
/// preparation which originally created the historical foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::store_generation) enum StableFoundationCreationLineageV1 {
    InitialExternal,
    OrdinarySuccessorContinuity,
    RecoveryNewFoundation,
}

impl StableFoundationCreationLineageV1 {
    pub(in crate::store_generation) fn parse(value: &str) -> Result<Self, SignerRefusalV2> {
        match value {
            "initialExternal" => Ok(Self::InitialExternal),
            "ordinarySuccessorContinuity" => Ok(Self::OrdinarySuccessorContinuity),
            "recoveryNewFoundation" => Ok(Self::RecoveryNewFoundation),
            // A restore adoption is a new adoption event, not a custody/key
            // creation event. Accepting this tag here would permit a second
            // proposal row to masquerade as historical custody reuse.
            _ => Err(SignerRefusalV2::CustodyPathMismatch),
        }
    }

    #[must_use]
    pub(in crate::store_generation) const fn as_str(self) -> &'static str {
        match self {
            Self::InitialExternal => "initialExternal",
            Self::OrdinarySuccessorContinuity => "ordinarySuccessorContinuity",
            Self::RecoveryNewFoundation => "recoveryNewFoundation",
        }
    }
}

/// Verify the distinct custody-creation/adoption provenance join.
///
/// Bootstrap, healthy succession, and recovery must reopen a proposal created
/// by that exact creation path. Restore instead reuses the selected historical
/// stable foundation, so its preparation retains whichever legal creation
/// lineage originally minted that foundation. This check grants no authority;
/// it only prevents the Store reopener from requiring or accepting a fabricated
/// `restoreHistorical` custody-preparation row.
pub(in crate::store_generation) fn verify_stable_foundation_creation_lineage_for_adoption_v1(
    preparation_lineage: &str,
    adoption_lineage: FoundationalAdoptionLineageV1,
) -> Result<StableFoundationCreationLineageV1, SignerRefusalV2> {
    let creation = StableFoundationCreationLineageV1::parse(preparation_lineage)?;
    let matches = match adoption_lineage {
        FoundationalAdoptionLineageV1::InitialExternal => {
            creation == StableFoundationCreationLineageV1::InitialExternal
        }
        FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity => {
            creation == StableFoundationCreationLineageV1::OrdinarySuccessorContinuity
        }
        FoundationalAdoptionLineageV1::RestoreHistorical => true,
        FoundationalAdoptionLineageV1::RecoveryNewFoundation => {
            creation == StableFoundationCreationLineageV1::RecoveryNewFoundation
        }
    };
    if matches {
        Ok(creation)
    } else {
        Err(SignerRefusalV2::CustodyPathMismatch)
    }
}

/// Store-sealed inert basis for preparing a semantically new recovery key.
/// It is deliberately not recovery entry authority: exact MSG-15 and the
/// discontinuity/current-state join are still required after the asynchronous
/// external grant returns. The private fields prevent a generic lineage/tag
/// constructor from reaching custody creation.
pub(in crate::store_generation) struct StoreRecoveryCustodyPreparationBasisV1 {
    coordinates: PreGenerationCustodyCoordinatesV1,
    historical_foundation_identity: Sha256Digest,
    terminal_binding_identity: Sha256Digest,
    recovery_transition_identity: Sha256Digest,
    successor_pop_challenge_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

impl StoreRecoveryCustodyPreparationBasisV1 {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn from_store_actor_resolution(
        actor: &StoreC2SnapshotActorV1<'_>,
        coordinates: PreGenerationCustodyCoordinatesV1,
        historical_foundation_identity: Sha256Digest,
        terminal_binding_identity: Sha256Digest,
        recovery_transition_identity: Sha256Digest,
        successor_pop_challenge_identity: Sha256Digest,
    ) -> Result<Self, SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        coordinates.validate()?;
        if [
            &historical_foundation_identity,
            &terminal_binding_identity,
            &recovery_transition_identity,
            &successor_pop_challenge_identity,
        ]
        .into_iter()
        .any(|identity| identity.as_str().ends_with(&"0".repeat(64)))
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(Self {
            coordinates,
            historical_foundation_identity,
            terminal_binding_identity,
            recovery_transition_identity,
            successor_pop_challenge_identity,
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            creator_pid: std::process::id(),
        })
    }

    fn verify_for_actor(&self, actor: &StoreC2SnapshotActorV1<'_>) -> Result<(), SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        self.coordinates.validate()
    }

    #[must_use]
    pub(in crate::store_generation) fn historical_foundation_identity(&self) -> &Sha256Digest {
        &self.historical_foundation_identity
    }

    #[must_use]
    pub(in crate::store_generation) fn terminal_binding_identity(&self) -> &Sha256Digest {
        &self.terminal_binding_identity
    }

    #[must_use]
    pub(in crate::store_generation) fn recovery_transition_identity(&self) -> &Sha256Digest {
        &self.recovery_transition_identity
    }

    #[must_use]
    pub(in crate::store_generation) fn successor_pop_challenge_identity(&self) -> &Sha256Digest {
        &self.successor_pop_challenge_identity
    }
}

fn valid_resident_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

/// Complete non-secret pre-generation coordinates fixed before key creation.
///
/// Initial custody deliberately contains no physical Store generation or
/// signer-lifecycle root.  Those coordinates do not exist until the later
/// signer-acceptance/bootstrap transition and therefore cannot be smuggled
/// backward into foundational enrollment through a custody carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreGenerationCustodyCoordinatesV1 {
    pub(crate) occurrence_id: String,
    pub(crate) scope_identity: Sha256Digest,
    pub(crate) a2_chain_root_identity: Sha256Digest,
    pub(crate) trust_anchor_identity: Sha256Digest,
    pub(crate) resident_identity: String,
    pub(crate) resident_generation: u64,
    pub(crate) host_role: String,
    pub(crate) role_manifest_generation: u64,
    pub(crate) authority_domain: String,
    pub(crate) signer_scope_policy_identity: Sha256Digest,
    pub(crate) signer_scope_policy_version: u64,
    pub(crate) proposed_key_generation: u64,
    pub(crate) custodian_implementation_manifest_identity: Sha256Digest,
}

impl PreGenerationCustodyCoordinatesV1 {
    fn validate(&self) -> Result<(), SignerRefusalV2> {
        let token = |value: &str| {
            !value.is_empty()
                && value.len() <= 256
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@-".contains(&byte))
        };
        if !token(&self.occurrence_id)
            || !token(&self.host_role)
            || !token(&self.authority_domain)
            || !valid_resident_identity(&self.resident_identity)
            || self.resident_generation == 0
            || self.role_manifest_generation == 0
            || self.signer_scope_policy_version == 0
            || [
                self.resident_generation,
                self.role_manifest_generation,
                self.signer_scope_policy_version,
                self.proposed_key_generation,
            ]
            .into_iter()
            .any(|value| value > IJSON_SAFE_INTEGER)
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(())
    }

    pub(in crate::store_generation) fn scope_token(&self) -> Result<Sha256Digest, SignerRefusalV2> {
        self.validate()?;
        domain_digest(
            SCOPE_DOMAIN_V1,
            &ScopeTokenPreimage {
                occurrence_id: &self.occurrence_id,
                a2_chain_root_identity: &self.a2_chain_root_identity,
                trust_anchor_identity: &self.trust_anchor_identity,
                resident_identity: &self.resident_identity,
                resident_generation: self.resident_generation,
                host_role: &self.host_role,
                role_manifest_generation: self.role_manifest_generation,
                authority_domain: &self.authority_domain,
                signer_scope_policy_identity: &self.signer_scope_policy_identity,
                signer_scope_policy_version: self.signer_scope_policy_version,
            },
        )
    }

    pub(super) fn occurrence_identity(&self) -> SignerIdentityV1 {
        domain_digest_bytes(
            b"nq.c2.store_occurrence.identity.v1\0",
            self.occurrence_id.as_bytes(),
        )
    }

    pub(super) fn scope_bytes(&self) -> SignerIdentityV1 {
        digest_bytes(&self.scope_identity)
    }

    pub(super) fn policy_bytes(&self) -> SignerIdentityV1 {
        digest_bytes(&self.signer_scope_policy_identity)
    }
}

#[derive(Serialize)]
struct ScopeTokenPreimage<'a> {
    occurrence_id: &'a str,
    a2_chain_root_identity: &'a Sha256Digest,
    trust_anchor_identity: &'a Sha256Digest,
    resident_identity: &'a str,
    resident_generation: u64,
    host_role: &'a str,
    role_manifest_generation: u64,
    authority_domain: &'a str,
    signer_scope_policy_identity: &'a Sha256Digest,
    signer_scope_policy_version: u64,
}

#[derive(Serialize)]
struct ProposalCorePreimage<'a> {
    scope_token: &'a Sha256Digest,
    proposal_ordinal: u64,
    proposed_key_generation: u64,
    algorithm: &'static str,
    public_key: &'a str,
    custody_nonce: &'a str,
    key_carrier_schema: &'static str,
}

#[derive(Serialize)]
struct ProposalIdentityPreimage<'a> {
    proposal_core_identity: &'a Sha256Digest,
    scope_directory_identity: &'a Sha256Digest,
    custody_file_device: u64,
    custody_file_mount: u64,
    custody_file_inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: &'static str,
    link_count: u64,
}

#[derive(Serialize)]
struct ScopeDirectoryIdentityPreimage {
    device: u64,
    mount: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: &'static str,
}

/// Exact non-secret carrier fields shared by proposal and private custody.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CustodyPublicFieldsV1 {
    proposal_core_identity: Sha256Digest,
    proposal_identity: Sha256Digest,
    proposal_ordinal: u64,
    scope_token: Sha256Digest,
    occurrence_id: String,
    scope_identity: Sha256Digest,
    a2_chain_root_identity: Sha256Digest,
    trust_anchor_identity: Sha256Digest,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    signer_scope_policy_identity: Sha256Digest,
    signer_scope_policy_version: u64,
    proposed_key_generation: u64,
    algorithm: String,
    public_key: String,
    custody_nonce: String,
    scope_directory_identity: Sha256Digest,
    custody_file_device: u64,
    custody_file_mount: u64,
    custody_file_inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: String,
    link_count: u64,
}

/// Inert public key proposal.  It contains no secret and grants no standing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoreIntegrityKeyProposalCarrierV1 {
    schema: String,
    schema_version: u8,
    #[serde(flatten)]
    fields: CustodyPublicFieldsV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1);

impl StoreIntegrityKeyProposalV1 {
    fn fields(&self) -> &CustodyPublicFieldsV1 {
        &self.0.fields
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, SignerRefusalV2> {
        canonical_json_bytes(&self.0).map_err(|_| SignerRefusalV2::CustodyFileMalformed)
    }

    pub(crate) fn proposal_identity(&self) -> &Sha256Digest {
        &self.fields().proposal_identity
    }

    pub(crate) fn key_generation_identity(&self) -> SignerIdentityV1 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.fields().proposal_identity.as_str().as_bytes());
        bytes.extend_from_slice(&self.fields().proposed_key_generation.to_be_bytes());
        domain_digest_bytes(KEY_GENERATION_DOMAIN_V1, &bytes)
    }
}

/// Canonical inert Store request to prepare custody for one ordinary healthy
/// successor. This is proposal evidence, not MSG-06 continuity authority and
/// not signer standing. The exact current-predecessor authority remains a
/// separate process-local premise consumed later by the healthy transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OrdinarySuccessorCustodyPreparationCarrierV1 {
    schema: String,
    schema_version: u8,
    preparation_request_identity: Sha256Digest,
    occurrence_id: String,
    scope_identity: Sha256Digest,
    predecessor_binding_identity: Sha256Digest,
    predecessor_key_generation_identity: Sha256Digest,
    transition_identity: Sha256Digest,
    successor_proposal_identity: Sha256Digest,
    successor_pop_challenge_identity: Sha256Digest,
    successor_key_generation: u64,
    active_policy_identity: Sha256Digest,
    active_policy_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::store_generation) struct StoreOrdinarySuccessorCustodyPreparationRequestV1(
    OrdinarySuccessorCustodyPreparationCarrierV1,
);

impl StoreOrdinarySuccessorCustodyPreparationRequestV1 {
    fn identity_for(
        carrier: &OrdinarySuccessorCustodyPreparationCarrierV1,
    ) -> Result<Sha256Digest, SignerRefusalV2> {
        let mut body =
            serde_json::to_value(carrier).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        body.as_object_mut()
            .ok_or(SignerRefusalV2::CustodyFileMalformed)?
            .remove("preparation_request_identity");
        domain_digest(ORDINARY_SUCCESSOR_CUSTODY_PREPARATION_ID_DOMAIN_V1, &body)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn construct(
        occurrence_id: String,
        scope_identity: Sha256Digest,
        predecessor_binding_identity: Sha256Digest,
        predecessor_key_generation_identity: Sha256Digest,
        transition_identity: Sha256Digest,
        proposal: &StoreIntegrityKeyProposalV1,
        successor_pop_challenge_identity: Sha256Digest,
        active_policy_identity: Sha256Digest,
        active_policy_generation: u64,
    ) -> Result<Self, SignerRefusalV2> {
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(proposal)?;
        if !valid_resident_identity(&occurrence_id)
            || proposal.fields().scope_identity != scope_identity
            || proposal.fields().proposed_key_generation == 0
            || active_policy_generation == 0
            || active_policy_generation > IJSON_SAFE_INTEGER
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        let mut carrier = OrdinarySuccessorCustodyPreparationCarrierV1 {
            schema: ORDINARY_SUCCESSOR_CUSTODY_PREPARATION_SCHEMA_V1.to_owned(),
            schema_version: 1,
            preparation_request_identity: sha256_bytes(b"uninitialized"),
            occurrence_id,
            scope_identity,
            predecessor_binding_identity,
            predecessor_key_generation_identity,
            transition_identity,
            successor_proposal_identity: proposal.proposal_identity().clone(),
            successor_pop_challenge_identity,
            successor_key_generation: proposal.fields().proposed_key_generation,
            active_policy_identity,
            active_policy_generation,
        };
        carrier.preparation_request_identity = Self::identity_for(&carrier)?;
        let request = Self(carrier);
        request.verify()?;
        Ok(request)
    }

    pub(in crate::store_generation) fn decode(bytes: &[u8]) -> Result<Self, SignerRefusalV2> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        if canonical_json_bytes(&value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)? != bytes
        {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let request =
            Self(serde_json::from_value(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?);
        request.verify()?;
        Ok(request)
    }

    fn verify(&self) -> Result<(), SignerRefusalV2> {
        let fields = &self.0;
        if fields.schema != ORDINARY_SUCCESSOR_CUSTODY_PREPARATION_SCHEMA_V1
            || fields.schema_version != 1
            || !valid_resident_identity(&fields.occurrence_id)
            || fields.successor_key_generation == 0
            || fields.successor_key_generation > IJSON_SAFE_INTEGER
            || fields.active_policy_generation == 0
            || fields.active_policy_generation > IJSON_SAFE_INTEGER
            || Self::identity_for(fields)? != fields.preparation_request_identity
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub(in crate::store_generation) fn identity(&self) -> &Sha256Digest {
        &self.0.preparation_request_identity
    }

    #[must_use]
    pub(in crate::store_generation) fn proposal_identity(&self) -> &Sha256Digest {
        &self.0.successor_proposal_identity
    }

    pub(in crate::store_generation) fn canonical_bytes(&self) -> Result<Vec<u8>, SignerRefusalV2> {
        self.verify()?;
        canonical_json_bytes(&self.0).map_err(|_| SignerRefusalV2::CustodyFileMalformed)
    }
}

/// Exact canonical private key carrier.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoreIntegrityCustodyCarrierV1 {
    schema: String,
    schema_version: u8,
    #[serde(flatten)]
    fields: CustodyPublicFieldsV1,
    magic: String,
    private_seed: String,
    custodian_implementation_manifest_identity: Sha256Digest,
    payload_digest: Sha256Digest,
}

/// Secret carrier value.  Seed text is cleared when this value is dropped.
#[derive(Eq, PartialEq)]
pub(crate) struct StoreIntegrityCustodyFileV1(StoreIntegrityCustodyCarrierV1);

impl std::fmt::Debug for StoreIntegrityCustodyFileV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreIntegrityCustodyFileV1")
            .field("proposal_identity", &self.0.fields.proposal_identity)
            .field("scope_token", &self.0.fields.scope_token)
            .field("custody_file_inode", &self.0.fields.custody_file_inode)
            .field("private_seed", &"<redacted>")
            .finish()
    }
}

impl Drop for StoreIntegrityCustodyFileV1 {
    fn drop(&mut self) {
        let zeroes = "0".repeat(self.0.private_seed.len());
        self.0.private_seed.replace_range(.., &zeroes);
        self.0.private_seed.clear();
    }
}

impl StoreIntegrityCustodyFileV1 {
    fn payload_digest(
        carrier: &StoreIntegrityCustodyCarrierV1,
    ) -> Result<Sha256Digest, SignerRefusalV2> {
        let mut value =
            serde_json::to_value(carrier).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        let object = value
            .as_object_mut()
            .ok_or(SignerRefusalV2::CustodyFileMalformed)?;
        object.remove("payload_digest");
        domain_digest(PRIVATE_PAYLOAD_DOMAIN_V1, &value)
    }

    fn encode(&self) -> Result<Vec<u8>, SignerRefusalV2> {
        if Self::payload_digest(&self.0)? != self.0.payload_digest {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        canonical_json_bytes(&self.0).map_err(|_| SignerRefusalV2::CustodyFileMalformed)
    }

    fn decode(bytes: &[u8]) -> Result<Self, SignerRefusalV2> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        let keys = value
            .as_object()
            .ok_or(SignerRefusalV2::CustodyFileMalformed)?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = private_carrier_keys().into_iter().collect::<BTreeSet<_>>();
        if keys != expected || canonical_json_bytes(&value).ok().as_deref() != Some(bytes) {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let carrier: StoreIntegrityCustodyCarrierV1 =
            serde_json::from_value(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        if carrier.schema != PRIVATE_CUSTODY_SCHEMA_V1
            || carrier.schema_version != 1
            || carrier.magic != PRIVATE_CUSTODY_MAGIC_V1
            || carrier.fields.algorithm != KEY_ALGORITHM_V1
            || carrier.fields.mode != "0400"
            || carrier.fields.link_count != 1
            || carrier.private_seed.len() != 64
            || carrier.fields.public_key.len() != 64
            || carrier.fields.custody_nonce.len() != 64
            || Self::payload_digest(&carrier)? != carrier.payload_digest
        {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let proposal = StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1 {
            schema: KEY_PROPOSAL_SCHEMA_V1.to_owned(),
            schema_version: 1,
            fields: carrier.fields.clone(),
        });
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
        let seed = decode_hex_32(&carrier.private_seed)?;
        if hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
            != carrier.fields.public_key
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        Ok(Self(carrier))
    }

    fn secret_seed(&self) -> Result<SecretSeedV1, SignerRefusalV2> {
        decode_hex_32(&self.0.private_seed).map(SecretSeedV1)
    }
}

fn private_carrier_keys() -> [&'static str; 33] {
    [
        "schema",
        "schema_version",
        "proposal_core_identity",
        "proposal_identity",
        "proposal_ordinal",
        "scope_token",
        "occurrence_id",
        "scope_identity",
        "a2_chain_root_identity",
        "trust_anchor_identity",
        "resident_identity",
        "resident_generation",
        "host_role",
        "role_manifest_generation",
        "authority_domain",
        "signer_scope_policy_identity",
        "signer_scope_policy_version",
        "proposed_key_generation",
        "algorithm",
        "public_key",
        "custody_nonce",
        "scope_directory_identity",
        "custody_file_device",
        "custody_file_mount",
        "custody_file_inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "link_count",
        "magic",
        "private_seed",
        "custodian_implementation_manifest_identity",
        "payload_digest",
    ]
}

struct SecretSeedV1([u8; 32]);

impl Drop for SecretSeedV1 {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Secret random temporary.  Bytes are cleared when this value is dropped.
struct SecretBytes32([u8; 32]);

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Secret byte buffer.  Bytes are cleared when this value is dropped.
struct SecretBytes(Vec<u8>);

impl std::ops::Deref for SecretBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Exact filesystem observations.  These facts grant no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CustodyObservationV1 {
    pub(crate) effective_uid: u32,
    pub(crate) effective_gid: u32,
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
    pub(crate) mode: u32,
    pub(crate) device: u64,
    pub(crate) mount: u64,
    pub(crate) inode: u64,
    pub(crate) link_count: u64,
    pub(crate) regular_file: bool,
    pub(crate) exact_length: bool,
    pub(crate) path_inode_matches: bool,
    pub(crate) key_correspondence: bool,
}

/// Exact canonical request bytes which accompanied one custody proposal in
/// the durable frontier. The variants are nominal so a query/replay caller
/// cannot select a free-form lineage tag or identity field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::store_generation) enum StoreCustodyPreparationReferenceV1 {
    InitialExternal(StoreIntegrityBootstrapGrantRequestV1),
    OrdinarySuccessor(StoreOrdinarySuccessorCustodyPreparationRequestV1),
    RecoveryNewFoundation(StoreIntegrityRecoveryRequestV1),
}

impl StoreCustodyPreparationReferenceV1 {
    pub(in crate::store_generation) fn decode_initial_external(
        canonical_bytes: &[u8],
    ) -> Result<Self, SignerRefusalV2> {
        let value = decode_canonical_json_v1(canonical_bytes)?;
        construct_bootstrap_grant_request(value).map(Self::InitialExternal)
    }

    pub(in crate::store_generation) fn decode_ordinary_successor(
        canonical_bytes: &[u8],
    ) -> Result<Self, SignerRefusalV2> {
        StoreOrdinarySuccessorCustodyPreparationRequestV1::decode(canonical_bytes)
            .map(Self::OrdinarySuccessor)
    }

    pub(in crate::store_generation) fn decode_recovery_new_foundation(
        canonical_bytes: &[u8],
    ) -> Result<Self, SignerRefusalV2> {
        let value = decode_canonical_json_v1(canonical_bytes)?;
        construct_recovery_request(value).map(Self::RecoveryNewFoundation)
    }

    #[must_use]
    pub(in crate::store_generation) const fn creation_lineage(
        &self,
    ) -> StableFoundationCreationLineageV1 {
        match self {
            Self::InitialExternal(_) => StableFoundationCreationLineageV1::InitialExternal,
            Self::OrdinarySuccessor(_) => {
                StableFoundationCreationLineageV1::OrdinarySuccessorContinuity
            }
            Self::RecoveryNewFoundation(_) => {
                StableFoundationCreationLineageV1::RecoveryNewFoundation
            }
        }
    }

    fn identity(&self) -> Result<Sha256Digest, SignerRefusalV2> {
        match self {
            Self::InitialExternal(request) => {
                digest_from_identity_bytes(*request.identity().bytes())
            }
            Self::OrdinarySuccessor(request) => Ok(request.identity().clone()),
            Self::RecoveryNewFoundation(request) => {
                digest_from_identity_bytes(*request.identity().bytes())
            }
        }
    }

    fn proposal_identity(&self) -> Result<Sha256Digest, SignerRefusalV2> {
        match self {
            Self::InitialExternal(request) => digest_field_v1(request.field("proposal_identity")),
            Self::OrdinarySuccessor(request) => Ok(request.proposal_identity().clone()),
            Self::RecoveryNewFoundation(request) => {
                digest_field_v1(request.field("successor_proposal_identity"))
            }
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, SignerRefusalV2> {
        match self {
            Self::InitialExternal(request) => Ok(request.canonical_bytes().to_vec()),
            Self::OrdinarySuccessor(request) => request.canonical_bytes(),
            Self::RecoveryNewFoundation(request) => Ok(request.canonical_bytes().to_vec()),
        }
    }
}

/// One immutable SQL row projected into a route-typed value before frontier
/// recomputation. This is evidence only. Its constructors are route-specific
/// and no constructor accepts a caller-selected lineage string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::store_generation) struct StoreCustodyProposalFrontierRowV1 {
    proposal_ordinal: u64,
    predecessor_frontier_identity: Sha256Digest,
    resulting_frontier_identity: Sha256Digest,
    proposal_identity: Sha256Digest,
    proposal_canonical_bytes: Vec<u8>,
    proposal_canonical_sha256: Sha256Digest,
    proposal_canonical_length: u64,
    reference: StoreCustodyPreparationReferenceV1,
    reference_canonical_sha256: Sha256Digest,
    reference_canonical_length: u64,
}

impl StoreCustodyProposalFrontierRowV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        proposal_ordinal: u64,
        predecessor_frontier_identity: Sha256Digest,
        resulting_frontier_identity: Sha256Digest,
        proposal_identity: Sha256Digest,
        proposal_canonical_bytes: Vec<u8>,
        proposal_canonical_sha256: Sha256Digest,
        proposal_canonical_length: u64,
        reference: StoreCustodyPreparationReferenceV1,
        reference_canonical_sha256: Sha256Digest,
        reference_canonical_length: u64,
    ) -> Result<Self, SignerRefusalV2> {
        let row = Self {
            proposal_ordinal,
            predecessor_frontier_identity,
            resulting_frontier_identity,
            proposal_identity,
            proposal_canonical_bytes,
            proposal_canonical_sha256,
            proposal_canonical_length,
            reference,
            reference_canonical_sha256,
            reference_canonical_length,
        };
        row.verify_static()?;
        Ok(row)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn initial_external(
        proposal_ordinal: u64,
        predecessor_frontier_identity: Sha256Digest,
        resulting_frontier_identity: Sha256Digest,
        proposal_identity: Sha256Digest,
        proposal_canonical_bytes: Vec<u8>,
        proposal_canonical_sha256: Sha256Digest,
        proposal_canonical_length: u64,
        request: StoreIntegrityBootstrapGrantRequestV1,
        request_canonical_sha256: Sha256Digest,
        request_canonical_length: u64,
    ) -> Result<Self, SignerRefusalV2> {
        Self::new(
            proposal_ordinal,
            predecessor_frontier_identity,
            resulting_frontier_identity,
            proposal_identity,
            proposal_canonical_bytes,
            proposal_canonical_sha256,
            proposal_canonical_length,
            StoreCustodyPreparationReferenceV1::InitialExternal(request),
            request_canonical_sha256,
            request_canonical_length,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn ordinary_successor(
        proposal_ordinal: u64,
        predecessor_frontier_identity: Sha256Digest,
        resulting_frontier_identity: Sha256Digest,
        proposal_identity: Sha256Digest,
        proposal_canonical_bytes: Vec<u8>,
        proposal_canonical_sha256: Sha256Digest,
        proposal_canonical_length: u64,
        request: StoreOrdinarySuccessorCustodyPreparationRequestV1,
        request_canonical_sha256: Sha256Digest,
        request_canonical_length: u64,
    ) -> Result<Self, SignerRefusalV2> {
        Self::new(
            proposal_ordinal,
            predecessor_frontier_identity,
            resulting_frontier_identity,
            proposal_identity,
            proposal_canonical_bytes,
            proposal_canonical_sha256,
            proposal_canonical_length,
            StoreCustodyPreparationReferenceV1::OrdinarySuccessor(request),
            request_canonical_sha256,
            request_canonical_length,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn recovery_new_foundation(
        proposal_ordinal: u64,
        predecessor_frontier_identity: Sha256Digest,
        resulting_frontier_identity: Sha256Digest,
        proposal_identity: Sha256Digest,
        proposal_canonical_bytes: Vec<u8>,
        proposal_canonical_sha256: Sha256Digest,
        proposal_canonical_length: u64,
        request: StoreIntegrityRecoveryRequestV1,
        request_canonical_sha256: Sha256Digest,
        request_canonical_length: u64,
    ) -> Result<Self, SignerRefusalV2> {
        Self::new(
            proposal_ordinal,
            predecessor_frontier_identity,
            resulting_frontier_identity,
            proposal_identity,
            proposal_canonical_bytes,
            proposal_canonical_sha256,
            proposal_canonical_length,
            StoreCustodyPreparationReferenceV1::RecoveryNewFoundation(request),
            request_canonical_sha256,
            request_canonical_length,
        )
    }

    fn verify_static(&self) -> Result<(), SignerRefusalV2> {
        let proposal = decode_canonical_proposal_v1(&self.proposal_canonical_bytes)?;
        let reference_bytes = self.reference.canonical_bytes()?;
        if self.proposal_ordinal == 0
            || self.proposal_ordinal > IJSON_SAFE_INTEGER
            || proposal.fields().proposal_ordinal != self.proposal_ordinal
            || proposal.proposal_identity() != &self.proposal_identity
            || self.reference.proposal_identity()? != self.proposal_identity
            || self.proposal_canonical_sha256 != sha256_bytes(&self.proposal_canonical_bytes)
            || self.proposal_canonical_length != self.proposal_canonical_bytes.len() as u64
            || self.reference_canonical_sha256 != sha256_bytes(&reference_bytes)
            || self.reference_canonical_length != reference_bytes.len() as u64
        {
            return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
        }
        Ok(())
    }
}

/// Recompute the complete durable custody frontier across bootstrap, healthy
/// successor, and recovery creation rows. Restore contributes no row because
/// it reuses one already present proposal. Exact route parsing occurs before
/// this function, and every adjacent step binds the canonical request bytes.
pub(in crate::store_generation) fn resolve_store_custody_proposal_frontier_rows_v1(
    scope_token: &Sha256Digest,
    rows: impl IntoIterator<Item = StoreCustodyProposalFrontierRowV1>,
) -> Result<(u64, Sha256Digest, BTreeMap<u64, Sha256Digest>), SignerRefusalV2> {
    let mut frontier = digest_fields_v1(
        C2_CUSTODY_EMPTY_FRONTIER_DOMAIN_V1,
        &[scope_token.as_str().as_bytes()],
    );
    let mut expected_ordinal = 1_u64;
    let mut committed = BTreeMap::new();
    for row in rows {
        row.verify_static()?;
        let reference_identity = row.reference.identity()?;
        let reference_bytes = row.reference.canonical_bytes()?;
        let expected_resulting = digest_fields_v1(
            C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1,
            &[
                frontier.as_str().as_bytes(),
                &row.proposal_ordinal.to_be_bytes(),
                row.proposal_identity.as_str().as_bytes(),
                reference_identity.as_str().as_bytes(),
                row.proposal_canonical_sha256.as_str().as_bytes(),
                sha256_bytes(&reference_bytes).as_str().as_bytes(),
            ],
        );
        let proposal = decode_canonical_proposal_v1(&row.proposal_canonical_bytes)?;
        if row.proposal_ordinal != expected_ordinal
            || row.predecessor_frontier_identity != frontier
            || row.resulting_frontier_identity != expected_resulting
            || proposal.fields().scope_token != *scope_token
            || committed
                .insert(row.proposal_ordinal, row.proposal_identity.clone())
                .is_some()
        {
            return Err(SignerRefusalV2::EnrollmentEvidenceCollision);
        }
        frontier = expected_resulting;
        expected_ordinal = expected_ordinal
            .checked_add(1)
            .filter(|ordinal| *ordinal <= IJSON_SAFE_INTEGER)
            .ok_or(SignerRefusalV2::CustodyPathMismatch)?;
    }
    Ok((expected_ordinal, frontier, committed))
}

/// Internal signature returned only to the private transition coordinator.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CustodySignatureV1 {
    pub(super) family: ClosedMessageFamilyV1,
    pub(super) signer_key_generation: SignerIdentityV1,
    pub(super) payload_digest: SignerIdentityV1,
    pub(super) signature: [u8; 64],
}

impl Drop for CustodySignatureV1 {
    fn drop(&mut self) {
        self.signature.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CustodyObjectFactsV1 {
    device: u64,
    mount: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    link_count: u64,
    regular_file: bool,
    length: u64,
}

/// Proof that the proposal/disposition and Store frontier was fully resolved.
/// Construction will move to the Store actor when durable ingress is wired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedCustodyProposalFrontierV1 {
    scope_token: Sha256Digest,
    next_ordinal: u64,
    complete_frontier_identity: Sha256Digest,
    committed_proposals: BTreeMap<u64, Sha256Digest>,
}

impl VerifiedCustodyProposalFrontierV1 {
    /// Seal only a frontier that the retained Store actor has already
    /// enumerated and whose complete identity it has recomputed from durable
    /// rows.  Raw ordinals never call custody creation directly.
    pub(in crate::store_generation) fn from_store_actor_resolution(
        actor: &StoreC2SnapshotActorV1<'_>,
        scope_token: Sha256Digest,
        next_ordinal: u64,
        complete_frontier_identity: Sha256Digest,
        committed_proposals: BTreeMap<u64, Sha256Digest>,
    ) -> Result<Self, SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        let frontier = Self {
            scope_token: scope_token.clone(),
            next_ordinal,
            complete_frontier_identity,
            committed_proposals,
        };
        frontier.verify_for(&scope_token)?;
        Ok(frontier)
    }

    #[cfg(test)]
    fn initial_for_test(scope_token: Sha256Digest) -> Self {
        Self {
            scope_token,
            next_ordinal: 1,
            complete_frontier_identity: sha256_bytes(b"test-only-empty-custody-frontier"),
            committed_proposals: BTreeMap::new(),
        }
    }

    fn verify_for(&self, scope_token: &Sha256Digest) -> Result<u64, SignerRefusalV2> {
        if &self.scope_token != scope_token
            || self.next_ordinal == 0
            || self.next_ordinal > IJSON_SAFE_INTEGER
            || self
                .complete_frontier_identity
                .as_str()
                .ends_with(&"0".repeat(64))
            || self.committed_proposals.len()
                != usize::try_from(self.next_ordinal.saturating_sub(1))
                    .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?
            || self
                .committed_proposals
                .keys()
                .copied()
                .ne(1..self.next_ordinal)
            || self
                .committed_proposals
                .values()
                .collect::<BTreeSet<_>>()
                .len()
                != self.committed_proposals.len()
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(self.next_ordinal)
    }

    fn verify_directory(
        &self,
        directory: &File,
        coordinates: &PreGenerationCustodyCoordinatesV1,
    ) -> Result<(), SignerRefusalV2> {
        let observed = scope_directory_committed_proposal_identities(directory)?;
        let expected = self
            .committed_proposals
            .values()
            .cloned()
            .collect::<BTreeSet<_>>();
        if observed != expected {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        for (ordinal, identity) in &self.committed_proposals {
            verify_committed_carrier_for_frontier(
                directory,
                &self.scope_token,
                *ordinal,
                identity,
                &coordinates.custodian_implementation_manifest_identity,
            )?;
        }
        Ok(())
    }
}

/// Store-sealed inert proposal evidence reloaded from the exact durable
/// preparation row.  It grants no signing or standing; custody still reopens
/// and authenticates the fixed descriptor/carrier in the current process.
pub(crate) struct StoreVerifiedPreparedCustodyV1 {
    coordinates: PreGenerationCustodyCoordinatesV1,
    proposal: StoreIntegrityKeyProposalV1,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

/// Exact stable foundation coordinates extracted only from the canonical
/// foundation record.  This private value is the route-neutral join between
/// durable signer-foundation evidence and custody; no raw-parts constructor
/// exists.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StableFoundationCustodyCoordinatesV1 {
    foundation_identity: Sha256Digest,
    public_key: [u8; 32],
    key_generation: u64,
    custody_evidence_identity: Sha256Digest,
}

impl StableFoundationCustodyCoordinatesV1 {
    fn from_foundation(
        foundation: &StoreIntegritySignerFoundationV1,
    ) -> Result<Self, SignerRefusalV2> {
        verify_store_integrity_signer_foundation_v1(foundation)?;
        Ok(Self {
            foundation_identity: foundation.identity().clone(),
            public_key: foundation.public_key()?,
            key_generation: foundation.key_generation(),
            custody_evidence_identity: foundation.custody_evidence_identity().clone(),
        })
    }

    fn verify_proposal(
        &self,
        proposal: &StoreIntegrityKeyProposalV1,
    ) -> Result<(), SignerRefusalV2> {
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(proposal)?;
        if decode_hex_32(&proposal.fields().public_key)? != self.public_key
            || proposal.fields().proposed_key_generation != self.key_generation
            || proposal.proposal_identity() != &self.custody_evidence_identity
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        Ok(())
    }
}

impl StoreVerifiedPreparedCustodyV1 {
    /// Reconstruct the exact non-secret custody coordinates from one
    /// canonical proposal selected by the Store and bind them to the freshly
    /// admitted implementation manifest.  Callers cannot supply individual
    /// coordinates; changing any proposal field changes or invalidates the
    /// canonical proposal identity before this seal is minted.
    pub(in crate::store_generation) fn from_store_selected_canonical_proposal(
        actor: &StoreC2SnapshotActorV1<'_>,
        canonical_proposal_bytes: &[u8],
        implementation_manifest_identity: Sha256Digest,
    ) -> Result<Self, SignerRefusalV2> {
        let value: serde_json::Value = serde_json::from_slice(canonical_proposal_bytes)
            .map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        if canonical_json_bytes(&value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?
            != canonical_proposal_bytes
        {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let carrier: StoreIntegrityKeyProposalCarrierV1 =
            serde_json::from_value(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        let fields = &carrier.fields;
        let coordinates = PreGenerationCustodyCoordinatesV1 {
            occurrence_id: fields.occurrence_id.clone(),
            scope_identity: fields.scope_identity.clone(),
            a2_chain_root_identity: fields.a2_chain_root_identity.clone(),
            trust_anchor_identity: fields.trust_anchor_identity.clone(),
            resident_identity: fields.resident_identity.clone(),
            resident_generation: fields.resident_generation,
            host_role: fields.host_role.clone(),
            role_manifest_generation: fields.role_manifest_generation,
            authority_domain: fields.authority_domain.clone(),
            signer_scope_policy_identity: fields.signer_scope_policy_identity.clone(),
            signer_scope_policy_version: fields.signer_scope_policy_version,
            proposed_key_generation: fields.proposed_key_generation,
            custodian_implementation_manifest_identity: implementation_manifest_identity,
        };
        Self::from_store_actor(actor, coordinates, canonical_proposal_bytes)
    }

    pub(in crate::store_generation) fn from_store_actor(
        actor: &StoreC2SnapshotActorV1<'_>,
        coordinates: PreGenerationCustodyCoordinatesV1,
        canonical_proposal_bytes: &[u8],
    ) -> Result<Self, SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        coordinates.validate()?;
        let value: serde_json::Value = serde_json::from_slice(canonical_proposal_bytes)
            .map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        if canonical_json_bytes(&value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?
            != canonical_proposal_bytes
        {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let carrier: StoreIntegrityKeyProposalCarrierV1 =
            serde_json::from_value(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        let proposal = StoreIntegrityKeyProposalV1(carrier);
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
        if proposal.fields().scope_token != coordinates.scope_token()?
            || !proposal_fields_match_coordinates(proposal.fields(), &coordinates)
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(Self {
            coordinates,
            proposal,
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            creator_pid: std::process::id(),
        })
    }

    fn verify_for_actor(&self, actor: &StoreC2SnapshotActorV1<'_>) -> Result<(), SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(())
    }

    /// Derive the next recovery key's pre-generation coordinates from the
    /// exact Store-selected current foundation preparation.  Only the key
    /// generation and freshly admitted implementation basis change; callers
    /// cannot supply or splice scope/custody coordinates individually.
    pub(in crate::store_generation) fn recovery_successor_coordinates_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        proposed_key_generation: u64,
        implementation_manifest_identity: Sha256Digest,
    ) -> Result<PreGenerationCustodyCoordinatesV1, SignerRefusalV2> {
        self.verify_for_actor(actor)?;
        if proposed_key_generation <= self.coordinates.proposed_key_generation
            || implementation_manifest_identity
                .as_str()
                .ends_with(&"0".repeat(64))
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        let mut coordinates = self.coordinates.clone();
        coordinates.proposed_key_generation = proposed_key_generation;
        coordinates.custodian_implementation_manifest_identity =
            implementation_manifest_identity;
        coordinates.validate()?;
        Ok(coordinates)
    }
}

/// Purpose-locked private owner of one Store-integrity key generation.
pub(crate) struct C2StoreIntegrityCustodian {
    coordinates: PreGenerationCustodyCoordinatesV1,
    proposal: StoreIntegrityKeyProposalV1,
    scope_directory: File,
    final_name: String,
    creator_pid: u32,
    process_epoch: SignerIdentityV1,
}

/// Process-local proof that one exact proposal is backed by the retained,
/// authenticated custody descriptor and its corresponding private key.
///
/// This proof is custody-owned.  It has no raw-digest constructor and cannot
/// be cloned, copied, serialized, or defaulted.  The custody-evidence identity
/// is deliberately the proposal identity: that proposal identity already
/// commits the scope directory, device/mount/inode, ownership/mode/link count,
/// public key, nonce, generation, and exact proposal core.  A second digest
/// over the same facts would create an unnecessary parallel taxonomy.
pub(crate) struct VerifiedFoundationalCustodyV1<'process> {
    custodian: &'process C2StoreIntegrityCustodian,
    proposal: &'process StoreIntegrityKeyProposalV1,
    public_key: [u8; 32],
    creator_pid: u32,
}

/// Fresh process-local custody verified against one exact canonical stable
/// signer foundation.  This wrapper carries no standing and cannot be built
/// from public-key/generation/digest coordinates supplied separately.
pub(crate) struct StoreVerifiedGenerationCurrentCustodyV1<'process> {
    foundational: VerifiedFoundationalCustodyV1<'process>,
    stable: StableFoundationCustodyCoordinatesV1,
}

/// Owner returned by the route-neutral durable-preparation reopen seam.
/// Borrowing a verified current-custody proof from it reauthenticates the
/// retained descriptor in the current process; the proof cannot outlive this
/// owner.
pub(crate) struct StoreReopenedGenerationCurrentCustodianV1 {
    custodian: C2StoreIntegrityCustodian,
    stable: StableFoundationCustodyCoordinatesV1,
}

/// Borrowed generation-bound view of one pre-generation custody object.
///
/// Final generation and lifecycle-root coordinates come exclusively from the
/// sealed Store live phase, never from the durable custody carrier.  The view
/// cannot outlive either premise and has no raw-parts constructor.
pub(crate) struct GenerationBoundC2CustodyV1<'live, 'context, 'store, Phase> {
    custodian: &'live C2StoreIntegrityCustodian,
    live: C2LiveSigningViewV1<'live, 'context, 'store, Phase>,
    physical_generation: SignerIdentityV1,
    lifecycle_root: SignerIdentityV1,
}

impl<'live, 'context, 'store, Phase> GenerationBoundC2CustodyV1<'live, 'context, 'store, Phase> {
    pub(crate) fn from_live_context(
        custodian: &'live C2StoreIntegrityCustodian,
        context: &'live C2LiveSignerContextV1<'context, 'store, Phase>,
        permit: &StoreC2SignerAppendPermitV1<'_, '_, '_, Phase>,
    ) -> Result<Self, SignerRefusalV2> {
        let live = context.signing_view();
        permit
            .verify_live_view(&live)
            .map_err(|_| SignerRefusalV2::MessageFrontierMismatch)?;
        let physical_generation = live
            .physical_generation_identity()
            .ok_or(SignerRefusalV2::MessageFrontierMismatch)?;
        let lifecycle_root = live
            .lifecycle_root_identity()
            .ok_or(SignerRefusalV2::MessageFrontierMismatch)?;
        if live.scope_class() != C2LiveSigningScopeV1::GenerationBound
            || live.occurrence_identity() != custodian.coordinates.occurrence_identity()
            || live.signer_scope_identity() != custodian.coordinates.scope_bytes()
            || live.signer_scope_policy_identity() != custodian.coordinates.policy_bytes()
            || live.signer_key_generation_identity() != custodian.key_generation_identity()
            || live.signer_public_key() != custodian.verifying_key()?
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(Self {
            custodian,
            live,
            physical_generation,
            lifecycle_root,
        })
    }

    #[must_use]
    pub(crate) fn occurrence_identity(&self) -> SignerIdentityV1 {
        self.live.occurrence_identity()
    }

    #[must_use]
    pub(crate) fn physical_generation_identity(&self) -> SignerIdentityV1 {
        self.physical_generation
    }

    #[must_use]
    pub(crate) fn lifecycle_root_identity(&self) -> SignerIdentityV1 {
        self.lifecycle_root
    }

    #[must_use]
    pub(crate) fn scope_identity(&self) -> SignerIdentityV1 {
        self.live.signer_scope_identity()
    }

    #[must_use]
    pub(crate) fn policy_identity(&self) -> SignerIdentityV1 {
        self.live.signer_scope_policy_identity()
    }

    #[must_use]
    pub(crate) fn key_generation_identity(&self) -> SignerIdentityV1 {
        self.live.signer_key_generation_identity()
    }

    pub(super) fn sign<M: SignerMessageV1>(
        &self,
        permit: CoordinatorSigningPermitV1,
        live_permit: &StoreC2SignerAppendPermitV1<'_, '_, '_, Phase>,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        self.custodian
            .sign(permit, live_permit, &self.live, message)
    }
}

impl<'process> VerifiedFoundationalCustodyV1<'process> {
    /// Borrow the exact retained custodian behind this sealed proof.  This is
    /// crate-private and one-way: a custodian cannot construct the proof, and
    /// the live Store driver uses it only to prevent a separately supplied
    /// key object from being substituted at signing time.
    pub(crate) const fn retained_custodian(&self) -> &'process C2StoreIntegrityCustodian {
        self.custodian
    }

    #[must_use]
    pub(crate) fn proposal_identity(&self) -> &Sha256Digest {
        self.proposal.proposal_identity()
    }

    #[must_use]
    pub(crate) fn custody_evidence_identity(&self) -> &Sha256Digest {
        self.proposal.proposal_identity()
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    #[must_use]
    pub(crate) fn key_generation(&self) -> u64 {
        self.proposal.fields().proposed_key_generation
    }

    /// Exact proposal-derived key-generation identity.  This is inert
    /// evidence; it has no conversion into custody or live signer standing.
    #[must_use]
    pub(crate) fn key_generation_identity(&self) -> SignerIdentityV1 {
        self.proposal.key_generation_identity()
    }

    #[must_use]
    pub(crate) fn scope_identity(&self) -> SignerIdentityV1 {
        self.custodian.coordinates.scope_bytes()
    }

    #[must_use]
    pub(crate) fn signer_scope_policy_identity(&self) -> SignerIdentityV1 {
        self.custodian.coordinates.policy_bytes()
    }

    #[must_use]
    pub(crate) fn signer_scope_policy_version(&self) -> u64 {
        self.proposal.fields().signer_scope_policy_version
    }

    /// Reopen and reauthenticate the descriptor on every authority-bearing
    /// use; an inherited or displaced file cannot remain verified by value.
    pub(crate) fn verify_same_process(&self) -> Result<(), SignerRefusalV2> {
        if self.creator_pid != std::process::id()
            || self.custodian.creator_pid != std::process::id()
            || !std::ptr::eq(self.proposal, &self.custodian.proposal)
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        let (seed, retained_file, retained_facts) = self.custodian.load_seed_for_signing()?;
        if retained_facts.inode != self.proposal.fields().custody_file_inode
            || retained_facts.device != self.proposal.fields().custody_file_device
            || retained_facts.mount != self.proposal.fields().custody_file_mount
            || self.custodian.verifying_key()? != self.public_key
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        drop(retained_file);
        drop(seed);
        Ok(())
    }
}

impl<'process> StoreVerifiedGenerationCurrentCustodyV1<'process> {
    #[must_use]
    pub(crate) fn foundation_identity(&self) -> &Sha256Digest {
        &self.stable.foundation_identity
    }

    #[must_use]
    pub(crate) fn foundational_custody(&self) -> &VerifiedFoundationalCustodyV1<'process> {
        &self.foundational
    }

    #[must_use]
    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.stable.public_key
    }

    #[must_use]
    pub(crate) fn key_generation(&self) -> u64 {
        self.stable.key_generation
    }

    #[must_use]
    pub(crate) fn custody_evidence_identity(&self) -> &Sha256Digest {
        &self.stable.custody_evidence_identity
    }

    pub(crate) fn verify_same_process(&self) -> Result<(), SignerRefusalV2> {
        self.foundational.verify_same_process()?;
        self.stable.verify_proposal(self.foundational.proposal)
    }
}

impl StoreReopenedGenerationCurrentCustodianV1 {
    /// Reauthenticate and seal this retained custodian against the stable
    /// foundation selected by the Store during reopen.
    pub(crate) fn verify_generation_current_custody(
        &self,
    ) -> Result<StoreVerifiedGenerationCurrentCustodyV1<'_>, SignerRefusalV2> {
        let foundational = self
            .custodian
            .verify_foundational_custody(&self.custodian.proposal)?;
        self.stable.verify_proposal(foundational.proposal)?;
        Ok(StoreVerifiedGenerationCurrentCustodyV1 {
            foundational,
            stable: self.stable.clone(),
        })
    }
}

impl std::fmt::Debug for C2StoreIntegrityCustodian {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("C2StoreIntegrityCustodian")
            .field("proposal_identity", self.proposal.proposal_identity())
            .field("final_name", &self.final_name)
            .field("creator_pid", &self.creator_pid)
            .field("secret", &"<descriptor-resolved>")
            .finish()
    }
}

impl C2StoreIntegrityCustodian {
    /// Production creation accepts no path or randomness from its caller.
    pub(in crate::store_generation) fn create(
        coordinates: PreGenerationCustodyCoordinatesV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        let root = open_production_custody_root()?;
        let reconciliation_root = root.try_clone().map_err(|_| SignerRefusalV2::CustodyIo)?;
        match Self::create_below_root(coordinates.clone(), frontier, root) {
            Ok(created) => Ok(created),
            Err(SignerRefusalV2::CustodyPathMismatch) => {
                // The only recoverable filesystem-first cut is one exact
                // committed carrier at the Store's still-missing ordinal.
                // Reconciliation reauthenticates that carrier and never
                // generates replacement key material.
                Self::reconcile_filesystem_first_below_root(
                    coordinates,
                    frontier,
                    reconciliation_root,
                )
            }
            Err(error) => Err(error),
        }
    }

    /// Nominal Store-owned preparation lane for a new ordinary-successor
    /// foundation. The current live view fixes the predecessor, scope, policy,
    /// implementation and next key generation; the returned request remains
    /// inert and cannot substitute for MSG-06 or MSG-07.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn create_ordinary_successor_for_actor_v1(
        actor: &StoreC2SnapshotActorV1<'_>,
        current: &C2LiveSigningViewV1<'_, '_, '_, GenerationCurrentV1>,
        coordinates: PreGenerationCustodyCoordinatesV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
        transition_identity: Sha256Digest,
        successor_pop_challenge_identity: Sha256Digest,
    ) -> Result<
        (
            Self,
            StoreIntegrityKeyProposalV1,
            StoreOrdinarySuccessorCustodyPreparationRequestV1,
        ),
        SignerRefusalV2,
    > {
        current
            .verify_live(actor)
            .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        let current_binding = current
            .current_binding_identity()
            .ok_or(SignerRefusalV2::CustodyPathMismatch)?;
        let expected_generation = current
            .signer_key_generation()
            .checked_add(1)
            .ok_or(SignerRefusalV2::CustodyPathMismatch)?;
        if coordinates.occurrence_id != current.occurrence_id()
            || digest_bytes(&coordinates.scope_identity) != current.signer_scope_identity()
            || coordinates.resident_identity != current.resident_identity()
            || coordinates.resident_generation != current.resident_generation()
            || coordinates.host_role != current.host_role()
            || coordinates.role_manifest_generation != current.role_manifest_generation()
            || coordinates.authority_domain != current.authority_domain()
            || digest_bytes(&coordinates.signer_scope_policy_identity)
                != current.signer_scope_policy_identity()
            || coordinates.signer_scope_policy_version != current.signer_scope_policy_version()
            || coordinates.proposed_key_generation != expected_generation
            || digest_bytes(&coordinates.custodian_implementation_manifest_identity)
                != current.implementation_manifest_identity()
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        let (custodian, proposal) = Self::create(coordinates, frontier)?;
        let request = StoreOrdinarySuccessorCustodyPreparationRequestV1::construct(
            current.occurrence_id().to_owned(),
            digest_from_identity_bytes(current.signer_scope_identity())?,
            digest_from_identity_bytes(current_binding)?,
            digest_from_identity_bytes(current.signer_key_generation_identity())?,
            transition_identity,
            &proposal,
            successor_pop_challenge_identity,
            digest_from_identity_bytes(current.active_policy_identity())?,
            current.active_policy_generation(),
        )?;
        Ok((custodian, proposal, request))
    }

    /// Nominal Store-owned key-creation lane for recovery. The returned
    /// proposal is inert and the consumed basis is not returned, so one live
    /// preparation seal cannot create two keys. Exact external MSG-15 remains
    /// a later, independently verified entry premise.
    pub(in crate::store_generation) fn create_recovery_foundation_for_actor_v1(
        actor: &StoreC2SnapshotActorV1<'_>,
        basis: StoreRecoveryCustodyPreparationBasisV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        basis.verify_for_actor(actor)?;
        Self::create(basis.coordinates, frontier)
    }

    /// Reopen only the exact proposal/coordinate pair freshly sealed from a
    /// Store-owned durable preparation row.  No raw proposal or path enters
    /// this production seam.
    pub(in crate::store_generation) fn reopen_prepared_for_actor(
        actor: &StoreC2SnapshotActorV1<'_>,
        prepared: StoreVerifiedPreparedCustodyV1,
    ) -> Result<Self, SignerRefusalV2> {
        prepared.verify_for_actor(actor)?;
        let root = open_production_custody_root()?;
        Self::reopen_below_root(prepared.coordinates, prepared.proposal, root)
    }

    /// Route-neutral reopen for a completed GenerationCurrent terminal.
    ///
    /// The Store actor supplies its sealed durable preparation and the exact
    /// canonical stable foundation selected by the terminal binding.  This
    /// seam accepts neither a caller-selected lineage/mode nor an independently
    /// authored public-key/generation/custody tuple.  It serves healthy
    /// successors and recovery with their prepared new custody, and restore
    /// only when the preparation is the exact historical custody foundation.
    pub(in crate::store_generation) fn reopen_prepared_generation_current_for_actor(
        actor: &StoreC2SnapshotActorV1<'_>,
        prepared: StoreVerifiedPreparedCustodyV1,
        foundation: &StoreIntegritySignerFoundationV1,
    ) -> Result<StoreReopenedGenerationCurrentCustodianV1, SignerRefusalV2> {
        prepared.verify_for_actor(actor)?;
        let stable = StableFoundationCustodyCoordinatesV1::from_foundation(foundation)?;
        stable.verify_proposal(&prepared.proposal)?;
        let root = open_production_custody_root()?;
        let custodian = Self::reopen_below_root(prepared.coordinates, prepared.proposal, root)?;
        let reopened = StoreReopenedGenerationCurrentCustodianV1 { custodian, stable };
        let verified = reopened.verify_generation_current_custody()?;
        verified.verify_same_process()?;
        drop(verified);
        Ok(reopened)
    }

    fn create_below_root(
        coordinates: PreGenerationCustodyCoordinatesV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
        root: File,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        // From entry through carrier zeroization, no process may be created
        // from this address space.  The fence is acquired before every
        // custody operation and every local custody lock in this method, and
        // RAII releases it last.
        let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;
        coordinates.validate()?;
        let scope_token = coordinates.scope_token()?;
        let proposal_ordinal = frontier.verify_for(&scope_token)?;
        let scope_mutex = custody_scope_mutex(&scope_token)?;
        let _scope_guard = scope_mutex.lock().map_err(|_| SignerRefusalV2::CustodyIo)?;
        let scope_directory = open_or_create_scope_directory(&root, &scope_token)?;
        frontier.verify_directory(&scope_directory, &coordinates)?;
        let scope_facts = directory_facts(&scope_directory)?;
        let scope_directory_identity = domain_digest(
            SCOPE_DIRECTORY_DOMAIN_V1,
            &ScopeDirectoryIdentityPreimage {
                device: scope_facts.device,
                mount: scope_facts.mount,
                inode: scope_facts.inode,
                owner_uid: scope_facts.owner_uid,
                owner_gid: scope_facts.owner_gid,
                mode: "0700",
            },
        )?;

        let mut seed = [0_u8; 32];
        let mut nonce = SecretBytes32([0_u8; 32]);
        let mut process_epoch = SecretBytes32([0_u8; 32]);
        getrandom::fill(&mut seed).map_err(|_| SignerRefusalV2::CustodyIo)?;
        getrandom::fill(&mut nonce.0).map_err(|_| SignerRefusalV2::CustodyIo)?;
        getrandom::fill(&mut process_epoch.0).map_err(|_| SignerRefusalV2::CustodyIo)?;
        let seed = SecretSeedV1(seed);
        let verifying_key = SigningKey::from_bytes(&seed.0).verifying_key().to_bytes();
        let public_key = hex::encode(verifying_key);
        let nonce_hex = hex::encode(nonce.0);
        let proposal_core_identity = domain_digest(
            PROPOSAL_CORE_DOMAIN_V1,
            &ProposalCorePreimage {
                scope_token: &scope_token,
                proposal_ordinal,
                proposed_key_generation: coordinates.proposed_key_generation,
                algorithm: KEY_ALGORITHM_V1,
                public_key: &public_key,
                custody_nonce: &nonce_hex,
                key_carrier_schema: PRIVATE_CUSTODY_SCHEMA_V1,
            },
        )?;
        let temporary_name = format!(".pending.{}.key", digest_hex(&proposal_core_identity));
        let mut temporary = File::from(
            openat(
                &scope_directory,
                temporary_name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| SignerRefusalV2::CustodyIo)?,
        );
        #[cfg(test)]
        crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-45");
        let initial_facts = object_facts(&temporary)?;
        if !initial_facts.regular_file
            || initial_facts.link_count != 1
            || initial_facts.owner_uid != effective_uid()
            || initial_facts.owner_gid != effective_gid()
            || initial_facts.mode != 0o600
        {
            return Err(SignerRefusalV2::CustodyFileUnsafe);
        }
        let proposal_identity = domain_digest(
            PROPOSAL_ID_DOMAIN_V1,
            &ProposalIdentityPreimage {
                proposal_core_identity: &proposal_core_identity,
                scope_directory_identity: &scope_directory_identity,
                custody_file_device: initial_facts.device,
                custody_file_mount: initial_facts.mount,
                custody_file_inode: initial_facts.inode,
                owner_uid: initial_facts.owner_uid,
                owner_gid: initial_facts.owner_gid,
                mode: "0400",
                link_count: 1,
            },
        )?;
        let fields = CustodyPublicFieldsV1 {
            proposal_core_identity,
            proposal_identity: proposal_identity.clone(),
            proposal_ordinal,
            scope_token,
            occurrence_id: coordinates.occurrence_id.clone(),
            scope_identity: coordinates.scope_identity.clone(),
            a2_chain_root_identity: coordinates.a2_chain_root_identity.clone(),
            trust_anchor_identity: coordinates.trust_anchor_identity.clone(),
            resident_identity: coordinates.resident_identity.clone(),
            resident_generation: coordinates.resident_generation,
            host_role: coordinates.host_role.clone(),
            role_manifest_generation: coordinates.role_manifest_generation,
            authority_domain: coordinates.authority_domain.clone(),
            signer_scope_policy_identity: coordinates.signer_scope_policy_identity.clone(),
            signer_scope_policy_version: coordinates.signer_scope_policy_version,
            proposed_key_generation: coordinates.proposed_key_generation,
            algorithm: KEY_ALGORITHM_V1.to_owned(),
            public_key,
            custody_nonce: nonce_hex,
            scope_directory_identity,
            custody_file_device: initial_facts.device,
            custody_file_mount: initial_facts.mount,
            custody_file_inode: initial_facts.inode,
            owner_uid: initial_facts.owner_uid,
            owner_gid: initial_facts.owner_gid,
            mode: "0400".to_owned(),
            link_count: 1,
        };
        let proposal = StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1 {
            schema: KEY_PROPOSAL_SCHEMA_V1.to_owned(),
            schema_version: 1,
            fields: fields.clone(),
        });
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
        let mut carrier = StoreIntegrityCustodyCarrierV1 {
            schema: PRIVATE_CUSTODY_SCHEMA_V1.to_owned(),
            schema_version: 1,
            fields,
            magic: PRIVATE_CUSTODY_MAGIC_V1.to_owned(),
            private_seed: hex::encode(seed.0),
            custodian_implementation_manifest_identity: coordinates
                .custodian_implementation_manifest_identity
                .clone(),
            payload_digest: sha256_bytes(b"placeholder-replaced-before-encoding"),
        };
        carrier.payload_digest = StoreIntegrityCustodyFileV1::payload_digest(&carrier)?;
        let private_file = StoreIntegrityCustodyFileV1(carrier);
        let mut bytes = SecretBytes(private_file.encode()?);
        temporary
            .write_all(&bytes)
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        #[cfg(test)]
        crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-46");
        temporary
            .set_len(bytes.len() as u64)
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        #[cfg(test)]
        crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-47");
        fchmod(&temporary, Mode::RUSR).map_err(|_| SignerRefusalV2::CustodyIo)?;
        fdatasync(&temporary).map_err(|_| SignerRefusalV2::CustodyIo)?;
        let committed_facts = object_facts(&temporary)?;
        verify_file_facts_against_fields(&committed_facts, private_file.0.fields(), bytes.len())?;
        if *read_exact_secret_bytes(&temporary)? != *bytes
            || StoreIntegrityCustodyFileV1::decode(&bytes)?.0 != private_file.0
        {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let final_name = format!("{}.key", digest_hex(&proposal_identity));
        renameat_with(
            &scope_directory,
            temporary_name.as_str(),
            &scope_directory,
            final_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
        fsync(&scope_directory).map_err(|_| SignerRefusalV2::CustodyIo)?;
        #[cfg(test)]
        crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-48");
        let final_file = open_final_key(&scope_directory, &final_name)?;
        let final_facts = object_facts(&final_file)?;
        if final_facts != committed_facts || *read_exact_secret_bytes(&final_file)? != *bytes {
            return Err(SignerRefusalV2::CustodyFileUnsafe);
        }
        bytes.fill(0);
        drop(private_file);
        drop(seed);
        fork_fence_guard
            .verify_same_process()
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        let custodian = Self {
            coordinates,
            proposal: proposal.clone(),
            scope_directory,
            final_name,
            creator_pid: std::process::id(),
            process_epoch: process_epoch.0,
        };
        Ok((custodian, proposal))
    }

    fn reconcile_filesystem_first_below_root(
        coordinates: PreGenerationCustodyCoordinatesV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
        root: File,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;
        coordinates.validate()?;
        let scope_token = coordinates.scope_token()?;
        let proposal_ordinal = frontier.verify_for(&scope_token)?;
        let scope_mutex = custody_scope_mutex(&scope_token)?;
        let _scope_guard = scope_mutex.lock().map_err(|_| SignerRefusalV2::CustodyIo)?;
        validate_directory(&root, 0o700)?;
        let scope_directory = open_directory_component(&root, digest_hex(&scope_token))?;
        validate_directory(&scope_directory, 0o700)?;
        require_same_filesystem(&root, &scope_directory)?;

        let observed = scope_directory_committed_proposal_identities(&scope_directory)?;
        let committed = frontier
            .committed_proposals
            .values()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !committed.is_subset(&observed) || observed.len() != committed.len() + 1 {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        for (ordinal, identity) in &frontier.committed_proposals {
            verify_committed_carrier_for_frontier(
                &scope_directory,
                &scope_token,
                *ordinal,
                identity,
                &coordinates.custodian_implementation_manifest_identity,
            )?;
        }
        let orphan_identity = observed
            .difference(&committed)
            .next()
            .ok_or(SignerRefusalV2::CustodyPathMismatch)?
            .clone();
        let final_name = format!("{}.key", digest_hex(&orphan_identity));
        let final_file = open_final_key(&scope_directory, &final_name)?;
        let facts = object_facts(&final_file)?;
        let bytes = read_exact_secret_bytes(&final_file)?;
        let carrier = StoreIntegrityCustodyFileV1::decode(&bytes)?;
        verify_file_facts_against_fields(&facts, carrier.0.fields(), bytes.len())?;
        let proposal = StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1 {
            schema: KEY_PROPOSAL_SCHEMA_V1.to_owned(),
            schema_version: 1,
            fields: carrier.0.fields.clone(),
        });
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
        let seed = carrier.secret_seed()?;
        if proposal.proposal_identity() != &orphan_identity
            || proposal.fields().proposal_ordinal != proposal_ordinal
            || proposal.fields().scope_token != scope_token
            || !proposal_fields_match_coordinates(proposal.fields(), &coordinates)
            || carrier.0.custodian_implementation_manifest_identity
                != coordinates.custodian_implementation_manifest_identity
            || SigningKey::from_bytes(&seed.0).verifying_key().to_bytes()
                != decode_hex_32(&proposal.fields().public_key)?
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        drop(seed);
        drop(carrier);
        drop(bytes);
        drop(final_file);
        let mut process_epoch = [0_u8; 32];
        getrandom::fill(&mut process_epoch).map_err(|_| SignerRefusalV2::CustodyIo)?;
        fork_fence_guard
            .verify_same_process()
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        let custodian = Self {
            coordinates,
            proposal: proposal.clone(),
            scope_directory,
            final_name,
            creator_pid: std::process::id(),
            process_epoch,
        };
        let proof = custodian.verify_foundational_custody(&custodian.proposal)?;
        proof.verify_same_process()?;
        drop(proof);
        Ok((custodian, proposal))
    }

    /// Reopen one exact pre-generation custody object in the current process.
    ///
    /// The caller supplies evidence coordinates and the exact public proposal,
    /// but neither can create custody: this function resolves the fixed root
    /// and scope through retained descriptors, reopens the proposal-named
    /// private carrier with `NOFOLLOW`, verifies inode/ownership/mode/link
    /// facts, canonical bytes, implementation manifest and seed/public-key
    /// correspondence, and only then returns a new process-local custodian.
    pub(crate) fn reopen(
        coordinates: PreGenerationCustodyCoordinatesV1,
        proposal: StoreIntegrityKeyProposalV1,
    ) -> Result<Self, SignerRefusalV2> {
        let root = open_production_custody_root()?;
        Self::reopen_below_root(coordinates, proposal, root)
    }

    /// Reconstruct fresh process-local custody from the exact durable
    /// foundational-enrollment evidence and the currently admitted custodian
    /// implementation basis.
    ///
    /// The public proposal is deliberately not a caller input.  It is decoded
    /// from the proposal-named, `NOFOLLOW` private carrier under the fixed
    /// custody root, then every pre-generation coordinate is checked against
    /// the canonical foundational record before the ordinary descriptor-
    /// retaining reopen verifier may mint a new custodian.  Neither the
    /// enrollment nor any of its digest fields is live authority by itself.
    pub(crate) fn reopen_from_foundational_evidence(
        foundational: &StoreIntegrityKeyEnrollmentV1,
        pre_generation_scope_identity: SignerIdentityV1,
        custodian_implementation_manifest_identity: &Sha256Digest,
    ) -> Result<Self, SignerRefusalV2> {
        verify_n_18_key_enrollment(foundational)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let scope_identity = Sha256Digest::parse(format!(
            "sha256:{}",
            hex::encode(pre_generation_scope_identity)
        ))
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let coordinates = PreGenerationCustodyCoordinatesV1 {
            occurrence_id: foundational.occurrence().as_str().to_owned(),
            scope_identity,
            a2_chain_root_identity: foundational.a2_chain_root().digest().clone(),
            trust_anchor_identity: foundational.dependency_anchor().digest().clone(),
            resident_identity: foundational.resident().as_str().to_owned(),
            resident_generation: foundational.resident_generation(),
            host_role: foundational.role().to_owned(),
            role_manifest_generation: foundational.role_manifest_generation(),
            authority_domain: foundational.authority_domain().to_owned(),
            signer_scope_policy_identity: foundational.signer_scope_policy().digest().clone(),
            signer_scope_policy_version: foundational.signer_scope_policy_version(),
            proposed_key_generation: u64::from(foundational.key_generation().get()),
            custodian_implementation_manifest_identity: custodian_implementation_manifest_identity
                .clone(),
        };
        coordinates.validate()?;
        let scope_token = coordinates.scope_token()?;
        let root = open_production_custody_root()?;
        validate_directory(&root, 0o700)?;
        let scope_directory = open_directory_component(&root, digest_hex(&scope_token))?;
        validate_directory(&scope_directory, 0o700)?;
        require_same_filesystem(&root, &scope_directory)?;
        let proposal_identity = foundational.proposal_identity().digest();
        let final_name = format!("{}.key", digest_hex(proposal_identity));
        let final_file = open_final_key(&scope_directory, &final_name)?;
        let bytes = read_exact_secret_bytes(&final_file)?;
        let carrier = StoreIntegrityCustodyFileV1::decode(&bytes)?;
        let proposal = StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1 {
            schema: KEY_PROPOSAL_SCHEMA_V1.to_owned(),
            schema_version: 1,
            fields: carrier.0.fields.clone(),
        });
        let enrolled_public_key = hex::decode(foundational.public_key().as_str())
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        if proposal.proposal_identity() != proposal_identity
            || foundational.custody_evidence_identity().digest() != proposal_identity
            || proposal.fields().scope_token != scope_token
            || !proposal_fields_match_coordinates(proposal.fields(), &coordinates)
            || proposal.fields().public_key.as_bytes()
                != foundational.public_key().as_str().as_bytes()
            || proposal.fields().proposed_key_generation
                != u64::from(foundational.key_generation().get())
            || enrolled_public_key.len() != 32
            || carrier.0.custodian_implementation_manifest_identity
                != *custodian_implementation_manifest_identity
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        drop(carrier);
        drop(bytes);
        drop(final_file);
        drop(scope_directory);
        Self::reopen_below_root(coordinates, proposal, root)
    }

    fn reopen_below_root(
        coordinates: PreGenerationCustodyCoordinatesV1,
        proposal: StoreIntegrityKeyProposalV1,
        root: File,
    ) -> Result<Self, SignerRefusalV2> {
        let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;
        coordinates.validate()?;
        let scope_token = coordinates.scope_token()?;
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
        if proposal.fields().scope_token != scope_token
            || !proposal_fields_match_coordinates(proposal.fields(), &coordinates)
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        let scope_mutex = custody_scope_mutex(&scope_token)?;
        let _scope_guard = scope_mutex.lock().map_err(|_| SignerRefusalV2::CustodyIo)?;
        validate_directory(&root, 0o700)?;
        let scope_directory = open_directory_component(&root, digest_hex(&scope_token))?;
        validate_directory(&scope_directory, 0o700)?;
        require_same_filesystem(&root, &scope_directory)?;
        let final_name = format!("{}.key", digest_hex(proposal.proposal_identity()));
        let final_file = open_final_key(&scope_directory, &final_name)?;
        let facts = object_facts(&final_file)?;
        let bytes = read_exact_secret_bytes(&final_file)?;
        let carrier = StoreIntegrityCustodyFileV1::decode(&bytes)?;
        verify_file_facts_against_fields(&facts, carrier.0.fields(), bytes.len())?;
        if carrier.0.fields != *proposal.fields()
            || carrier.0.custodian_implementation_manifest_identity
                != coordinates.custodian_implementation_manifest_identity
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        let seed = carrier.secret_seed()?;
        if SigningKey::from_bytes(&seed.0).verifying_key().to_bytes()
            != decode_hex_32(&proposal.fields().public_key)?
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        drop(seed);
        drop(carrier);
        drop(bytes);
        let mut process_epoch = [0_u8; 32];
        getrandom::fill(&mut process_epoch).map_err(|_| SignerRefusalV2::CustodyIo)?;
        fork_fence_guard
            .verify_same_process()
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        let custodian = Self {
            coordinates,
            proposal,
            scope_directory,
            final_name,
            creator_pid: std::process::id(),
            process_epoch,
        };
        // Final readback after construction prevents the reopened descriptor
        // set from being replaced between verification and returned custody.
        let proof = custodian.verify_foundational_custody(&custodian.proposal)?;
        proof.verify_same_process()?;
        drop(proof);
        Ok(custodian)
    }

    pub(in crate::store_generation) fn proposal_identity(&self) -> &Sha256Digest {
        self.proposal.proposal_identity()
    }

    pub(in crate::store_generation) fn canonical_proposal_bytes(
        &self,
    ) -> Result<Vec<u8>, SignerRefusalV2> {
        self.proposal.canonical_bytes()
    }

    pub(super) fn coordinates(&self) -> &PreGenerationCustodyCoordinatesV1 {
        &self.coordinates
    }

    pub(in crate::store_generation) fn verifying_key(&self) -> Result<[u8; 32], SignerRefusalV2> {
        decode_hex_32(&self.proposal.fields().public_key)
    }

    pub(super) fn key_generation_identity(&self) -> SignerIdentityV1 {
        self.proposal.key_generation_identity()
    }

    /// Seal foundational custody only after exact descriptor readback, file
    /// facts, carrier canonicality, seed/public-key correspondence, and
    /// process freshness have all been reverified.
    pub(crate) fn verify_foundational_custody<'process>(
        &'process self,
        proposal: &'process StoreIntegrityKeyProposalV1,
    ) -> Result<VerifiedFoundationalCustodyV1<'process>, SignerRefusalV2> {
        if self.creator_pid != std::process::id()
            || !std::ptr::eq(proposal, &self.proposal)
            || proposal.fields() != self.proposal.fields()
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        let public_key = self.verifying_key()?;
        let proof = VerifiedFoundationalCustodyV1 {
            custodian: self,
            proposal,
            public_key,
            creator_pid: std::process::id(),
        };
        proof.verify_same_process()?;
        Ok(proof)
    }

    /// Bind retained, freshly authenticated custody to one exact canonical
    /// stable signer foundation.  This is route-neutral: the four lineage
    /// routes differ in how the Store selected/adopted the foundation, not in
    /// the custody correspondence required once it is GenerationCurrent.
    pub(crate) fn verify_generation_current_foundation_custody<'process>(
        &'process self,
        foundation: &StoreIntegritySignerFoundationV1,
    ) -> Result<StoreVerifiedGenerationCurrentCustodyV1<'process>, SignerRefusalV2> {
        let stable = StableFoundationCustodyCoordinatesV1::from_foundation(foundation)?;
        let foundational = self.verify_foundational_custody(&self.proposal)?;
        stable.verify_proposal(foundational.proposal)?;
        Ok(StoreVerifiedGenerationCurrentCustodyV1 {
            foundational,
            stable,
        })
    }

    /// Seal custody reopened from durable foundational evidence without
    /// exposing or reconstructing the private retained proposal outside the
    /// custodian.  The proposal remains inert; this fresh descriptor/process
    /// check is what produces the borrowed live custody proof.
    pub(crate) fn seal_reopened_foundational_custody(
        &self,
    ) -> Result<VerifiedFoundationalCustodyV1<'_>, SignerRefusalV2> {
        self.verify_foundational_custody(&self.proposal)
    }

    /// Private typed signing helper; the sealed message trait excludes raw
    /// bytes and external-governance carriers.
    pub(super) fn sign<M: SignerMessageV1, Phase>(
        &self,
        _permit: CoordinatorSigningPermitV1,
        live_permit: &StoreC2SignerAppendPermitV1<'_, '_, '_, Phase>,
        live: &C2LiveSigningViewV1<'_, '_, '_, Phase>,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        live_permit
            .verify_live_view(live)
            .map_err(|_| SignerRefusalV2::MessageFrontierMismatch)?;
        let expected_physical_generation = live.physical_generation_identity().unwrap_or([0; 32]);
        let expected_lifecycle_root = live.lifecycle_root_identity().unwrap_or([0; 32]);
        if std::process::id() != self.creator_pid
            || self.process_epoch.iter().all(|byte| *byte == 0)
            || !message.family().is_store_signable()
            || message.coordinates().occurrence != self.coordinates.occurrence_identity()
            || message.coordinates().occurrence != live.occurrence_identity()
            || message.coordinates().physical_generation != expected_physical_generation
            || message.coordinates().lifecycle_root != expected_lifecycle_root
            || message.coordinates().scope != self.coordinates.scope_bytes()
            || message.coordinates().scope != live.signer_scope_identity()
            || message.coordinates().policy != self.coordinates.policy_bytes()
            || message.coordinates().policy != live.signer_scope_policy_identity()
            || message.coordinates().signer_key_generation
                != self.proposal.key_generation_identity()
            || message.coordinates().signer_key_generation != live.signer_key_generation_identity()
            || message.coordinates().cut != live.event_cut()
            || self.verifying_key()? != live.signer_public_key()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        self.sign_after_authority_checks(message)
    }

    /// Purpose-locked MSG-02 signing before B/G or live signer standing.
    /// The actor has already verified the sealed request immediately before
    /// issuing `live_permit`; this method additionally binds that exact
    /// request to this retained custodian and the typed MSG-02 message.
    pub(super) fn sign_initial_possession<M: SignerMessageV1>(
        &self,
        _permit: CoordinatorSigningPermitV1,
        live_permit: &StoreC2InitialPossessionAppendPermitV1<'_, '_>,
        request: &VerifiedInitialPossessionRequestV1<'_, '_>,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        if std::ptr::from_ref(live_permit.request()).cast::<()>()
            != std::ptr::from_ref(request).cast::<()>()
            || !std::ptr::eq(request.custody().custodian, self)
            || std::process::id() != self.creator_pid
            || message.family() != ClosedMessageFamilyV1::Msg02InitialProposalPop
            || message.coordinates().occurrence != request.occurrence_identity()?
            || message.coordinates().occurrence != self.coordinates.occurrence_identity()
            || message.coordinates().physical_generation != [0; 32]
            || message.coordinates().lifecycle_root != [0; 32]
            || message.coordinates().scope != request.signer_scope_identity()
            || message.coordinates().scope != self.coordinates.scope_bytes()
            || message.coordinates().policy != request.signer_scope_policy_identity()?
            || message.coordinates().policy != self.coordinates.policy_bytes()
            || message.coordinates().signer_key_generation
                != request.signer_key_generation_identity()
            || message.coordinates().signer_key_generation
                != self.proposal.key_generation_identity()
            || message.coordinates().cut != request.event_cut()
            || request.public_key() != self.verifying_key()?
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        self.sign_after_authority_checks(message)
    }

    /// Perform only the custody/cryptographic portion after the caller has
    /// established the sealed live-Store correspondence.
    ///
    /// Keeping this helper private prevents a sibling module from bypassing
    /// the live permit checks above.  The test-only wrapper below exists so
    /// filesystem-tamper tests can exercise custody failures without minting
    /// fake product authority.
    fn sign_after_authority_checks<M: SignerMessageV1>(
        &self,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        // From seed reload through signing-key zeroization, no process may be
        // created from this address space.
        let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;
        let (seed, retained_file, retained_facts) = self.load_seed_for_signing()?;
        let preimage = message.canonical_preimage();
        let payload_digest: SignerIdentityV1 = Sha256::digest(&preimage).into();
        let signing_key = SigningKey::from_bytes(&seed.0);
        let signature = signing_key.sign(&preimage).to_bytes();
        let reopened = open_final_key(&self.scope_directory, &self.final_name)?;
        if object_facts(&reopened)? != retained_facts {
            return Err(SignerRefusalV2::CustodyFileUnsafe);
        }
        drop(retained_file);
        drop(signing_key);
        drop(seed);
        fork_fence_guard
            .verify_same_process()
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        Ok(CustodySignatureV1 {
            family: message.family(),
            signer_key_generation: self.proposal.key_generation_identity(),
            payload_digest,
            signature,
        })
    }

    #[cfg(test)]
    fn sign_for_custody_hostile_test<M: SignerMessageV1>(
        &self,
        _permit: CoordinatorSigningPermitV1,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        if std::process::id() != self.creator_pid
            || self.process_epoch.iter().all(|byte| *byte == 0)
            || !message.family().is_store_signable()
            || message.coordinates().occurrence != self.coordinates.occurrence_identity()
            || message.coordinates().scope != self.coordinates.scope_bytes()
            || message.coordinates().policy != self.coordinates.policy_bytes()
            || message.coordinates().signer_key_generation
                != self.proposal.key_generation_identity()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        self.sign_after_authority_checks(message)
    }

    fn load_seed_for_signing(
        &self,
    ) -> Result<(SecretSeedV1, Flock<File>, CustodyObjectFactsV1), SignerRefusalV2> {
        let file = open_final_key(&self.scope_directory, &self.final_name)?;
        let flock = Flock::lock(file, FlockArg::LockSharedNonblock)
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        let facts = object_facts(&flock)?;
        let bytes = SecretBytes(read_exact_bytes(&flock)?);
        let carrier = StoreIntegrityCustodyFileV1::decode(&bytes)?;
        verify_file_facts_against_fields(&facts, carrier.0.fields(), bytes.len())?;
        if carrier.0.fields != *self.proposal.fields()
            || carrier.0.custodian_implementation_manifest_identity
                != self.coordinates.custodian_implementation_manifest_identity
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        let seed = carrier.secret_seed()?;
        Ok((seed, flock, facts))
    }

    #[cfg(test)]
    pub(super) fn create_below_test_root(
        coordinates: PreGenerationCustodyCoordinatesV1,
        root: File,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        let frontier =
            VerifiedCustodyProposalFrontierV1::initial_for_test(coordinates.scope_token()?);
        Self::create_below_root(coordinates, &frontier, root)
    }
}

fn proposal_fields_match_coordinates(
    fields: &CustodyPublicFieldsV1,
    coordinates: &PreGenerationCustodyCoordinatesV1,
) -> bool {
    fields.occurrence_id == coordinates.occurrence_id
        && fields.scope_identity == coordinates.scope_identity
        && fields.a2_chain_root_identity == coordinates.a2_chain_root_identity
        && fields.trust_anchor_identity == coordinates.trust_anchor_identity
        && fields.resident_identity == coordinates.resident_identity
        && fields.resident_generation == coordinates.resident_generation
        && fields.host_role == coordinates.host_role
        && fields.role_manifest_generation == coordinates.role_manifest_generation
        && fields.authority_domain == coordinates.authority_domain
        && fields.signer_scope_policy_identity == coordinates.signer_scope_policy_identity
        && fields.signer_scope_policy_version == coordinates.signer_scope_policy_version
        && fields.proposed_key_generation == coordinates.proposed_key_generation
}

impl CustodyPublicFieldsV1 {
    fn proposal_identity_preimage(&self) -> ProposalIdentityPreimage<'_> {
        ProposalIdentityPreimage {
            proposal_core_identity: &self.proposal_core_identity,
            scope_directory_identity: &self.scope_directory_identity,
            custody_file_device: self.custody_file_device,
            custody_file_mount: self.custody_file_mount,
            custody_file_inode: self.custody_file_inode,
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            mode: "0400",
            link_count: self.link_count,
        }
    }
}

impl StoreIntegrityCustodyCarrierV1 {
    fn fields(&self) -> &CustodyPublicFieldsV1 {
        &self.fields
    }
}

fn custody_scope_mutex(scope_token: &Sha256Digest) -> Result<&'static Mutex<()>, SignerRefusalV2> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, &'static Mutex<()>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry.lock().map_err(|_| SignerRefusalV2::CustodyIo)?;
    Ok(*registry
        .entry(scope_token.as_str().to_owned())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(())))))
}

fn open_production_custody_root() -> Result<File, SignerRefusalV2> {
    #[cfg(test)]
    if let Some(root) = TEST_PRODUCTION_CUSTODY_ROOT_V1.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(File::try_clone)
            .transpose()
    })
    .map_err(|_| SignerRefusalV2::CustodyIo)?
    {
        validate_directory(&root, 0o700)?;
        return Ok(root);
    }

    let filesystem_root = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    );
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-49");
    let var = open_directory_component(&filesystem_root, "var")?;
    require_same_filesystem(&filesystem_root, &var)?;
    let lib = open_directory_component(&var, "lib")?;
    require_same_filesystem(&var, &lib)?;
    let parent = open_directory_component(&lib, "nq")?;
    require_same_filesystem(&lib, &parent)?;
    validate_directory(&parent, 0o700)?;
    let root = open_directory_component(&parent, STORE_INTEGRITY_CUSTODY_CHILD_V1)?;
    validate_directory(&root, 0o700)?;
    require_same_filesystem(&parent, &root)?;
    Ok(root)
}

fn open_directory_component(parent: &File, name: &str) -> Result<File, SignerRefusalV2> {
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    );
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-50");
    Ok(directory)
}

fn require_same_filesystem(parent: &File, child: &File) -> Result<(), SignerRefusalV2> {
    let parent = object_facts(parent)?;
    let child = object_facts(child)?;
    if parent.device != child.device || parent.mount != child.mount {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    Ok(())
}

fn open_or_create_scope_directory(
    root: &File,
    scope_token: &Sha256Digest,
) -> Result<File, SignerRefusalV2> {
    validate_directory(root, 0o700)?;
    let name = digest_hex(scope_token);
    match mkdirat(root, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => {
            fsync(root).map_err(|_| SignerRefusalV2::CustodyIo)?;
            #[cfg(test)]
            crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-51");
        }
        Err(error) if error == rustix::io::Errno::EXIST => {}
        Err(_) => return Err(SignerRefusalV2::CustodyIo),
    }
    let directory = File::from(
        openat(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    );
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-52");
    validate_directory(&directory, 0o700)?;
    require_same_filesystem(root, &directory)?;
    Ok(directory)
}

fn validate_directory(directory: &File, expected_mode: u32) -> Result<(), SignerRefusalV2> {
    let metadata = directory
        .metadata()
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.gid() != effective_gid()
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    let mut attribute_buffer = [0_u8; 4096];
    let attribute_length =
        flistxattr(directory, &mut attribute_buffer).map_err(|_| SignerRefusalV2::CustodyIo)?;
    let attributes = &attribute_buffer[..attribute_length];
    for attribute in attributes.split(|byte| *byte == 0) {
        if attribute == b"system.posix_acl_access" || attribute == b"system.posix_acl_default" {
            return Err(SignerRefusalV2::CustodyFileUnsafe);
        }
    }
    Ok(())
}

fn directory_facts(directory: &File) -> Result<CustodyObjectFactsV1, SignerRefusalV2> {
    let facts = object_facts(directory)?;
    if facts.mode != 0o700
        || facts.owner_uid != effective_uid()
        || facts.owner_gid != effective_gid()
    {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    Ok(facts)
}

fn object_facts(file: &File) -> Result<CustodyObjectFactsV1, SignerRefusalV2> {
    let metadata = file.metadata().map_err(|_| SignerRefusalV2::CustodyIo)?;
    let statx = statx(
        file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(|_| SignerRefusalV2::CustodyIo)?;
    if [
        metadata.dev(),
        statx.stx_mnt_id,
        metadata.ino(),
        metadata.nlink(),
        metadata.len(),
    ]
    .into_iter()
    .any(|value| value > IJSON_SAFE_INTEGER)
    {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    Ok(CustodyObjectFactsV1 {
        device: metadata.dev(),
        mount: statx.stx_mnt_id,
        inode: metadata.ino(),
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        link_count: metadata.nlink(),
        regular_file: metadata.file_type().is_file(),
        length: metadata.len(),
    })
}

fn open_final_key(directory: &File, name: &str) -> Result<File, SignerRefusalV2> {
    let file = File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    );
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-53");
    Ok(file)
}

fn scope_directory_committed_proposal_identities(
    directory: &File,
) -> Result<BTreeSet<Sha256Digest>, SignerRefusalV2> {
    let mut reader = Dir::read_from(directory).map_err(|_| SignerRefusalV2::CustodyIo)?;
    let mut identities = BTreeSet::new();
    for entry in &mut reader {
        let entry = entry.map_err(|_| SignerRefusalV2::CustodyIo)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let is_exact_key_name = name.len() == 64 + b".key".len()
            && name.ends_with(b".key")
            && name[..64]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
        if !is_exact_key_name {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        let digest = Sha256Digest::parse(format!(
            "sha256:{}",
            std::str::from_utf8(&name[..64]).map_err(|_| SignerRefusalV2::CustodyPathMismatch)?,
        ))
        .map_err(|_| SignerRefusalV2::CustodyPathMismatch)?;
        if !identities.insert(digest) {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
    }
    Ok(identities)
}

fn verify_committed_carrier_for_frontier(
    directory: &File,
    expected_scope_token: &Sha256Digest,
    expected_ordinal: u64,
    expected_proposal_identity: &Sha256Digest,
    expected_manifest_identity: &Sha256Digest,
) -> Result<(), SignerRefusalV2> {
    let name = format!("{}.key", digest_hex(expected_proposal_identity));
    let file = open_final_key(directory, &name)?;
    let facts = object_facts(&file)?;
    let bytes = read_exact_secret_bytes(&file)?;
    let carrier = StoreIntegrityCustodyFileV1::decode(&bytes)?;
    verify_file_facts_against_fields(&facts, carrier.0.fields(), bytes.len())?;
    let proposal = StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1 {
        schema: KEY_PROPOSAL_SCHEMA_V1.to_owned(),
        schema_version: 1,
        fields: carrier.0.fields.clone(),
    });
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
    if proposal.proposal_identity() != expected_proposal_identity
        || proposal.fields().scope_token != *expected_scope_token
        || proposal.fields().proposal_ordinal != expected_ordinal
        || carrier.0.custodian_implementation_manifest_identity != *expected_manifest_identity
    {
        return Err(SignerRefusalV2::CustodyPathMismatch);
    }
    Ok(())
}

fn read_exact_bytes(file: &File) -> Result<Vec<u8>, SignerRefusalV2> {
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| SignerRefusalV2::CustodyIo)?
            .len(),
    )
    .map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
    if length == 0 || length > 64 * 1024 {
        return Err(SignerRefusalV2::CustodyFileMalformed);
    }
    let mut bytes = vec![0_u8; length];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    Ok(bytes)
}

/// Read-back of a secret-bearing custody file, cleared when dropped.
fn read_exact_secret_bytes(file: &File) -> Result<SecretBytes, SignerRefusalV2> {
    Ok(SecretBytes(read_exact_bytes(file)?))
}

fn verify_file_facts_against_fields(
    facts: &CustodyObjectFactsV1,
    fields: &CustodyPublicFieldsV1,
    exact_length: usize,
) -> Result<(), SignerRefusalV2> {
    if !facts.regular_file
        || facts.device != fields.custody_file_device
        || facts.mount != fields.custody_file_mount
        || facts.inode != fields.custody_file_inode
        || facts.owner_uid != fields.owner_uid
        || facts.owner_gid != fields.owner_gid
        || facts.mode != 0o400
        || facts.link_count != 1
        || facts.length != exact_length as u64
    {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    Ok(())
}

fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn effective_gid() -> u32 {
    nix::unistd::getegid().as_raw()
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Sha256Digest, SignerRefusalV2> {
    let canonical =
        canonical_json_bytes(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
    Ok(sha256_bytes(&[domain, canonical.as_slice()].concat()))
}

fn digest_fields_v1(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Sha256Digest::parse(format!("sha256:{}", hex::encode(bytes)))
        .expect("SHA-256 bytes always form a valid algorithm-qualified digest")
}

fn decode_canonical_json_v1(bytes: &[u8]) -> Result<serde_json::Value, SignerRefusalV2> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
    if canonical_json_bytes(&value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)? != bytes {
        return Err(SignerRefusalV2::CustodyFileMalformed);
    }
    Ok(value)
}

fn decode_canonical_proposal_v1(
    bytes: &[u8],
) -> Result<StoreIntegrityKeyProposalV1, SignerRefusalV2> {
    let value = decode_canonical_json_v1(bytes)?;
    let carrier: StoreIntegrityKeyProposalCarrierV1 =
        serde_json::from_value(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
    let proposal = StoreIntegrityKeyProposalV1(carrier);
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
    Ok(proposal)
}

fn digest_from_identity_bytes(bytes: [u8; 32]) -> Result<Sha256Digest, SignerRefusalV2> {
    Sha256Digest::parse(format!("sha256:{}", hex::encode(bytes)))
        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)
}

fn digest_field_v1(value: Option<&serde_json::Value>) -> Result<Sha256Digest, SignerRefusalV2> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(SignerRefusalV2::EnrollmentEvidenceCollision)
        .and_then(|value| {
            Sha256Digest::parse(value.to_owned())
                .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)
        })
}

fn domain_digest_bytes(domain: &[u8], bytes: &[u8]) -> SignerIdentityV1 {
    let digest = Sha256::digest([domain, bytes].concat());
    digest.into()
}

fn digest_bytes(digest: &Sha256Digest) -> SignerIdentityV1 {
    decode_hex_32(
        digest
            .as_str()
            .strip_prefix("sha256:")
            .expect("validated digest"),
    )
    .expect("Sha256Digest invariant")
}

fn digest_hex(digest: &Sha256Digest) -> &str {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("Sha256Digest invariant")
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], SignerRefusalV2> {
    let bytes = hex::decode(value).map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
    bytes
        .try_into()
        .map_err(|_| SignerRefusalV2::CustodyFileMalformed)
}

pub(crate) fn construct_sg_wu_02_key_proposal_custody_owner_inert_key_creation(
    proposal: StoreIntegrityKeyProposalV1,
) -> Result<StoreIntegrityKeyProposalV1, SignerRefusalV2> {
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
    Ok(proposal)
}

pub(crate) fn verify_sg_wu_02_key_proposal_custody_owner_inert_key_creation(
    proposal: &StoreIntegrityKeyProposalV1,
) -> Result<(), SignerRefusalV2> {
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(proposal)
}

pub(crate) fn construct_sg_n_08_local_key_proposal_is_inert_carries_no(
    proposal: StoreIntegrityKeyProposalV1,
) -> Result<StoreIntegrityKeyProposalV1, SignerRefusalV2> {
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
    Ok(proposal)
}

pub(crate) fn verify_sg_n_08_local_key_proposal_is_inert_carries_no(
    proposal: &StoreIntegrityKeyProposalV1,
) -> Result<(), SignerRefusalV2> {
    let fields = proposal.fields();
    if proposal.0.schema != KEY_PROPOSAL_SCHEMA_V1
        || proposal.0.schema_version != 1
        || fields.algorithm != KEY_ALGORITHM_V1
        || fields.mode != "0400"
        || fields.link_count != 1
        || fields.proposal_ordinal == 0
        || fields.proposal_ordinal > IJSON_SAFE_INTEGER
        || fields.proposed_key_generation > IJSON_SAFE_INTEGER
        || !valid_resident_identity(&fields.resident_identity)
        || fields.resident_generation == 0
        || fields.resident_generation > IJSON_SAFE_INTEGER
        || fields.role_manifest_generation == 0
        || fields.role_manifest_generation > IJSON_SAFE_INTEGER
        || fields.signer_scope_policy_version == 0
        || fields.signer_scope_policy_version > IJSON_SAFE_INTEGER
        || fields.public_key.len() != 64
        || fields.custody_nonce.len() != 64
        || canonical_json_bytes(&proposal.0).is_err()
    {
        return Err(SignerRefusalV2::CustodyKeyMismatch);
    }
    let core = domain_digest(
        PROPOSAL_CORE_DOMAIN_V1,
        &ProposalCorePreimage {
            scope_token: &fields.scope_token,
            proposal_ordinal: fields.proposal_ordinal,
            proposed_key_generation: fields.proposed_key_generation,
            algorithm: KEY_ALGORITHM_V1,
            public_key: &fields.public_key,
            custody_nonce: &fields.custody_nonce,
            key_carrier_schema: PRIVATE_CUSTODY_SCHEMA_V1,
        },
    )?;
    let scope_token = domain_digest(
        SCOPE_DOMAIN_V1,
        &ScopeTokenPreimage {
            occurrence_id: &fields.occurrence_id,
            a2_chain_root_identity: &fields.a2_chain_root_identity,
            trust_anchor_identity: &fields.trust_anchor_identity,
            resident_identity: &fields.resident_identity,
            resident_generation: fields.resident_generation,
            host_role: &fields.host_role,
            role_manifest_generation: fields.role_manifest_generation,
            authority_domain: &fields.authority_domain,
            signer_scope_policy_identity: &fields.signer_scope_policy_identity,
            signer_scope_policy_version: fields.signer_scope_policy_version,
        },
    )?;
    let identity = domain_digest(PROPOSAL_ID_DOMAIN_V1, &fields.proposal_identity_preimage())?;
    if scope_token != fields.scope_token
        || core != fields.proposal_core_identity
        || identity != fields.proposal_identity
    {
        return Err(SignerRefusalV2::CustodyKeyMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_10_custody_root_path_are_fixed_by_implementation(
    coordinates: &PreGenerationCustodyCoordinatesV1,
) -> Result<PathBuf, SignerRefusalV2> {
    let scope = coordinates.scope_token()?;
    Ok(Path::new(STORE_INTEGRITY_CUSTODY_ROOT_V1).join(digest_hex(&scope)))
}

pub(crate) fn verify_sg_n_10_custody_root_path_are_fixed_by_implementation(
    coordinates: &PreGenerationCustodyCoordinatesV1,
    path: &Path,
) -> Result<(), SignerRefusalV2> {
    if construct_sg_n_10_custody_root_path_are_fixed_by_implementation(coordinates)? != path {
        return Err(SignerRefusalV2::CallerSelectedCustodyRoot);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_11_custody_file_creation_commit_uses_no_follow(
    file: StoreIntegrityCustodyFileV1,
) -> Result<StoreIntegrityCustodyFileV1, SignerRefusalV2> {
    verify_sg_n_11_custody_file_creation_commit_uses_no_follow(&file)?;
    Ok(file)
}

pub(crate) fn verify_sg_n_11_custody_file_creation_commit_uses_no_follow(
    file: &StoreIntegrityCustodyFileV1,
) -> Result<(), SignerRefusalV2> {
    let bytes = SecretBytes(file.encode()?);
    if StoreIntegrityCustodyFileV1::decode(&bytes)?.0 != file.0 {
        return Err(SignerRefusalV2::CustodyFileMalformed);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_13_uid_mode_inode_file_existence_key_possession(
    observation: CustodyObservationV1,
) -> CustodyObservationV1 {
    observation
}

pub(crate) fn verify_sg_n_13_uid_mode_inode_file_existence_key_possession(
    observation: &CustodyObservationV1,
) -> Result<(), SignerRefusalV2> {
    if observation.effective_uid != observation.owner_uid
        || observation.effective_gid != observation.owner_gid
        || observation.mode != 0o400
        || observation.device == 0
        || observation.mount == 0
        || observation.inode == 0
        || observation.link_count != 1
        || !observation.regular_file
        || !observation.exact_length
        || !observation.path_inode_matches
        || !observation.key_correspondence
    {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    Ok(())
}

pub(crate) fn construct_sg_rec_01a_inert_storeintegritykeyproposalv1_half_sg_rec_binds_occurrence(
    proposal: StoreIntegrityKeyProposalV1,
) -> Result<(StoreIntegrityKeyProposalV1, ProposalResultV2), SignerRefusalV2> {
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal)?;
    Ok((proposal, ProposalResultV2::InertProposalPersisted))
}

pub(crate) fn verify_sg_rec_01a_inert_storeintegritykeyproposalv1_half_sg_rec_binds_occurrence(
    proposal: &StoreIntegrityKeyProposalV1,
) -> Result<(), SignerRefusalV2> {
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(proposal)
}

pub(crate) fn construct_sg_rec_14_custody_file(
    file: StoreIntegrityCustodyFileV1,
) -> Result<StoreIntegrityCustodyFileV1, SignerRefusalV2> {
    construct_sg_n_11_custody_file_creation_commit_uses_no_follow(file)
}

pub(crate) fn verify_sg_rec_14_custody_file(
    file: &StoreIntegrityCustodyFileV1,
) -> Result<(), SignerRefusalV2> {
    verify_sg_n_11_custody_file_creation_commit_uses_no_follow(file)
}

#[cfg(test)]
pub(super) fn test_coordinates() -> PreGenerationCustodyCoordinatesV1 {
    let digest = |byte: char| {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    };
    PreGenerationCustodyCoordinatesV1 {
        occurrence_id: "occurrence-1".into(),
        scope_identity: digest('3'),
        a2_chain_root_identity: digest('4'),
        trust_anchor_identity: digest('5'),
        resident_identity: "resident/node-a".into(),
        resident_generation: 7,
        host_role: "nq.host.store".into(),
        role_manifest_generation: 8,
        authority_domain: "nq.store-integrity".into(),
        signer_scope_policy_identity: digest('9'),
        signer_scope_policy_version: 10,
        proposed_key_generation: 0,
        custodian_implementation_manifest_identity: digest('a'),
    }
}

#[cfg(test)]
fn test_public_fields(
    coordinates: &PreGenerationCustodyCoordinatesV1,
    scope_token: Sha256Digest,
    verifying_key: [u8; 32],
) -> CustodyPublicFieldsV1 {
    let nonce = hex::encode([0x5a; 32]);
    let public_key = hex::encode(verifying_key);
    let core = domain_digest(
        PROPOSAL_CORE_DOMAIN_V1,
        &ProposalCorePreimage {
            scope_token: &scope_token,
            proposal_ordinal: 1,
            proposed_key_generation: coordinates.proposed_key_generation,
            algorithm: KEY_ALGORITHM_V1,
            public_key: &public_key,
            custody_nonce: &nonce,
            key_carrier_schema: PRIVATE_CUSTODY_SCHEMA_V1,
        },
    )
    .unwrap();
    let directory_identity = sha256_bytes(b"test-only-scope-directory");
    let identity = domain_digest(
        PROPOSAL_ID_DOMAIN_V1,
        &ProposalIdentityPreimage {
            proposal_core_identity: &core,
            scope_directory_identity: &directory_identity,
            custody_file_device: 1,
            custody_file_mount: 2,
            custody_file_inode: 3,
            owner_uid: effective_uid(),
            owner_gid: effective_gid(),
            mode: "0400",
            link_count: 1,
        },
    )
    .unwrap();
    CustodyPublicFieldsV1 {
        proposal_core_identity: core,
        proposal_identity: identity,
        proposal_ordinal: 1,
        scope_token,
        occurrence_id: coordinates.occurrence_id.clone(),
        scope_identity: coordinates.scope_identity.clone(),
        a2_chain_root_identity: coordinates.a2_chain_root_identity.clone(),
        trust_anchor_identity: coordinates.trust_anchor_identity.clone(),
        resident_identity: coordinates.resident_identity.clone(),
        resident_generation: coordinates.resident_generation,
        host_role: coordinates.host_role.clone(),
        role_manifest_generation: coordinates.role_manifest_generation,
        authority_domain: coordinates.authority_domain.clone(),
        signer_scope_policy_identity: coordinates.signer_scope_policy_identity.clone(),
        signer_scope_policy_version: coordinates.signer_scope_policy_version,
        proposed_key_generation: coordinates.proposed_key_generation,
        algorithm: KEY_ALGORITHM_V1.into(),
        public_key,
        custody_nonce: nonce,
        scope_directory_identity: directory_identity,
        custody_file_device: 1,
        custody_file_mount: 2,
        custody_file_inode: 3,
        owner_uid: effective_uid(),
        owner_gid: effective_gid(),
        mode: "0400".into(),
        link_count: 1,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;
    use crate::store_generation::signer::messages::{
        SignerMessageCoordinatesV1,
        construct_msg_06_healthy_rotation_continuity_current_usable_predecessor,
    };
    use crate::store_generation::signer::records::construct_store_integrity_signer_foundation_v1;

    fn matching_message(
        custodian: &C2StoreIntegrityCustodian,
        coordinates: &PreGenerationCustodyCoordinatesV1,
    ) -> impl SignerMessageV1 {
        construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            SignerMessageCoordinatesV1 {
                occurrence: coordinates.occurrence_identity(),
                // This test-only sealed MSG-06 exercises descriptor custody,
                // not phase construction.  Use a coherent nonzero synthetic
                // generation-bound scope; the production signer path derives
                // both identities from the unforgeable live context.
                physical_generation: [6; 32],
                lifecycle_root: [7; 32],
                scope: coordinates.scope_bytes(),
                policy: coordinates.policy_bytes(),
                signer_key_generation: custodian.proposal.key_generation_identity(),
                cut: 8,
            },
            [9; 32],
            [10; 32],
        )
        .expect("valid message")
    }

    fn schema_keys(bytes: &str) -> (BTreeSet<String>, BTreeSet<String>) {
        let schema: serde_json::Value = serde_json::from_str(bytes).unwrap();
        let required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        let properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        (required, properties)
    }

    #[test]
    fn exact_schemas_match_the_canonical_public_and_private_carriers() {
        let proposal_schema =
            include_str!("../../../../../schemas/c2/nq.c2_store_integrity_key_proposal.v1.json");
        let custody_schema = include_str!(
            "../../../../../schemas/c2/nq.c2_store_integrity_private_key_custody.v1.json"
        );
        let private_keys = private_carrier_keys()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let public_keys = private_keys
            .iter()
            .filter(|key| {
                ![
                    "magic",
                    "private_seed",
                    "custodian_implementation_manifest_identity",
                    "payload_digest",
                ]
                .contains(&key.as_str())
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let (proposal_required, proposal_properties) = schema_keys(proposal_schema);
        let (custody_required, custody_properties) = schema_keys(custody_schema);
        assert_eq!(proposal_required, public_keys);
        assert_eq!(proposal_properties, public_keys);
        assert_eq!(custody_required, private_keys);
        assert_eq!(custody_properties, private_keys);
    }

    #[test]
    fn ordinary_successor_preparation_schema_matches_runtime_record() {
        let schema = include_str!(
            "../../../../../schemas/c2/nq.c2_store_integrity_ordinary_successor_custody_preparation.v1.json"
        );
        let expected = [
            "schema",
            "schema_version",
            "preparation_request_identity",
            "occurrence_id",
            "scope_identity",
            "predecessor_binding_identity",
            "predecessor_key_generation_identity",
            "transition_identity",
            "successor_proposal_identity",
            "successor_pop_challenge_identity",
            "successor_key_generation",
            "active_policy_identity",
            "active_policy_generation",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let (required, properties) = schema_keys(schema);
        assert_eq!(required, expected);
        assert_eq!(properties, expected);
        let digest = Sha256Digest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
        let runtime = serde_json::to_value(OrdinarySuccessorCustodyPreparationCarrierV1 {
            schema: ORDINARY_SUCCESSOR_CUSTODY_PREPARATION_SCHEMA_V1.to_owned(),
            schema_version: 1,
            preparation_request_identity: digest.clone(),
            occurrence_id: "occurrence-1".to_owned(),
            scope_identity: digest.clone(),
            predecessor_binding_identity: digest.clone(),
            predecessor_key_generation_identity: digest.clone(),
            transition_identity: digest.clone(),
            successor_proposal_identity: digest.clone(),
            successor_pop_challenge_identity: digest.clone(),
            successor_key_generation: 1,
            active_policy_identity: digest,
            active_policy_generation: 1,
        })
        .unwrap();
        let runtime = runtime
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(runtime, expected);
    }

    #[test]
    fn custody_refuses_invalid_raw_gen4_resident_coordinates() {
        assert!(valid_resident_identity("resident/node-a"));
        assert!(valid_resident_identity(&"é".repeat(512)));
        assert!(!valid_resident_identity("resident\nnode-a"));
        assert!(!valid_resident_identity(&"é".repeat(513)));

        let mut coordinates = test_coordinates();
        coordinates.resident_identity = "resident\nnode-a".to_owned();
        assert_eq!(
            coordinates.validate(),
            Err(SignerRefusalV2::CustodyPathMismatch)
        );
    }

    #[test]
    fn fixed_scope_path_cannot_be_selected_by_caller() {
        let coordinates = test_coordinates();
        let path = construct_sg_n_10_custody_root_path_are_fixed_by_implementation(&coordinates)
            .expect("valid scope path");
        assert!(path.starts_with(STORE_INTEGRITY_CUSTODY_ROOT_V1));
        assert_eq!(
            verify_sg_n_10_custody_root_path_are_fixed_by_implementation(
                &coordinates,
                Path::new("/tmp/attacker")
            ),
            Err(SignerRefusalV2::CallerSelectedCustodyRoot)
        );
    }

    #[test]
    fn private_signing_surface_accepts_only_matching_sealed_message() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_test_root(
            coordinates.clone(),
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let message = matching_message(&custodian, &coordinates);
        let signature = custodian
            .sign_for_custody_hostile_test(CoordinatorSigningPermitV1::for_test(), &message)
            .expect("typed signing succeeds");
        assert_eq!(
            signature.family,
            ClosedMessageFamilyV1::Msg06NormalRotationContinuity
        );
        assert_eq!(
            signature.signer_key_generation,
            custodian.proposal.key_generation_identity()
        );
    }

    #[test]
    fn canonical_private_codec_rejects_unknown_and_mutated_fields() {
        let coordinates = test_coordinates();
        let seed = [7; 32];
        let fields = test_public_fields(
            &coordinates,
            coordinates.scope_token().unwrap(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        );
        let mut carrier = StoreIntegrityCustodyCarrierV1 {
            schema: PRIVATE_CUSTODY_SCHEMA_V1.into(),
            schema_version: 1,
            fields,
            magic: PRIVATE_CUSTODY_MAGIC_V1.into(),
            private_seed: hex::encode(seed),
            custodian_implementation_manifest_identity: coordinates
                .custodian_implementation_manifest_identity
                .clone(),
            payload_digest: sha256_bytes(b"placeholder"),
        };
        carrier.payload_digest = StoreIntegrityCustodyFileV1::payload_digest(&carrier).unwrap();
        let file = StoreIntegrityCustodyFileV1(carrier);
        let bytes = file.encode().unwrap();
        assert_eq!(
            StoreIntegrityCustodyFileV1::decode(&bytes).unwrap().0,
            file.0
        );
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unexpected"] = serde_json::json!(true);
        let changed = canonical_json_bytes(&value).unwrap();
        assert_eq!(
            StoreIntegrityCustodyFileV1::decode(&changed),
            Err(SignerRefusalV2::CustodyFileMalformed)
        );

        let mut mutated_fields = file.0.fields.clone();
        mutated_fields.a2_chain_root_identity =
            Sha256Digest::parse(format!("sha256:{}", "b".repeat(64))).unwrap();
        let mut spliced = StoreIntegrityCustodyCarrierV1 {
            schema: PRIVATE_CUSTODY_SCHEMA_V1.into(),
            schema_version: 1,
            fields: mutated_fields,
            magic: PRIVATE_CUSTODY_MAGIC_V1.into(),
            private_seed: hex::encode(seed),
            custodian_implementation_manifest_identity: coordinates
                .custodian_implementation_manifest_identity
                .clone(),
            payload_digest: sha256_bytes(b"placeholder"),
        };
        spliced.payload_digest = StoreIntegrityCustodyFileV1::payload_digest(&spliced).unwrap();
        let spliced_bytes = canonical_json_bytes(&spliced).unwrap();
        assert_eq!(
            StoreIntegrityCustodyFileV1::decode(&spliced_bytes),
            Err(SignerRefusalV2::CustodyKeyMismatch)
        );
    }

    #[test]
    fn no_replace_commit_reopens_same_inode_at_mode_0400() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root_file = File::open(root.path()).unwrap();
        let coordinates = test_coordinates();
        let frontier =
            VerifiedCustodyProposalFrontierV1::initial_for_test(coordinates.scope_token().unwrap());
        let (custodian, proposal) =
            C2StoreIntegrityCustodian::create_below_root(coordinates, &frontier, root_file)
                .expect("exact custody commit");
        let directory = &custodian.scope_directory;
        let final_file = open_final_key(directory, &custodian.final_name).unwrap();
        let facts = object_facts(&final_file).unwrap();
        assert_eq!(facts.mode, 0o400);
        assert_eq!(facts.inode, proposal.fields().custody_file_inode);
        assert_eq!(facts.link_count, 1);
        assert!(matches!(
            C2StoreIntegrityCustodian::create_below_root(
                test_coordinates(),
                &frontier,
                File::open(root.path()).unwrap(),
            ),
            Err(SignerRefusalV2::CustodyPathMismatch)
        ));
    }

    #[test]
    fn generation_current_custody_requires_exact_stable_foundation_coordinates() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut coordinates = test_coordinates();
        coordinates.proposed_key_generation = 1;
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_test_root(
            coordinates,
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let foundational = custodian.seal_reopened_foundational_custody().unwrap();
        let exact = construct_store_integrity_signer_foundation_v1(
            foundational.public_key(),
            foundational.key_generation(),
            foundational.custody_evidence_identity().clone(),
        )
        .unwrap();
        drop(foundational);

        let verified = custodian
            .verify_generation_current_foundation_custody(&exact)
            .unwrap();
        assert_eq!(verified.foundation_identity(), exact.identity());
        assert_eq!(verified.public_key(), exact.public_key().unwrap());
        assert_eq!(verified.key_generation(), exact.key_generation());
        assert_eq!(
            verified.custody_evidence_identity(),
            exact.custody_evidence_identity()
        );
        assert_eq!(
            verified.foundational_custody().proposal_identity(),
            exact.custody_evidence_identity()
        );
        verified.verify_same_process().unwrap();
        drop(verified);

        let wrong_public_key = construct_store_integrity_signer_foundation_v1(
            SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes(),
            exact.key_generation(),
            exact.custody_evidence_identity().clone(),
        )
        .unwrap();
        assert!(matches!(
            custodian.verify_generation_current_foundation_custody(&wrong_public_key),
            Err(SignerRefusalV2::CustodyKeyMismatch)
        ));

        let wrong_generation = construct_store_integrity_signer_foundation_v1(
            exact.public_key().unwrap(),
            exact.key_generation() + 1,
            exact.custody_evidence_identity().clone(),
        )
        .unwrap();
        assert!(matches!(
            custodian.verify_generation_current_foundation_custody(&wrong_generation),
            Err(SignerRefusalV2::CustodyKeyMismatch)
        ));

        let wrong_custody = construct_store_integrity_signer_foundation_v1(
            exact.public_key().unwrap(),
            exact.key_generation(),
            sha256_bytes(b"substituted-custody-evidence"),
        )
        .unwrap();
        assert!(matches!(
            custodian.verify_generation_current_foundation_custody(&wrong_custody),
            Err(SignerRefusalV2::CustodyKeyMismatch)
        ));
    }

    #[test]
    fn filesystem_first_crash_cut_reconciles_exact_carrier_without_second_key() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let scope_token = coordinates.scope_token().unwrap();
        let frontier = VerifiedCustodyProposalFrontierV1::initial_for_test(scope_token.clone());
        let (first_process, proposal) = C2StoreIntegrityCustodian::create_below_root(
            coordinates.clone(),
            &frontier,
            File::open(root.path()).unwrap(),
        )
        .expect("filesystem-first carrier is durably committed");
        let proposal_identity = proposal.proposal_identity().clone();
        drop(first_process);

        // This models the cut after carrier fsync/rename but before the Store
        // preparation row commits. Reconciliation must reopen exactly that
        // carrier and must not generate a second proposal.
        let (reconciled, reconciled_proposal) =
            C2StoreIntegrityCustodian::reconcile_filesystem_first_below_root(
                coordinates,
                &frontier,
                File::open(root.path()).unwrap(),
            )
            .expect("exact missing Store row reconciles from the committed carrier");
        assert_eq!(reconciled_proposal.proposal_identity(), &proposal_identity);
        assert_eq!(reconciled.proposal_identity(), &proposal_identity);
        assert_eq!(
            scope_directory_committed_proposal_identities(&reconciled.scope_directory).unwrap(),
            BTreeSet::from([proposal_identity]),
        );
    }

    #[test]
    fn exact_frontier_refuses_same_count_proposal_name_substitution() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let scope_token = coordinates.scope_token().unwrap();
        let initial = VerifiedCustodyProposalFrontierV1::initial_for_test(scope_token.clone());
        let (custodian, proposal) = C2StoreIntegrityCustodian::create_below_root(
            coordinates.clone(),
            &initial,
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let committed = proposal.proposal_identity().clone();
        let scope_path = root.path().join(digest_hex(&scope_token));
        let substituted = format!("{}.key", "a".repeat(64));
        std::fs::rename(
            scope_path.join(&custodian.final_name),
            scope_path.join(&substituted),
        )
        .unwrap();
        drop(custodian);

        let frontier = VerifiedCustodyProposalFrontierV1 {
            scope_token,
            next_ordinal: 2,
            complete_frontier_identity: sha256_bytes(b"store-resolved-frontier-after-one"),
            committed_proposals: BTreeMap::from([(1, committed)]),
        };
        let mut successor_coordinates = coordinates;
        successor_coordinates.proposed_key_generation = 1;
        assert_eq!(
            C2StoreIntegrityCustodian::create_below_root(
                successor_coordinates,
                &frontier,
                File::open(root.path()).unwrap(),
            )
            .unwrap_err(),
            SignerRefusalV2::CustodyPathMismatch,
        );
        assert_eq!(std::fs::read_dir(scope_path).unwrap().count(), 1);
    }

    #[test]
    fn exact_frontier_refuses_same_name_replacement_inode() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let scope_token = coordinates.scope_token().unwrap();
        let initial = VerifiedCustodyProposalFrontierV1::initial_for_test(scope_token.clone());
        let (custodian, proposal) = C2StoreIntegrityCustodian::create_below_root(
            coordinates.clone(),
            &initial,
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let committed = proposal.proposal_identity().clone();
        let scope_path = root.path().join(digest_hex(&scope_token));
        let carrier_path = scope_path.join(&custodian.final_name);
        let bytes = std::fs::read(&carrier_path).unwrap();
        drop(custodian);
        // Retain the displaced inode so the filesystem cannot immediately
        // recycle its number for the replacement and make this hostile
        // specimen allocator-dependent.
        let displaced_inode = File::open(&carrier_path).unwrap();
        std::fs::remove_file(&carrier_path).unwrap();
        std::fs::write(&carrier_path, bytes).unwrap();
        std::fs::set_permissions(&carrier_path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let frontier = VerifiedCustodyProposalFrontierV1 {
            scope_token,
            next_ordinal: 2,
            complete_frontier_identity: sha256_bytes(b"store-resolved-frontier-after-one"),
            committed_proposals: BTreeMap::from([(1, committed)]),
        };
        let mut successor_coordinates = coordinates;
        successor_coordinates.proposed_key_generation = 1;
        assert!(matches!(
            C2StoreIntegrityCustodian::create_below_root(
                successor_coordinates,
                &frontier,
                File::open(root.path()).unwrap(),
            ),
            Err(SignerRefusalV2::CustodyFileUnsafe)
        ));
        assert_eq!(std::fs::read_dir(scope_path).unwrap().count(), 1);
        drop(displaced_inode);
    }

    #[test]
    fn nonconforming_root_refuses_without_chmod_or_creation() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let coordinates = test_coordinates();
        let frontier =
            VerifiedCustodyProposalFrontierV1::initial_for_test(coordinates.scope_token().unwrap());
        assert!(matches!(
            C2StoreIntegrityCustodian::create_below_root(
                coordinates,
                &frontier,
                File::open(root.path()).unwrap(),
            ),
            Err(SignerRefusalV2::CustodyFileUnsafe)
        ));
        assert_eq!(
            std::fs::symlink_metadata(root.path()).unwrap().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn hard_link_added_after_commit_refuses_signing() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let scope_token = coordinates.scope_token().unwrap();
        let frontier = VerifiedCustodyProposalFrontierV1::initial_for_test(scope_token.clone());
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_root(
            coordinates.clone(),
            &frontier,
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let scope_path = root.path().join(digest_hex(&scope_token));
        std::fs::hard_link(
            scope_path.join(&custodian.final_name),
            scope_path.join("attacker-alias.key"),
        )
        .unwrap();
        let message = matching_message(&custodian, &coordinates);
        assert_eq!(
            custodian
                .sign_for_custody_hostile_test(CoordinatorSigningPermitV1::for_test(), &message,),
            Err(SignerRefusalV2::CustodyFileUnsafe)
        );
    }

    #[test]
    fn identical_bytes_on_replacement_inode_refuse_signing() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let scope_token = coordinates.scope_token().unwrap();
        let frontier = VerifiedCustodyProposalFrontierV1::initial_for_test(scope_token.clone());
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_root(
            coordinates.clone(),
            &frontier,
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let scope_path = root.path().join(digest_hex(&scope_token));
        let final_path = scope_path.join(&custodian.final_name);
        let original_bytes = std::fs::read(&final_path).unwrap();
        std::fs::rename(&final_path, scope_path.join("displaced-original.key")).unwrap();
        std::fs::write(&final_path, original_bytes).unwrap();
        std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let message = matching_message(&custodian, &coordinates);
        assert_eq!(
            custodian
                .sign_for_custody_hostile_test(CoordinatorSigningPermitV1::for_test(), &message,),
            Err(SignerRefusalV2::CustodyFileUnsafe)
        );
    }

    #[test]
    fn fork_fence_is_released_after_successful_creation() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_test_root(
            test_coordinates(),
            File::open(root.path()).unwrap(),
        )
        .expect("creation succeeds");
        drop(custodian);
        let guard = C2ForkFence::acquire().expect("fence is free after successful creation");
        guard.verify_same_process().expect("same process");
    }

    #[test]
    fn fork_fence_is_released_after_refused_creation_and_signing() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let scope_token = coordinates.scope_token().unwrap();
        let frontier = VerifiedCustodyProposalFrontierV1::initial_for_test(scope_token.clone());
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_root(
            coordinates.clone(),
            &frontier,
            File::open(root.path()).unwrap(),
        )
        .expect("first creation succeeds");
        // The occupied scope directory refuses regeneration.
        assert!(matches!(
            C2StoreIntegrityCustodian::create_below_root(
                test_coordinates(),
                &frontier,
                File::open(root.path()).unwrap(),
            ),
            Err(SignerRefusalV2::CustodyPathMismatch)
        ));
        // A hard-linked alias refuses signing after the fence is acquired.
        let scope_path = root.path().join(digest_hex(&scope_token));
        std::fs::hard_link(
            scope_path.join(&custodian.final_name),
            scope_path.join("attacker-alias.key"),
        )
        .unwrap();
        let message = matching_message(&custodian, &coordinates);
        assert_eq!(
            custodian
                .sign_for_custody_hostile_test(CoordinatorSigningPermitV1::for_test(), &message,),
            Err(SignerRefusalV2::CustodyFileUnsafe)
        );
        let guard = C2ForkFence::acquire().expect("fence is free after refusals");
        guard.verify_same_process().expect("same process");
    }

    #[test]
    fn fork_fence_serializes_cross_thread_acquisition() {
        let guard = C2ForkFence::acquire().expect("main thread acquires the fence");
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = C2ForkFence::acquire().expect("worker eventually acquires");
            sender.send(()).expect("main thread waits");
            drop(acquired);
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(250))
                .is_err(),
            "second thread acquired the fence while the first thread held it"
        );
        drop(guard);
        receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("second thread acquires after release");
        worker.join().expect("worker thread joins");
    }

    #[test]
    fn fenced_custody_paths_refuse_same_thread_reentrancy() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_test_root(
            coordinates.clone(),
            File::open(root.path()).unwrap(),
        )
        .expect("creation succeeds");
        let message = matching_message(&custodian, &coordinates);
        let guard = C2ForkFence::acquire().expect("main thread acquires the fence");
        // The fence is acquired at the top of the fenced paths, so a
        // reentrant attempt fails closed at the fence before touching any
        // custody lock, rather than deadlocking.
        assert!(matches!(
            C2StoreIntegrityCustodian::create_below_test_root(
                test_coordinates(),
                File::open(root.path()).unwrap(),
            ),
            Err(SignerRefusalV2::CustodyIo)
        ));
        assert_eq!(
            custodian
                .sign_for_custody_hostile_test(CoordinatorSigningPermitV1::for_test(), &message,),
            Err(SignerRefusalV2::CustodyIo)
        );
        drop(guard);
        let guard = C2ForkFence::acquire().expect("fence is free after reentrant refusals");
        guard.verify_same_process().expect("same process");
    }

    #[test]
    fn custody_creation_provenance_is_distinct_from_restore_adoption_lineage() {
        for creation in [
            "initialExternal",
            "ordinarySuccessorContinuity",
            "recoveryNewFoundation",
        ] {
            assert_eq!(
                verify_stable_foundation_creation_lineage_for_adoption_v1(
                    creation,
                    FoundationalAdoptionLineageV1::RestoreHistorical,
                )
                .expect("restore reuses an exact legally created foundation")
                .as_str(),
                creation
            );
        }
        assert_eq!(
            verify_stable_foundation_creation_lineage_for_adoption_v1(
                "restoreHistorical",
                FoundationalAdoptionLineageV1::RestoreHistorical,
            ),
            Err(SignerRefusalV2::CustodyPathMismatch)
        );
    }

    #[test]
    fn nonrestore_adoption_requires_its_exact_custody_creation_lineage() {
        let cases = [
            (
                FoundationalAdoptionLineageV1::InitialExternal,
                "initialExternal",
            ),
            (
                FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
                "ordinarySuccessorContinuity",
            ),
            (
                FoundationalAdoptionLineageV1::RecoveryNewFoundation,
                "recoveryNewFoundation",
            ),
        ];
        for (adoption, expected) in cases {
            for actual in [
                "initialExternal",
                "ordinarySuccessorContinuity",
                "recoveryNewFoundation",
            ] {
                let result =
                    verify_stable_foundation_creation_lineage_for_adoption_v1(actual, adoption);
                assert_eq!(result.is_ok(), actual == expected);
            }
        }
    }

    #[test]
    fn route_aware_frontier_accepts_ordinary_successor_without_bootstrap_request() {
        let digest = |byte: char| {
            Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
        };
        let mut coordinates = test_coordinates();
        coordinates.proposed_key_generation = 1;
        let scope_token = coordinates.scope_token().unwrap();
        let fields = test_public_fields(
            &coordinates,
            scope_token.clone(),
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        );
        let proposal = StoreIntegrityKeyProposalV1(StoreIntegrityKeyProposalCarrierV1 {
            schema: KEY_PROPOSAL_SCHEMA_V1.to_owned(),
            schema_version: 1,
            fields,
        });
        verify_sg_n_08_local_key_proposal_is_inert_carries_no(&proposal).unwrap();
        let request = StoreOrdinarySuccessorCustodyPreparationRequestV1::construct(
            coordinates.occurrence_id.clone(),
            coordinates.scope_identity.clone(),
            digest('b'),
            digest('c'),
            digest('d'),
            &proposal,
            digest('e'),
            digest('f'),
            2,
        )
        .unwrap();
        let proposal_bytes = proposal.canonical_bytes().unwrap();
        let request_bytes = request.canonical_bytes().unwrap();
        let predecessor = digest_fields_v1(
            C2_CUSTODY_EMPTY_FRONTIER_DOMAIN_V1,
            &[scope_token.as_str().as_bytes()],
        );
        let proposal_sha = sha256_bytes(&proposal_bytes);
        let request_sha = sha256_bytes(&request_bytes);
        let resulting = digest_fields_v1(
            C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1,
            &[
                predecessor.as_str().as_bytes(),
                &1_u64.to_be_bytes(),
                proposal.proposal_identity().as_str().as_bytes(),
                request.identity().as_str().as_bytes(),
                proposal_sha.as_str().as_bytes(),
                request_sha.as_str().as_bytes(),
            ],
        );
        let row = StoreCustodyProposalFrontierRowV1::ordinary_successor(
            1,
            predecessor,
            resulting.clone(),
            proposal.proposal_identity().clone(),
            proposal_bytes.clone(),
            proposal_sha,
            proposal_bytes.len() as u64,
            request,
            request_sha,
            request_bytes.len() as u64,
        )
        .unwrap();
        let (next, resolved, committed) =
            resolve_store_custody_proposal_frontier_rows_v1(&scope_token, [row.clone()]).unwrap();
        assert_eq!(next, 2);
        assert_eq!(resolved, resulting);
        assert_eq!(committed.get(&1), Some(proposal.proposal_identity()));

        let mut collision = row;
        collision.resulting_frontier_identity = digest('1');
        assert_eq!(
            resolve_store_custody_proposal_frontier_rows_v1(&scope_token, [collision]),
            Err(SignerRefusalV2::EnrollmentEvidenceCollision)
        );
    }

    #[test]
    fn schema_closes_custody_creation_lineages_and_recovery_ordinal_law() {
        let canonical = include_str!("../../schema.sql");
        let migration = include_str!("../../../migrations/v9_c2_signer_lineage.sql");
        for sql in [canonical, migration] {
            let preparation_start = sql
                .find("CREATE TABLE c2_custody_proposal_preparations")
                .expect("custody preparation table exists");
            let preparation_end = sql[preparation_start..]
                .find("CREATE TRIGGER immutable_c2_custody_proposal_preparations_update")
                .map(|offset| preparation_start + offset)
                .expect("custody preparation table closes before trigger");
            let preparation = &sql[preparation_start..preparation_end];
            assert!(preparation.contains("'ordinarySuccessorContinuity'"));
            assert!(preparation.contains("'recoveryNewFoundation'"));
            assert!(
                !preparation.contains("'restoreHistorical'"),
                "restore must reuse historical custody rather than create a row"
            );

            let recovery_check = sql
                .find("(binding_mode = 'recovery_successor'")
                .expect("recovery current-binding check exists");
            let recovery_check = &sql[recovery_check..][..500.min(sql.len() - recovery_check)];
            assert!(recovery_check.contains("current_key_generation >= 0"));
            assert!(!recovery_check.contains("current_key_generation > 0"));
        }
    }
}
