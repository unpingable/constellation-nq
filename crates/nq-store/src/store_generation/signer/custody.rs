//! Purpose-locked Store-integrity signer custody.
//!
//! Production custody is rooted at one literal directory, resolves children
//! through retained descriptors, commits canonical private carriers with a
//! no-replace rename, and exposes signing only to the private typed
//! coordinator.  Filesystem possession is never converted into standing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ed25519_dalek::{Signer as _, SigningKey};
use nix::fcntl::{Flock, FlockArg};
use nq_helper_sandbox::enter_c2_secret_process_interval;
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, RenameFlags, StatxFlags, fchmod, fdatasync, flistxattr, fsync,
    mkdirat, open, openat, renameat_with, statx,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::coordinator::CoordinatorSigningPermitV1;
use super::messages::{ClosedMessageFamilyV1, SignerIdentityV1, SignerMessageV1};
use super::result::{ProposalResultV2, SignerRefusalV2};

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
const IJSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Complete non-secret coordinates fixed before key creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CustodyCoordinatesV1 {
    pub(crate) occurrence_id: String,
    pub(crate) physical_store_generation_identity: Sha256Digest,
    pub(crate) signer_lifecycle_root_identity: Sha256Digest,
    pub(crate) scope_identity: Sha256Digest,
    pub(crate) a2_chain_root_identity: Sha256Digest,
    pub(crate) trust_anchor_identity: Sha256Digest,
    pub(crate) resident_identity: Sha256Digest,
    pub(crate) resident_generation: u64,
    pub(crate) host_role: String,
    pub(crate) role_manifest_generation: u64,
    pub(crate) authority_domain: String,
    pub(crate) signer_scope_policy_identity: Sha256Digest,
    pub(crate) signer_scope_policy_version: u64,
    pub(crate) proposed_key_generation: u64,
    pub(crate) custodian_implementation_manifest_identity: Sha256Digest,
}

impl CustodyCoordinatesV1 {
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

    fn scope_token(&self) -> Result<Sha256Digest, SignerRefusalV2> {
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

    pub(super) fn physical_generation_bytes(&self) -> SignerIdentityV1 {
        digest_bytes(&self.physical_store_generation_identity)
    }

    pub(super) fn lifecycle_root_bytes(&self) -> SignerIdentityV1 {
        digest_bytes(&self.signer_lifecycle_root_identity)
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
    resident_identity: &'a Sha256Digest,
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
    physical_store_generation_identity: Sha256Digest,
    signer_lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    a2_chain_root_identity: Sha256Digest,
    trust_anchor_identity: Sha256Digest,
    resident_identity: Sha256Digest,
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

fn private_carrier_keys() -> [&'static str; 35] {
    [
        "schema",
        "schema_version",
        "proposal_core_identity",
        "proposal_identity",
        "proposal_ordinal",
        "scope_token",
        "occurrence_id",
        "physical_store_generation_identity",
        "signer_lifecycle_root_identity",
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
pub(super) struct VerifiedCustodyProposalFrontierV1 {
    scope_token: Sha256Digest,
    next_ordinal: u64,
    complete_frontier_identity: Sha256Digest,
}

impl VerifiedCustodyProposalFrontierV1 {
    #[cfg(test)]
    fn initial_for_test(scope_token: Sha256Digest) -> Self {
        Self {
            scope_token,
            next_ordinal: 1,
            complete_frontier_identity: sha256_bytes(b"test-only-empty-custody-frontier"),
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
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(self.next_ordinal)
    }
}

/// Purpose-locked private owner of one Store-integrity key generation.
pub(crate) struct C2StoreIntegrityCustodian {
    coordinates: CustodyCoordinatesV1,
    proposal: StoreIntegrityKeyProposalV1,
    scope_directory: File,
    final_name: String,
    creator_pid: u32,
    process_epoch: SignerIdentityV1,
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
    pub(super) fn create(
        coordinates: CustodyCoordinatesV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        let root = open_production_custody_root()?;
        Self::create_below_root(coordinates, frontier, root)
    }

    fn create_below_root(
        coordinates: CustodyCoordinatesV1,
        frontier: &VerifiedCustodyProposalFrontierV1,
        root: File,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        coordinates.validate()?;
        let scope_token = coordinates.scope_token()?;
        let proposal_ordinal = frontier.verify_for(&scope_token)?;
        let scope_mutex = custody_scope_mutex(&scope_token);
        let _scope_guard = scope_mutex.lock().map_err(|_| SignerRefusalV2::CustodyIo)?;
        let scope_directory = open_or_create_scope_directory(&root, &scope_token)?;
        if proposal_ordinal != 1 || !scope_directory_is_empty(&scope_directory)? {
            // Later ordinals require the complete Store/frontier join.  Until
            // that actor-owned resolver is connected, refuse rather than
            // regenerate, sort, or select a file by name.
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
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

        // From the first private random byte through carrier zeroization, no
        // production helper process may be created from this address space.
        let secret_process_guard =
            enter_c2_secret_process_interval().map_err(|_| SignerRefusalV2::CustodyIo)?;

        let mut seed = [0_u8; 32];
        let mut nonce = [0_u8; 32];
        let mut process_epoch = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| SignerRefusalV2::CustodyIo)?;
        getrandom::fill(&mut nonce).map_err(|_| SignerRefusalV2::CustodyIo)?;
        getrandom::fill(&mut process_epoch).map_err(|_| SignerRefusalV2::CustodyIo)?;
        let seed = SecretSeedV1(seed);
        let verifying_key = SigningKey::from_bytes(&seed.0).verifying_key().to_bytes();
        let public_key = hex::encode(verifying_key);
        let nonce_hex = hex::encode(nonce);
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
            physical_store_generation_identity: coordinates
                .physical_store_generation_identity
                .clone(),
            signer_lifecycle_root_identity: coordinates.signer_lifecycle_root_identity.clone(),
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
        let mut bytes = private_file.encode()?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.set_len(bytes.len() as u64))
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        fchmod(&temporary, Mode::RUSR).map_err(|_| SignerRefusalV2::CustodyIo)?;
        fdatasync(&temporary).map_err(|_| SignerRefusalV2::CustodyIo)?;
        let committed_facts = object_facts(&temporary)?;
        verify_file_facts_against_fields(&committed_facts, private_file.0.fields(), bytes.len())?;
        if read_exact_bytes(&temporary)? != bytes
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
        let final_file = open_final_key(&scope_directory, &final_name)?;
        let final_facts = object_facts(&final_file)?;
        if final_facts != committed_facts || read_exact_bytes(&final_file)? != bytes {
            return Err(SignerRefusalV2::CustodyFileUnsafe);
        }
        bytes.fill(0);
        drop(private_file);
        drop(seed);
        secret_process_guard
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
        Ok((custodian, proposal))
    }

    pub(super) fn proposal_identity(&self) -> &Sha256Digest {
        self.proposal.proposal_identity()
    }

    pub(super) fn coordinates(&self) -> &CustodyCoordinatesV1 {
        &self.coordinates
    }

    pub(super) fn verifying_key(&self) -> Result<[u8; 32], SignerRefusalV2> {
        decode_hex_32(&self.proposal.fields().public_key)
    }

    pub(super) fn key_generation_identity(&self) -> SignerIdentityV1 {
        self.proposal.key_generation_identity()
    }

    /// Private typed signing helper; the sealed message trait excludes raw
    /// bytes and external-governance carriers.
    pub(super) fn sign<M: SignerMessageV1>(
        &self,
        _permit: CoordinatorSigningPermitV1,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        if std::process::id() != self.creator_pid
            || self.process_epoch.iter().all(|byte| *byte == 0)
            || !message.family().is_store_signable()
            || message.coordinates().occurrence != self.coordinates.occurrence_identity()
            || message.coordinates().physical_generation
                != self.coordinates.physical_generation_bytes()
            || message.coordinates().lifecycle_root != self.coordinates.lifecycle_root_bytes()
            || message.coordinates().scope != self.coordinates.scope_bytes()
            || message.coordinates().policy != self.coordinates.policy_bytes()
            || message.coordinates().signer_key_generation
                != self.proposal.key_generation_identity()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        let secret_process_guard =
            enter_c2_secret_process_interval().map_err(|_| SignerRefusalV2::CustodyIo)?;
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
        secret_process_guard
            .verify_same_process()
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        Ok(CustodySignatureV1 {
            family: message.family(),
            signer_key_generation: self.proposal.key_generation_identity(),
            payload_digest,
            signature,
        })
    }

    fn load_seed_for_signing(
        &self,
    ) -> Result<(SecretSeedV1, Flock<File>, CustodyObjectFactsV1), SignerRefusalV2> {
        let file = open_final_key(&self.scope_directory, &self.final_name)?;
        let flock = Flock::lock(file, FlockArg::LockSharedNonblock)
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        let facts = object_facts(&flock)?;
        let bytes = read_exact_bytes(&flock)?;
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
        coordinates: CustodyCoordinatesV1,
        root: File,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        let frontier =
            VerifiedCustodyProposalFrontierV1::initial_for_test(coordinates.scope_token()?);
        Self::create_below_root(coordinates, &frontier, root)
    }
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

fn custody_scope_mutex(scope_token: &Sha256Digest) -> &'static Mutex<()> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, &'static Mutex<()>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry.lock().expect("custody mutex registry poisoned");
    *registry
        .entry(scope_token.as_str().to_owned())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
}

fn open_production_custody_root() -> Result<File, SignerRefusalV2> {
    let filesystem_root = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    );
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
    Ok(File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    ))
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
        Ok(()) => fsync(root).map_err(|_| SignerRefusalV2::CustodyIo)?,
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
    Ok(File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?,
    ))
}

fn scope_directory_is_empty(directory: &File) -> Result<bool, SignerRefusalV2> {
    let mut reader = Dir::read_from(directory).map_err(|_| SignerRefusalV2::CustodyIo)?;
    for entry in &mut reader {
        let entry = entry.map_err(|_| SignerRefusalV2::CustodyIo)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Ok(true)
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
    coordinates: &CustodyCoordinatesV1,
) -> Result<PathBuf, SignerRefusalV2> {
    let scope = coordinates.scope_token()?;
    Ok(Path::new(STORE_INTEGRITY_CUSTODY_ROOT_V1).join(digest_hex(&scope)))
}

pub(crate) fn verify_sg_n_10_custody_root_path_are_fixed_by_implementation(
    coordinates: &CustodyCoordinatesV1,
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
    let bytes = file.encode()?;
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
pub(super) fn test_coordinates() -> CustodyCoordinatesV1 {
    let digest = |byte: char| {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    };
    CustodyCoordinatesV1 {
        occurrence_id: "occurrence-1".into(),
        physical_store_generation_identity: digest('1'),
        signer_lifecycle_root_identity: digest('2'),
        scope_identity: digest('3'),
        a2_chain_root_identity: digest('4'),
        trust_anchor_identity: digest('5'),
        resident_identity: digest('6'),
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
    coordinates: &CustodyCoordinatesV1,
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
        physical_store_generation_identity: coordinates.physical_store_generation_identity.clone(),
        signer_lifecycle_root_identity: coordinates.signer_lifecycle_root_identity.clone(),
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

    fn matching_message(
        custodian: &C2StoreIntegrityCustodian,
        coordinates: &CustodyCoordinatesV1,
    ) -> impl SignerMessageV1 {
        construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            SignerMessageCoordinatesV1 {
                occurrence: coordinates.occurrence_identity(),
                physical_generation: coordinates.physical_generation_bytes(),
                lifecycle_root: coordinates.lifecycle_root_bytes(),
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
            .sign(CoordinatorSigningPermitV1::for_test(), &message)
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
            custodian.sign(CoordinatorSigningPermitV1::for_test(), &message),
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
            custodian.sign(CoordinatorSigningPermitV1::for_test(), &message),
            Err(SignerRefusalV2::CustodyFileUnsafe)
        );
    }
}
