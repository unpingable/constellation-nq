//! Purpose-locked Store-integrity signer custody.
//!
//! The authority-bearing custodian is crate-private, owns one exact key
//! generation, derives its path below a fixed root, and signs only sealed
//! family-branded messages.  It exposes neither private bytes nor a generic
//! signing trait.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use nix::unistd::geteuid;
use sha2::{Digest as _, Sha256};

use super::messages::{ClosedMessageFamilyV1, SignerIdentityV1, SignerMessageV1};
use super::result::{ProposalResultV2, SignerRefusalV2};

pub(crate) const STORE_INTEGRITY_CUSTODY_ROOT_V1: &str = "/var/lib/nq/store-integrity-custody.v1";
const CUSTODY_MAGIC_V1: &[u8; 8] = b"NQC2KEY1";
const CUSTODY_VERSION_V1: u16 = 1;
const CUSTODY_FILE_LENGTH_V1: usize = 8 + 2 + 32 * 10;

/// Exact coordinates used both for custody path derivation and key-file
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CustodyCoordinatesV1 {
    pub(crate) occurrence: SignerIdentityV1,
    pub(crate) physical_generation: SignerIdentityV1,
    pub(crate) lifecycle_root: SignerIdentityV1,
    pub(crate) signer_scope: SignerIdentityV1,
    pub(crate) policy: SignerIdentityV1,
    pub(crate) key_generation: SignerIdentityV1,
}

impl CustodyCoordinatesV1 {
    fn validate(&self) -> Result<(), SignerRefusalV2> {
        if [
            self.occurrence,
            self.physical_generation,
            self.lifecycle_root,
            self.signer_scope,
            self.policy,
            self.key_generation,
        ]
        .iter()
        .any(|identity| identity.iter().all(|byte| *byte == 0))
        {
            return Err(SignerRefusalV2::CustodyPathMismatch);
        }
        Ok(())
    }

    fn path_identity(&self) -> SignerIdentityV1 {
        let mut hash = Sha256::new();
        hash.update(b"nq.c2.store-integrity-custody-path.v1\0");
        hash.update(self.occurrence);
        hash.update(self.physical_generation);
        hash.update(self.lifecycle_root);
        hash.update(self.signer_scope);
        hash.update(self.policy);
        hash.update(self.key_generation);
        hash.finalize().into()
    }
}

/// Inert key proposal.  Possession of this value confers no standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreIntegrityKeyProposalV1 {
    pub(crate) coordinates: CustodyCoordinatesV1,
    pub(crate) proposal_identity: SignerIdentityV1,
    pub(crate) custody_nonce: SignerIdentityV1,
    pub(crate) verifying_key: [u8; 32],
}

/// Canonical fixed-format custody file.
#[derive(PartialEq, Eq)]
pub(crate) struct StoreIntegrityCustodyFileV1 {
    coordinates: CustodyCoordinatesV1,
    proposal_identity: SignerIdentityV1,
    custody_nonce: SignerIdentityV1,
    verifying_key: [u8; 32],
    secret_seed: [u8; 32],
}

impl std::fmt::Debug for StoreIntegrityCustodyFileV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreIntegrityCustodyFileV1")
            .field("coordinates", &self.coordinates)
            .field("proposal_identity", &self.proposal_identity)
            .field("custody_nonce", &self.custody_nonce)
            .field("verifying_key", &self.verifying_key)
            .field("secret_seed", &"<redacted>")
            .finish()
    }
}

impl Drop for StoreIntegrityCustodyFileV1 {
    fn drop(&mut self) {
        self.secret_seed.fill(0);
    }
}

impl StoreIntegrityCustodyFileV1 {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CUSTODY_FILE_LENGTH_V1);
        bytes.extend_from_slice(CUSTODY_MAGIC_V1);
        bytes.extend_from_slice(&CUSTODY_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&self.coordinates.occurrence);
        bytes.extend_from_slice(&self.coordinates.physical_generation);
        bytes.extend_from_slice(&self.coordinates.lifecycle_root);
        bytes.extend_from_slice(&self.coordinates.signer_scope);
        bytes.extend_from_slice(&self.coordinates.policy);
        bytes.extend_from_slice(&self.coordinates.key_generation);
        bytes.extend_from_slice(&self.proposal_identity);
        bytes.extend_from_slice(&self.custody_nonce);
        bytes.extend_from_slice(&self.verifying_key);
        bytes.extend_from_slice(&self.secret_seed);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, SignerRefusalV2> {
        if bytes.len() != CUSTODY_FILE_LENGTH_V1
            || bytes.get(..8) != Some(CUSTODY_MAGIC_V1.as_slice())
            || bytes.get(8..10) != Some(CUSTODY_VERSION_V1.to_be_bytes().as_slice())
        {
            return Err(SignerRefusalV2::CustodyFileMalformed);
        }
        let mut cursor = 10;
        let mut next = || {
            let mut value = [0_u8; 32];
            value.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            value
        };
        let file = Self {
            coordinates: CustodyCoordinatesV1 {
                occurrence: next(),
                physical_generation: next(),
                lifecycle_root: next(),
                signer_scope: next(),
                policy: next(),
                key_generation: next(),
            },
            proposal_identity: next(),
            custody_nonce: next(),
            verifying_key: next(),
            secret_seed: next(),
        };
        file.coordinates.validate()?;
        if SigningKey::from_bytes(&file.secret_seed)
            .verifying_key()
            .to_bytes()
            != file.verifying_key
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        Ok(file)
    }
}

/// Exact runtime observations.  No field in this structure creates standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CustodyObservationV1 {
    pub(crate) uid: u32,
    pub(crate) custody_root_uid: u32,
    pub(crate) mode: u32,
    pub(crate) inode: u64,
    pub(crate) regular_file: bool,
    pub(crate) exact_length: bool,
    pub(crate) key_correspondence: bool,
}

/// Internal signature returned only to the private transition coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CustodySignatureV1 {
    pub(super) family: ClosedMessageFamilyV1,
    pub(super) signer_key_generation: SignerIdentityV1,
    pub(super) payload_digest: SignerIdentityV1,
    pub(super) signature: [u8; 64],
}

/// Purpose-locked private owner of one Store-integrity key generation.
///
/// Not `Clone`, not `Serialize`, and not publicly constructible.
pub(crate) struct C2StoreIntegrityCustodian {
    coordinates: CustodyCoordinatesV1,
    proposal_identity: SignerIdentityV1,
    custody_nonce: SignerIdentityV1,
    verifying_key: [u8; 32],
    secret_seed: [u8; 32],
    custody_path: PathBuf,
}

impl std::fmt::Debug for C2StoreIntegrityCustodian {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("C2StoreIntegrityCustodian")
            .field("coordinates", &self.coordinates)
            .field("proposal_identity", &self.proposal_identity)
            .field("custody_nonce", &self.custody_nonce)
            .field("verifying_key", &self.verifying_key)
            .field("custody_path", &self.custody_path)
            .field("secret_seed", &"<redacted>")
            .finish()
    }
}

impl Drop for C2StoreIntegrityCustodian {
    fn drop(&mut self) {
        self.secret_seed.fill(0);
    }
}

impl C2StoreIntegrityCustodian {
    /// Creates and durably commits a new key under the fixed custody root.
    /// Randomness is read from the operating system; callers select neither
    /// key bytes nor a path.
    pub(super) fn create(
        coordinates: CustodyCoordinatesV1,
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        coordinates.validate()?;
        let mut seed = [0_u8; 32];
        let mut nonce = [0_u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut random| {
                random.read_exact(&mut seed)?;
                random.read_exact(&mut nonce)
            })
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        Self::create_from_fresh_randomness(coordinates, seed, nonce)
    }

    fn create_from_fresh_randomness(
        coordinates: CustodyCoordinatesV1,
        seed: [u8; 32],
        custody_nonce: [u8; 32],
    ) -> Result<(Self, StoreIntegrityKeyProposalV1), SignerRefusalV2> {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let proposal_identity = proposal_identity(&coordinates, &custody_nonce, &verifying_key);
        let proposal = StoreIntegrityKeyProposalV1 {
            coordinates,
            proposal_identity,
            custody_nonce,
            verifying_key,
        };
        let custody_path = fixed_custody_path(&coordinates)?;
        let file = StoreIntegrityCustodyFileV1 {
            coordinates,
            proposal_identity,
            custody_nonce,
            verifying_key,
            secret_seed: seed,
        };
        commit_custody_file(&custody_path, &file.encode())?;
        Ok((
            Self {
                coordinates,
                proposal_identity,
                custody_nonce,
                verifying_key,
                secret_seed: seed,
                custody_path,
            },
            proposal,
        ))
    }

    pub(super) fn load(
        coordinates: CustodyCoordinatesV1,
        expected_proposal: &StoreIntegrityKeyProposalV1,
    ) -> Result<Self, SignerRefusalV2> {
        coordinates.validate()?;
        let path = fixed_custody_path(&coordinates)?;
        let observation = observe_custody_file(&path)?;
        verify_sg_n_13_uid_mode_inode_file_existence_key_possession(&observation)?;
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|_| SignerRefusalV2::CustodyIo)?;
        let mut file = StoreIntegrityCustodyFileV1::decode(&bytes)?;
        if file.coordinates != coordinates
            || file.proposal_identity != expected_proposal.proposal_identity
            || file.custody_nonce != expected_proposal.custody_nonce
            || file.verifying_key != expected_proposal.verifying_key
        {
            return Err(SignerRefusalV2::CustodyKeyMismatch);
        }
        let secret_seed = std::mem::take(&mut file.secret_seed);
        Ok(Self {
            coordinates,
            proposal_identity: file.proposal_identity,
            custody_nonce: file.custody_nonce,
            verifying_key: file.verifying_key,
            secret_seed,
            custody_path: path,
        })
    }

    pub(super) fn coordinates(&self) -> CustodyCoordinatesV1 {
        self.coordinates
    }

    pub(super) fn proposal_identity(&self) -> SignerIdentityV1 {
        self.proposal_identity
    }

    pub(super) fn verifying_key(&self) -> [u8; 32] {
        self.verifying_key
    }

    pub(super) fn custody_path(&self) -> &Path {
        &self.custody_path
    }

    /// The only signing entry point.  The sealed trait prevents raw bytes,
    /// caller-selected domains, or external A1 carrier families from entering.
    pub(super) fn sign<M: SignerMessageV1>(
        &self,
        message: &M,
    ) -> Result<CustodySignatureV1, SignerRefusalV2> {
        if !message.family().is_store_signable()
            || message.coordinates().occurrence != self.coordinates.occurrence
            || message.coordinates().physical_generation != self.coordinates.physical_generation
            || message.coordinates().lifecycle_root != self.coordinates.lifecycle_root
            || message.coordinates().scope != self.coordinates.signer_scope
            || message.coordinates().policy != self.coordinates.policy
            || message.coordinates().signer_key_generation != self.coordinates.key_generation
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        let preimage = message.canonical_preimage();
        let payload_digest: SignerIdentityV1 = Sha256::digest(&preimage).into();
        let signing_key = SigningKey::from_bytes(&self.secret_seed);
        let signature = signing_key.sign(&preimage).to_bytes();
        Ok(CustodySignatureV1 {
            family: message.family(),
            signer_key_generation: self.coordinates.key_generation,
            payload_digest,
            signature,
        })
    }

    #[cfg(test)]
    pub(super) fn from_seed_for_test(coordinates: CustodyCoordinatesV1, seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let custody_nonce = [0x5a; 32];
        let proposal_identity = proposal_identity(&coordinates, &custody_nonce, &verifying_key);
        Self {
            coordinates,
            proposal_identity,
            custody_nonce,
            verifying_key,
            secret_seed: seed,
            custody_path: fixed_custody_path(&coordinates).expect("test coordinates are valid"),
        }
    }
}

fn proposal_identity(
    coordinates: &CustodyCoordinatesV1,
    custody_nonce: &SignerIdentityV1,
    verifying_key: &[u8; 32],
) -> SignerIdentityV1 {
    let mut hash = Sha256::new();
    hash.update(b"nq.c2.store-integrity-key-proposal.v1\0");
    hash.update(coordinates.path_identity());
    hash.update(custody_nonce);
    hash.update(verifying_key);
    hash.finalize().into()
}

fn fixed_custody_path(coordinates: &CustodyCoordinatesV1) -> Result<PathBuf, SignerRefusalV2> {
    coordinates.validate()?;
    let identity = hex::encode(coordinates.path_identity());
    Ok(Path::new(STORE_INTEGRITY_CUSTODY_ROOT_V1).join(format!("{identity}.key")))
}

fn commit_custody_file(path: &Path, bytes: &[u8]) -> Result<(), SignerRefusalV2> {
    if bytes.len() != CUSTODY_FILE_LENGTH_V1
        || path.parent() != Some(Path::new(STORE_INTEGRITY_CUSTODY_ROOT_V1))
    {
        return Err(SignerRefusalV2::CallerSelectedCustodyRoot);
    }
    let root = Path::new(STORE_INTEGRITY_CUSTODY_ROOT_V1);
    std::fs::create_dir_all(root).map_err(|_| SignerRefusalV2::CustodyIo)?;
    let metadata = std::fs::symlink_metadata(root).map_err(|_| SignerRefusalV2::CustodyIo)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SignerRefusalV2::CustodyFileUnsafe);
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SignerRefusalV2::CustodyIo)
}

fn observe_custody_file(path: &Path) -> Result<CustodyObservationV1, SignerRefusalV2> {
    if path.parent() != Some(Path::new(STORE_INTEGRITY_CUSTODY_ROOT_V1)) {
        return Err(SignerRefusalV2::CallerSelectedCustodyRoot);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| SignerRefusalV2::CustodyIo)?;
    let root_metadata = std::fs::symlink_metadata(STORE_INTEGRITY_CUSTODY_ROOT_V1)
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    Ok(CustodyObservationV1 {
        uid: metadata.uid(),
        custody_root_uid: root_metadata.uid(),
        mode: metadata.mode() & 0o777,
        inode: metadata.ino(),
        regular_file: metadata.is_file() && !metadata.file_type().is_symlink(),
        exact_length: metadata.len() as usize == CUSTODY_FILE_LENGTH_V1,
        key_correspondence: true,
    })
}

pub(crate) fn construct_sg_wu_02_key_proposal_custody_owner_inert_key_creation(
    coordinates: CustodyCoordinatesV1,
    custody_nonce: SignerIdentityV1,
    verifying_key: [u8; 32],
) -> Result<StoreIntegrityKeyProposalV1, SignerRefusalV2> {
    construct_sg_n_08_local_key_proposal_is_inert_carries_no(
        coordinates,
        custody_nonce,
        verifying_key,
    )
}

pub(crate) fn verify_sg_wu_02_key_proposal_custody_owner_inert_key_creation(
    proposal: &StoreIntegrityKeyProposalV1,
) -> Result<(), SignerRefusalV2> {
    verify_sg_n_08_local_key_proposal_is_inert_carries_no(proposal)
}

pub(crate) fn construct_sg_n_08_local_key_proposal_is_inert_carries_no(
    coordinates: CustodyCoordinatesV1,
    custody_nonce: SignerIdentityV1,
    verifying_key: [u8; 32],
) -> Result<StoreIntegrityKeyProposalV1, SignerRefusalV2> {
    coordinates.validate()?;
    if custody_nonce.iter().all(|byte| *byte == 0) || verifying_key.iter().all(|byte| *byte == 0) {
        return Err(SignerRefusalV2::CustodyKeyMismatch);
    }
    Ok(StoreIntegrityKeyProposalV1 {
        coordinates,
        proposal_identity: proposal_identity(&coordinates, &custody_nonce, &verifying_key),
        custody_nonce,
        verifying_key,
    })
}

pub(crate) fn verify_sg_n_08_local_key_proposal_is_inert_carries_no(
    proposal: &StoreIntegrityKeyProposalV1,
) -> Result<(), SignerRefusalV2> {
    proposal.coordinates.validate()?;
    if proposal.proposal_identity
        != proposal_identity(
            &proposal.coordinates,
            &proposal.custody_nonce,
            &proposal.verifying_key,
        )
    {
        return Err(SignerRefusalV2::CustodyKeyMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_10_custody_root_path_are_fixed_by_implementation(
    coordinates: CustodyCoordinatesV1,
) -> Result<PathBuf, SignerRefusalV2> {
    fixed_custody_path(&coordinates)
}

pub(crate) fn verify_sg_n_10_custody_root_path_are_fixed_by_implementation(
    coordinates: &CustodyCoordinatesV1,
    path: &Path,
) -> Result<(), SignerRefusalV2> {
    if fixed_custody_path(coordinates)?.as_path() != path {
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
    let decoded = StoreIntegrityCustodyFileV1::decode(&file.encode())?;
    if decoded.coordinates != file.coordinates
        || decoded.proposal_identity != file.proposal_identity
        || decoded.custody_nonce != file.custody_nonce
        || decoded.verifying_key != file.verifying_key
    {
        return Err(SignerRefusalV2::CustodyFileMalformed);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_13_uid_mode_inode_file_existence_key_possession(
    uid: u32,
    custody_root_uid: u32,
    mode: u32,
    inode: u64,
    regular_file: bool,
    exact_length: bool,
    key_correspondence: bool,
) -> CustodyObservationV1 {
    CustodyObservationV1 {
        uid,
        custody_root_uid,
        mode,
        inode,
        regular_file,
        exact_length,
        key_correspondence,
    }
}

pub(crate) fn verify_sg_n_13_uid_mode_inode_file_existence_key_possession(
    observation: &CustodyObservationV1,
) -> Result<(), SignerRefusalV2> {
    // These checks establish usable custody only.  Their successful result has
    // no conversion into standing, currentness, or external authority.
    if observation.uid != geteuid().as_raw()
        || observation.custody_root_uid != geteuid().as_raw()
        || observation.mode != 0o600
        || observation.inode == 0
        || !observation.regular_file
        || !observation.exact_length
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
mod tests {
    use super::*;
    use crate::store_generation::signer::messages::{
        SignerMessageCoordinatesV1,
        construct_msg_06_healthy_rotation_continuity_current_usable_predecessor,
    };

    fn coordinates() -> CustodyCoordinatesV1 {
        CustodyCoordinatesV1 {
            occurrence: [1; 32],
            physical_generation: [2; 32],
            lifecycle_root: [3; 32],
            signer_scope: [4; 32],
            policy: [5; 32],
            key_generation: [6; 32],
        }
    }

    #[test]
    fn fixed_path_cannot_be_selected_by_a_caller() {
        let coordinates = coordinates();
        let path = construct_sg_n_10_custody_root_path_are_fixed_by_implementation(coordinates)
            .expect("valid fixed path");
        assert!(path.starts_with(STORE_INTEGRITY_CUSTODY_ROOT_V1));
        assert_eq!(
            verify_sg_n_10_custody_root_path_are_fixed_by_implementation(
                &coordinates,
                Path::new("/tmp/attacker.key")
            ),
            Err(SignerRefusalV2::CallerSelectedCustodyRoot)
        );
    }

    #[test]
    fn private_signing_surface_accepts_only_sealed_messages() {
        let coordinates = coordinates();
        let custodian = C2StoreIntegrityCustodian::from_seed_for_test(coordinates, [7; 32]);
        let message = construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            SignerMessageCoordinatesV1 {
                occurrence: coordinates.occurrence,
                physical_generation: coordinates.physical_generation,
                lifecycle_root: coordinates.lifecycle_root,
                scope: coordinates.signer_scope,
                policy: coordinates.policy,
                signer_key_generation: coordinates.key_generation,
                cut: 8,
            },
            [9; 32],
            [10; 32],
        )
        .expect("valid message");
        let signature = custodian.sign(&message).expect("typed signing succeeds");
        assert_eq!(
            signature.family,
            ClosedMessageFamilyV1::Msg06NormalRotationContinuity
        );
        assert_eq!(signature.signer_key_generation, coordinates.key_generation);
    }

    #[test]
    fn custody_codec_roundtrip_has_exact_v1_length() {
        let coordinates = coordinates();
        let seed = [7; 32];
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let custody_nonce = [8; 32];
        let file = StoreIntegrityCustodyFileV1 {
            coordinates,
            proposal_identity: proposal_identity(&coordinates, &custody_nonce, &verifying_key),
            custody_nonce,
            verifying_key,
            secret_seed: seed,
        };
        let bytes = file.encode();
        assert_eq!(bytes.len(), CUSTODY_FILE_LENGTH_V1);
        let decoded = StoreIntegrityCustodyFileV1::decode(&bytes).expect("exact file decodes");
        assert_eq!(decoded.coordinates, coordinates);
        assert_eq!(decoded.proposal_identity, file.proposal_identity);
        assert_eq!(decoded.verifying_key, verifying_key);
    }
}
