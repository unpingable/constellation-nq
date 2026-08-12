//! Permanent C2 Store-generation lock object and process exclusion.
//!
//! The file lock establishes quiescence only.  Neither its path, inode, the
//! process mutex, nor the operating-system lock is mutation standing.

use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{Mutex, OnceLock};

use nix::fcntl::{Flock, FlockArg};
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rustix::fs::{Mode, OFlags, openat};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::C2_LOCK_FILE_V1;

const LOCK_SCHEMA_V1: &str = "nq.c2_store_generation_lock.v1";
const LOCK_IDENTITY_DOMAIN_V1: &[u8] = b"nq.c2.store_generation_lock.identity.v1\0";
const LOCK_CHECKSUM_DOMAIN_V1: &[u8] = b"nq.c2.store_generation_lock.checksum.v1\0";
const LENGTH_PREFIX_BYTES: usize = 4;

pub(crate) type LockInodeKey = (u64, u64);
type LifetimeLockedFile = Flock<File>;

fn held_lock_inodes() -> &'static Mutex<BTreeSet<LockInodeKey>> {
    static HELD: OnceLock<Mutex<BTreeSet<LockInodeKey>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Exact lock carrier before zero padding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LockCarrierV1 {
    schema: String,
    schema_version: u8,
    lock_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    b_genesis_frame_identity: Sha256Digest,
    checksum: Sha256Digest,
    canonical_length: u32,
    trailing_padding: String,
}

#[derive(Serialize)]
struct LockIdentityPreimage<'a> {
    schema: &'static str,
    schema_version: u8,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    b_genesis_frame_identity: &'a Sha256Digest,
    canonical_length: u32,
}

/// Typed refusal for the permanent lock surface.
#[derive(Debug, Error)]
pub enum C2StoreGenerationLockErrorV1 {
    /// I/O or operating-system lock failure.
    #[error("Store-generation lock I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Canonical JSON construction failed.
    #[error("Store-generation lock canonicalization failed: {0}")]
    Canonical(#[from] nq_protocol::CanonicalizationError),
    /// Parsed JSON did not match the closed carrier.
    #[error("Store-generation lock carrier is malformed or substituted")]
    MalformedCarrier,
    /// The exact file length or canonical zero padding was wrong.
    #[error("Store-generation lock length or padding is noncanonical")]
    NoncanonicalLengthOrPadding,
    /// This inode is already held in this process.
    #[error("Store-generation lock inode is already held by this process")]
    ProcessAliasConflict,
    /// The operating-system exclusive lock was unavailable.
    #[error("Store-generation lock is held by another process")]
    OperatingSystemConflict,
    /// A parsed backlink named another authenticated B genesis.
    #[error("Store-generation lock B-genesis backlink mismatch")]
    BacklinkMismatch,
}

/// Read-only verified contents of the exactly sized lock object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGenerationLockCarrierV1 {
    /// Lock semantic identity.
    pub lock_identity: Sha256Digest,
    /// Store occurrence.
    pub occurrence_id: String,
    /// Exact physical generation.
    pub physical_store_generation_identity: Sha256Digest,
    /// Authenticated B genesis backlink.
    pub b_genesis_frame_identity: Sha256Digest,
    /// Exact allocated byte length.
    pub canonical_length: u32,
}

/// Held nonreentrant process mutex plus provisional `LOCK_EX`.
///
/// This type intentionally has no conversion into writer standing.
pub struct C2StoreGenerationLockV1 {
    inode: LockInodeKey,
    carrier: VerifiedGenerationLockCarrierV1,
    _flock: LifetimeLockedFile,
}

/// Fresh-installation lock retained from exclusive creation through REC-29
/// publication. It owns the process-inode reservation and OS flock but is
/// deliberately not a completed generation lock until its one-way finalizer
/// writes and verifies the B-genesis backlink.
pub(crate) struct C2ProvisionalStoreGenerationLockV1 {
    inode: LockInodeKey,
    provisional_inode: ProvisionalHeldInode,
    flock: LifetimeLockedFile,
}

/// Linear intermediate after the exact lock inode has entered the process
/// nonreentrancy registry but before the OS flock is acquired.  Splitting this
/// otherwise tiny constructor gives the installation crash observer truthful
/// boundaries for mutex transfer and flock acquisition.
pub(crate) struct C2ProvisionalLockInodeReservationV1 {
    inode: LockInodeKey,
    provisional_inode: ProvisionalHeldInode,
    file: File,
}

impl C2ProvisionalStoreGenerationLockV1 {
    /// Borrow the retained descriptor for exact allocation/profile checks.
    #[must_use]
    pub(crate) fn file(&self) -> &File {
        &self.flock
    }
}

impl C2StoreGenerationLockV1 {
    /// Fixed child name resolved through the retained Store-root descriptor.
    #[must_use]
    pub const fn fixed_name(&self) -> &'static str {
        C2_LOCK_FILE_V1
    }

    /// Parsed, independently verified carrier.
    #[must_use]
    pub const fn carrier(&self) -> &VerifiedGenerationLockCarrierV1 {
        &self.carrier
    }

    /// Inode key used by the process-wide nonreentrancy registry.
    #[must_use]
    pub const fn inode_key(&self) -> LockInodeKey {
        self.inode
    }
}

/// Provisional process-registry entry removed automatically on every
/// constructor error.  Ownership transfers to `C2StoreGenerationLockV1` only
/// after the descriptor, flock, bytes, and backlink have all verified.
struct ProvisionalHeldInode {
    inode: LockInodeKey,
    armed: bool,
}

impl ProvisionalHeldInode {
    fn insert(inode: LockInodeKey) -> Result<Self, C2StoreGenerationLockErrorV1> {
        let mut held = held_lock_inodes()
            .lock()
            .map_err(|_| C2StoreGenerationLockErrorV1::ProcessAliasConflict)?;
        if !held.insert(inode) {
            return Err(C2StoreGenerationLockErrorV1::ProcessAliasConflict);
        }
        Ok(Self { inode, armed: true })
    }

    fn transfer(mut self) {
        self.armed = false;
    }
}

impl Drop for ProvisionalHeldInode {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut held) = held_lock_inodes().lock() {
                held.remove(&self.inode);
            }
        }
    }
}

fn read_exact_descriptor_bytes(file: &File) -> Result<Vec<u8>, C2StoreGenerationLockErrorV1> {
    let len = usize::try_from(file.metadata()?.len())
        .map_err(|_| C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)?;
    let mut bytes = vec![0_u8; len];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

impl Drop for C2StoreGenerationLockV1 {
    fn drop(&mut self) {
        if let Ok(mut held) = held_lock_inodes().lock() {
            held.remove(&self.inode);
        }
    }
}

/// Acquire the permanent generation lock immediately after exclusive file
/// creation, before any B/G or SQL installation effect. The empty allocated
/// file remains an observable S1 prefix and cannot be mistaken for REC-29.
pub(crate) fn begin_provisional_generation_lock_v1(
    file: File,
) -> Result<C2ProvisionalStoreGenerationLockV1, C2StoreGenerationLockErrorV1> {
    acquire_provisional_generation_flock_v1(reserve_provisional_generation_inode_v1(file)?)
}

/// Transfer one exclusively created lock file into the process-wide inode
/// registry.  No OS flock has been acquired when this returns.
pub(crate) fn reserve_provisional_generation_inode_v1(
    file: File,
) -> Result<C2ProvisionalLockInodeReservationV1, C2StoreGenerationLockErrorV1> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    let inode = (metadata.dev(), metadata.ino());
    let provisional_inode = ProvisionalHeldInode::insert(inode)?;
    Ok(C2ProvisionalLockInodeReservationV1 {
        inode,
        provisional_inode,
        file,
    })
}

/// Acquire `LOCK_EX` for an inode already reserved by this process.  Failure
/// drops the reservation and cannot leave a process-local authority alias.
pub(crate) fn acquire_provisional_generation_flock_v1(
    reservation: C2ProvisionalLockInodeReservationV1,
) -> Result<C2ProvisionalStoreGenerationLockV1, C2StoreGenerationLockErrorV1> {
    let flock = match Flock::lock(reservation.file, FlockArg::LockExclusiveNonblock) {
        Ok(flock) => flock,
        Err((_file, _error)) => return Err(C2StoreGenerationLockErrorV1::OperatingSystemConflict),
    };
    Ok(C2ProvisionalStoreGenerationLockV1 {
        inode: reservation.inode,
        provisional_inode: reservation.provisional_inode,
        flock,
    })
}

/// Publish and reverify REC-29 while retaining the original flock and inode
/// reservation. There is no unlock/reopen gap between installation prefix
/// and completed lock standing.
pub(crate) fn finalize_provisional_generation_lock_v1(
    provisional: C2ProvisionalStoreGenerationLockV1,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    b_genesis_frame_identity: Sha256Digest,
) -> Result<C2StoreGenerationLockV1, C2StoreGenerationLockErrorV1> {
    let canonical_length = u32::try_from(provisional.flock.metadata()?.len())
        .map_err(|_| C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)?;
    let bytes = encode_rec_29_generation_lock(
        occurrence_id,
        physical_store_generation_identity,
        b_genesis_frame_identity.clone(),
        canonical_length,
    )?;
    let mut written = 0;
    while written < bytes.len() {
        let count = provisional
            .flock
            .write_at(&bytes[written..], written as u64)?;
        if count == 0 {
            return Err(C2StoreGenerationLockErrorV1::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "C2 REC-29 write made no progress",
            )));
        }
        written = written
            .checked_add(count)
            .ok_or(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)?;
    }
    provisional.flock.sync_all()?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-39");
    let observed = read_exact_descriptor_bytes(&provisional.flock)?;
    let carrier = verify_rec_29_generation_lock(&observed, &b_genesis_frame_identity)?;
    provisional.provisional_inode.transfer();
    Ok(C2StoreGenerationLockV1 {
        inode: provisional.inode,
        carrier,
        _flock: provisional.flock,
    })
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    sha256_bytes(&preimage)
}

fn carrier_for(
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    b_genesis_frame_identity: Sha256Digest,
    canonical_length: u32,
) -> Result<LockCarrierV1, C2StoreGenerationLockErrorV1> {
    if occurrence_id.is_empty() || occurrence_id.len() > 256 {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    let identity_preimage = LockIdentityPreimage {
        schema: LOCK_SCHEMA_V1,
        schema_version: 1,
        occurrence_id: &occurrence_id,
        physical_store_generation_identity: &physical_store_generation_identity,
        b_genesis_frame_identity: &b_genesis_frame_identity,
        canonical_length,
    };
    let identity_bytes = canonical_json_bytes(&identity_preimage)?;
    let lock_identity = domain_digest(LOCK_IDENTITY_DOMAIN_V1, &identity_bytes);
    let mut checksum_preimage = identity_bytes;
    checksum_preimage.extend_from_slice(lock_identity.as_str().as_bytes());
    let checksum = domain_digest(LOCK_CHECKSUM_DOMAIN_V1, &checksum_preimage);
    Ok(LockCarrierV1 {
        schema: LOCK_SCHEMA_V1.to_owned(),
        schema_version: 1,
        lock_identity,
        occurrence_id,
        physical_store_generation_identity,
        b_genesis_frame_identity,
        checksum,
        canonical_length,
        trailing_padding: "zero".to_owned(),
    })
}

/// REC-29 encoder: four-byte big-endian JSON length, canonical JSON, then
/// canonical zero padding to the exact installed `A` byte length.
pub fn encode_rec_29_generation_lock(
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    b_genesis_frame_identity: Sha256Digest,
    canonical_length: u32,
) -> Result<Vec<u8>, C2StoreGenerationLockErrorV1> {
    let carrier = carrier_for(
        occurrence_id,
        physical_store_generation_identity,
        b_genesis_frame_identity,
        canonical_length,
    )?;
    let json = canonical_json_bytes(&carrier)?;
    let payload_len = LENGTH_PREFIX_BYTES
        .checked_add(json.len())
        .ok_or(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)?;
    let exact_len = usize::try_from(canonical_length)
        .map_err(|_| C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)?;
    if payload_len > exact_len || json.len() > u32::MAX as usize {
        return Err(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding);
    }
    let mut encoded = vec![0_u8; exact_len];
    encoded[..4].copy_from_slice(&(json.len() as u32).to_be_bytes());
    encoded[4..payload_len].copy_from_slice(&json);
    Ok(encoded)
}

/// REC-29 verifier for exact bytes, checksum, semantic identity, and backlink.
pub fn verify_rec_29_generation_lock(
    bytes: &[u8],
    expected_b_genesis: &Sha256Digest,
) -> Result<VerifiedGenerationLockCarrierV1, C2StoreGenerationLockErrorV1> {
    if bytes.len() < LENGTH_PREFIX_BYTES {
        return Err(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding);
    }
    let json_len = u32::from_be_bytes(bytes[..4].try_into().expect("four-byte prefix")) as usize;
    let json_end = LENGTH_PREFIX_BYTES
        .checked_add(json_len)
        .ok_or(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)?;
    if json_end > bytes.len() || bytes[json_end..].iter().any(|byte| *byte != 0) {
        return Err(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding);
    }
    let carrier: LockCarrierV1 = serde_json::from_slice(&bytes[4..json_end])
        .map_err(|_| C2StoreGenerationLockErrorV1::MalformedCarrier)?;
    if carrier.schema != LOCK_SCHEMA_V1
        || carrier.schema_version != 1
        || carrier.trailing_padding != "zero"
        || usize::try_from(carrier.canonical_length).ok() != Some(bytes.len())
        || canonical_json_bytes(&carrier)? != bytes[4..json_end]
    {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    let expected = carrier_for(
        carrier.occurrence_id.clone(),
        carrier.physical_store_generation_identity.clone(),
        carrier.b_genesis_frame_identity.clone(),
        carrier.canonical_length,
    )?;
    if carrier != expected {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    if &carrier.b_genesis_frame_identity != expected_b_genesis {
        return Err(C2StoreGenerationLockErrorV1::BacklinkMismatch);
    }
    Ok(VerifiedGenerationLockCarrierV1 {
        lock_identity: carrier.lock_identity,
        occurrence_id: carrier.occurrence_id,
        physical_store_generation_identity: carrier.physical_store_generation_identity,
        b_genesis_frame_identity: carrier.b_genesis_frame_identity,
        canonical_length: carrier.canonical_length,
    })
}

/// Acquire the fixed-name permanent lock. This is quiescence evidence only.
pub(crate) fn construct_wu_04_immutable_wu_local_lock_flock_process_registry(
    retained_root: &File,
    expected_b_genesis: &Sha256Digest,
) -> Result<C2StoreGenerationLockV1, C2StoreGenerationLockErrorV1> {
    let file = File::from(
        openat(
            retained_root,
            C2_LOCK_FILE_V1,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-40");
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    let inode = (metadata.dev(), metadata.ino());
    let provisional_inode = ProvisionalHeldInode::insert(inode)?;
    let flock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(flock) => flock,
        Err((_file, _error)) => return Err(C2StoreGenerationLockErrorV1::OperatingSystemConflict),
    };
    let bytes = read_exact_descriptor_bytes(&flock)?;
    let carrier = verify_rec_29_generation_lock(&bytes, expected_b_genesis)?;
    provisional_inode.transfer();
    Ok(C2StoreGenerationLockV1 {
        inode,
        carrier,
        _flock: flock,
    })
}

/// Revalidate WU-04/N-82 against live descriptor identity and exact bytes.
pub fn verify_wu_04_immutable_wu_local_lock_flock_process_registry(
    lock: &C2StoreGenerationLockV1,
) -> Result<(), C2StoreGenerationLockErrorV1> {
    let metadata = lock._flock.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || (metadata.dev(), metadata.ino()) != lock.inode
        || !held_lock_inodes()
            .lock()
            .map_err(|_| C2StoreGenerationLockErrorV1::ProcessAliasConflict)?
            .contains(&lock.inode)
    {
        return Err(C2StoreGenerationLockErrorV1::ProcessAliasConflict);
    }
    let bytes = read_exact_descriptor_bytes(&lock._flock)?;
    let reparsed = verify_rec_29_generation_lock(&bytes, &lock.carrier.b_genesis_frame_identity)?;
    if reparsed != lock.carrier {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    Ok(())
}

/// N-81 shares WU-04's exact held-lock verifier; later typed phases enforce
/// the release order without turning this guard into standing.
pub fn construct_n_81_completed_open_lock_transaction_effect_sequence_reverse(
    lock: &C2StoreGenerationLockV1,
) -> Result<(), C2StoreGenerationLockErrorV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)
}

/// N-81 verifier alias.
pub fn verify_n_81_completed_open_lock_transaction_effect_sequence_reverse(
    lock: &C2StoreGenerationLockV1,
) -> Result<(), C2StoreGenerationLockErrorV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)
}

/// N-82 exact inode-registry constructor target.
pub fn construct_n_82_process_mutex_keyed_by_retained_lock_inode(
    lock: &C2StoreGenerationLockV1,
) -> Result<LockInodeKey, C2StoreGenerationLockErrorV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)?;
    Ok(lock.inode)
}

/// N-82 verifier alias.
pub fn verify_n_82_process_mutex_keyed_by_retained_lock_inode(
    lock: &C2StoreGenerationLockV1,
) -> Result<(), C2StoreGenerationLockErrorV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)
}

/// Creation-bucket key used only until the permanent inode mutex is held.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct C2CreationBucketV1 {
    root_device: u64,
    root_inode: u64,
    fixed_token: &'static str,
}

/// N-83 constructs the sole root-inode/fixed-token creation bucket.
pub fn construct_n_83_fresh_creation_bucket_is_root_inode_fixed(
    retained_root: &File,
) -> Result<C2CreationBucketV1, C2StoreGenerationLockErrorV1> {
    let metadata = retained_root.metadata()?;
    Ok(C2CreationBucketV1 {
        root_device: metadata.dev(),
        root_inode: metadata.ino(),
        fixed_token: C2_LOCK_FILE_V1,
    })
}

/// N-83 rejects substituted creation tokens or root identities.
pub fn verify_n_83_fresh_creation_bucket_is_root_inode_fixed(
    bucket: &C2CreationBucketV1,
    retained_root: &File,
) -> Result<(), C2StoreGenerationLockErrorV1> {
    let metadata = retained_root.metadata()?;
    if bucket.root_device != metadata.dev()
        || bucket.root_inode != metadata.ino()
        || bucket.fixed_token != C2_LOCK_FILE_V1
    {
        return Err(C2StoreGenerationLockErrorV1::MalformedCarrier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn write_lock_fixture(retained_root: &Path, bytes: &[u8]) {
        let path = retained_root.join(C2_LOCK_FILE_V1);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn provisional_lock_finalizes_without_unlock_or_inode_transfer_gap() {
        let root = tempdir().unwrap();
        let path = root.path().join(C2_LOCK_FILE_V1);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        file.set_len(4096).unwrap();
        let inode = {
            let metadata = file.metadata().unwrap();
            (metadata.dev(), metadata.ino())
        };
        let provisional = begin_provisional_generation_lock_v1(file).unwrap();
        assert_eq!(
            (
                provisional.file().metadata().unwrap().dev(),
                provisional.file().metadata().unwrap().ino()
            ),
            inode
        );
        let b_genesis = digest('3');
        let completed = finalize_provisional_generation_lock_v1(
            provisional,
            "occurrence-1".into(),
            digest('2'),
            b_genesis.clone(),
        )
        .unwrap();
        assert_eq!(completed.inode_key(), inode);
        verify_wu_04_immutable_wu_local_lock_flock_process_registry(&completed).unwrap();
        assert!(matches!(
            construct_wu_04_immutable_wu_local_lock_flock_process_registry(
                &File::open(root.path()).unwrap(),
                &b_genesis,
            ),
            Err(C2StoreGenerationLockErrorV1::ProcessAliasConflict)
                | Err(C2StoreGenerationLockErrorV1::OperatingSystemConflict)
        ));
    }

    #[test]
    fn rec_29_round_trip_and_padding_mutation_refuse() {
        let bytes =
            encode_rec_29_generation_lock("occurrence-1".into(), digest('2'), digest('3'), 2048)
                .unwrap();
        let parsed = verify_rec_29_generation_lock(&bytes, &digest('3')).unwrap();
        assert_eq!(parsed.canonical_length, 2048);
        let mut changed = bytes;
        *changed.last_mut().unwrap() = 1;
        assert!(matches!(
            verify_rec_29_generation_lock(&changed, &digest('3')),
            Err(C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding)
        ));
    }

    #[test]
    fn aliases_share_one_nonreentrant_inode_registry() {
        let root = tempdir().unwrap();
        let bytes =
            encode_rec_29_generation_lock("occurrence-1".into(), digest('2'), digest('3'), 2048)
                .unwrap();
        write_lock_fixture(root.path(), &bytes);
        let retained_root = File::open(root.path()).unwrap();
        let first = construct_wu_04_immutable_wu_local_lock_flock_process_registry(
            &retained_root,
            &digest('3'),
        )
        .unwrap();
        // Fixed-name reopen is sufficient to hit the same inode.
        assert!(matches!(
            construct_wu_04_immutable_wu_local_lock_flock_process_registry(
                &retained_root,
                &digest('3')
            ),
            Err(C2StoreGenerationLockErrorV1::ProcessAliasConflict)
        ));
        drop(first);
        assert!(
            construct_wu_04_immutable_wu_local_lock_flock_process_registry(
                &retained_root,
                &digest('3')
            )
            .is_ok()
        );
    }

    #[test]
    fn hard_linked_lock_object_refuses() {
        let root = tempdir().unwrap();
        let bytes =
            encode_rec_29_generation_lock("occurrence-1".into(), digest('2'), digest('3'), 2048)
                .unwrap();
        write_lock_fixture(root.path(), &bytes);
        let retained_root = File::open(root.path()).unwrap();
        std::fs::hard_link(
            root.path().join(C2_LOCK_FILE_V1),
            root.path().join("second-lock"),
        )
        .unwrap();
        assert!(matches!(
            construct_wu_04_immutable_wu_local_lock_flock_process_registry(
                &retained_root,
                &digest('3')
            ),
            Err(C2StoreGenerationLockErrorV1::MalformedCarrier)
        ));
    }

    #[test]
    fn failed_constructor_releases_provisional_inode_registry_entry() {
        let root = tempdir().unwrap();
        let bytes =
            encode_rec_29_generation_lock("occurrence-1".into(), digest('2'), digest('3'), 2048)
                .unwrap();
        write_lock_fixture(root.path(), &bytes);
        let retained_root = File::open(root.path()).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                construct_wu_04_immutable_wu_local_lock_flock_process_registry(
                    &retained_root,
                    &digest('4')
                ),
                Err(C2StoreGenerationLockErrorV1::BacklinkMismatch)
            ));
        }
    }
}
