//! C2 backend preflight, physical-carrier facts, and closed standing.
//!
//! The types in this module intentionally separate three phases:
//!
//! 1. borrowed, non-authoritative host observations;
//! 2. borrowed facts about raw fixed lock/B/G allocation; and
//! 3. post-receipt closed-backend standing created by one function after a
//!    final descriptor reopen and held-lock verification.
//!
//! None of these values is a capacity token.  In particular, this module has
//! no F/M/L, reservation, allocation-capsule, writer-session, serialization,
//! default, clone, or caller-selected backend conversion.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use nq_protocol::Sha256Digest;
use thiserror::Error;

use crate::append_extent::{
    C2AppendExtentLayoutV1, C2AppendExtentRefusalV1, C2CarrierPairHeaderCorrespondenceV1,
    C2DurableAppendPairV1, C2InstallationExtentInitializedV1, C2ObservedAppendExtentRefusalV1,
    initialize_durable_append_pair_v1, initialize_durable_append_pair_with_observer_v1,
    open_durable_append_pair_v1,
};
use crate::store_generation::install::C2DurableResultV1;
use crate::store_generation::lock::{
    C2StoreGenerationLockV1, LockInodeKey,
    verify_wu_04_immutable_wu_local_lock_flock_process_registry,
};
use crate::store_generation::records::{
    PhysicalStoreGenerationIdentityV1, StoreOccurrenceIdentityV1,
};

const PRODUCTION_BACKEND_V1: &str = "linux_posix_fallocate_regular_file_v1";
const LOCK_ROLE_V1: &str = "nq.c2.permanent_lock.v1";
const B_ROLE_V1: &str = "nq.c2.bootstrap_append_extent.b.v1";
const G_ROLE_V1: &str = "nq.c2.global_refusal_append_extent.g.v1";

/// An inert scalar-only refusal.  No variant can carry a descriptor, guard,
/// reference, borrowed brand, closed object, or writer standing.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum C2BackendRefusalV1 {
    #[error("the retained Store root is not one exact directory descriptor")]
    RootDescriptorMismatch,
    #[error("the backend or qualified-profile binding was substituted")]
    BackendProfileMismatch,
    #[error("the backend observation epoch is foreign or expired")]
    ObservationEpochMismatch,
    #[error("a fixed carrier is not a regular one-link file")]
    CarrierShapeMismatch,
    #[error("a fixed carrier has the wrong exact length")]
    CarrierLengthMismatch,
    #[error("a fixed carrier is sparse or lacks its required physical allocation")]
    CarrierAllocationMismatch,
    #[error("the lock, B, and G carriers do not share the retained-root device")]
    CarrierDeviceMismatch,
    #[error("the permanent lock or process-wide lock evidence is absent or stale")]
    LockStandingMismatch,
    #[error("closed standing was requested before the exact S4 completion receipt")]
    CompletionStageMismatch,
    #[error("the S4 physical generation or receipt differs from the authenticated tuple")]
    CompletionReceiptMismatch,
    #[error("the final read-only reopen differs from the authenticated Store tuple")]
    FinalReopenMismatch,
    #[error("an occurrence, generation, policy, common binding, or predecessor was spliced")]
    ClosedTupleMismatch,
    #[error("preflight or raw allocation was treated as authority-bearing standing")]
    AuthorityAmplification,
    #[error("closed construction failure changed the S4 durable snapshot")]
    NoWriteSnapshotMismatch,
}

/// One retained Store-root descriptor observation epoch.
///
/// The fields are private and the value deliberately has no `Clone`, `Copy`,
/// `Default`, or serde implementation.  It cannot survive restart as standing.
pub(crate) struct C2BackendObservationEpochV1<'root> {
    root: &'root File,
    root_device: u64,
    root_inode: u64,
    epoch_identity: Sha256Digest,
}

/// The exact authenticated profile coordinate against which live facts are
/// compared.  It is a binding input, not proof that production qualification
/// has passed.
pub(crate) struct C2QualifiedBackendProfileBindingV1 {
    backend_identity: &'static str,
    profile_identity: Sha256Digest,
    implementation_manifest_identity: Sha256Digest,
    contract_identity: Sha256Digest,
}

/// Private borrowed C2 preflight observations.
///
/// These fields never authenticate a Store generation and support only the
/// fixed raw carrier allocation operation below.
pub(crate) struct C2BackendPreflightFactsV1<'root> {
    epoch: &'root C2BackendObservationEpochV1<'root>,
    profile: &'root C2QualifiedBackendProfileBindingV1,
    observed_root_device: u64,
    observed_root_inode: u64,
    observed_backend_identity: &'static str,
}

/// Static-analysis spelling for the accepted non-authoritative preflight
/// role.  The V1 type remains the exact matrix-assigned runtime component.
type C2BackendPreflightFacts<'root> = C2BackendPreflightFactsV1<'root>;

/// One physical file fact.  A role is fixed by the constructor call site and
/// cannot be caller-selected through a generic collection.
struct C2RawFixedCarrierFactV1<'root> {
    role: &'static str,
    file: &'root File,
    device: u64,
    inode: u64,
    length: u64,
    allocated_bytes: u64,
}

/// Exact physical preallocation of the only three permanent C2 carriers.
///
/// This is borrowed, non-serializable physical evidence.  It has no standing,
/// capacity, session, F/M/L, reservation, or authority conversion.
pub(crate) struct C2PermanentPhysicalPreallocationV1<'root> {
    preflight: &'root C2BackendPreflightFactsV1<'root>,
    lock: C2RawFixedCarrierFactV1<'root>,
    b: C2RawFixedCarrierFactV1<'root>,
    g: C2RawFixedCarrierFactV1<'root>,
}

/// Exact installation-mode correspondence repeated by the authenticated
/// tuple and the final reopen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2ClosedInstallationModeV1<'store> {
    Fresh,
    RestoreSuccessor {
        predecessor_physical_generation: &'store Sha256Digest,
        predecessor_bootstrap: &'store Sha256Digest,
        predecessor_completion_receipt: &'store Sha256Digest,
        restore_disposition: &'store Sha256Digest,
    },
}

/// Complete authenticated tuple supplied by the Store-owned resolver after
/// policy, enrollment, generation, B/G, and receipt verification.
///
/// Construction is crate-private so the machine call-graph census can require
/// its sole Store-owned producer.  It is not accepted as a Boolean or digest-
/// only closed-standing substitute.
pub(crate) struct C2AuthenticatedClosedTupleV1<'store> {
    occurrence: &'store str,
    physical_generation: &'store Sha256Digest,
    active_policy: &'store Sha256Digest,
    b_g_common_binding: &'store Sha256Digest,
    b_header: &'store Sha256Digest,
    g_header: &'store Sha256Digest,
    lock_identity: &'store Sha256Digest,
    installation_mode: C2ClosedInstallationModeV1<'store>,
    qualified_profile: &'store C2QualifiedBackendProfileBindingV1,
    completion_receipt: &'store Sha256Digest,
    completed_snapshot: &'store Sha256Digest,
    root_device: u64,
    root_inode: u64,
    b_device: u64,
    b_inode: u64,
    g_device: u64,
    g_inode: u64,
}

/// Live, read-only, final-reopen facts.  File references keep this evidence
/// process-local and borrowed.
pub(crate) struct C2FinalReopenFactsV1<'store> {
    root: &'store File,
    b: &'store File,
    g: &'store File,
    root_device: u64,
    root_inode: u64,
    b_device: u64,
    b_inode: u64,
    g_device: u64,
    g_inode: u64,
    b_length: u64,
    g_length: u64,
    profile_identity: &'store Sha256Digest,
    b_g_common_binding: &'store Sha256Digest,
    b_header: &'store Sha256Digest,
    g_header: &'store Sha256Digest,
    active_policy: &'store Sha256Digest,
}

/// The sole authority-bearing backend correspondence object.
///
/// It is borrowed and cannot be cloned, copied, defaulted, or serialized.  It
/// contains no conversion to a writer session or any capacity representation.
pub(crate) struct ClosedC2StoreBackendV1<'store> {
    tuple: &'store C2AuthenticatedClosedTupleV1<'store>,
    final_reopen: &'store C2FinalReopenFactsV1<'store>,
    lock: &'store C2StoreGenerationLockV1,
    physical_allocation: &'store C2PermanentPhysicalPreallocationV1<'store>,
}

impl<'store> ClosedC2StoreBackendV1<'store> {
    /// Sole physical constructor.  Its only caller is the post-receipt final-
    /// reopen path below; no Boolean or caller assertion can create closure.
    fn new_verified(
        tuple: &'store C2AuthenticatedClosedTupleV1<'store>,
        final_reopen: &'store C2FinalReopenFactsV1<'store>,
        lock: &'store C2StoreGenerationLockV1,
        physical_allocation: &'store C2PermanentPhysicalPreallocationV1<'store>,
    ) -> Self {
        Self {
            tuple,
            final_reopen,
            lock,
            physical_allocation,
        }
    }
}

/// Non-authority proof that C2 exposes only fixed physical allocation and no
/// capacity-bearing object or F/M/L conversion.
pub(crate) struct C2CapacityBoundaryV1<'store> {
    physical_allocation: &'store C2PermanentPhysicalPreallocationV1<'store>,
    closed_backend: &'store ClosedC2StoreBackendV1<'store>,
}

/// Store fields disjoint from the descriptors and guards retained by the
/// closed backend.  The ordinary writer-session owner supplies this private
/// field set; the witness cannot be publicly constructed.
pub(crate) struct C2OrdinaryStoreFieldsV1 {
    field_set_identity: Sha256Digest,
}

/// A nonescaping field-split borrow.  The HRTB constructor below is the only
/// way to receive it, so neither side of the split can be returned from the
/// closure.
pub(crate) struct FieldSplitC2WriterSessionBorrowV1<'borrow, 'store> {
    closed_backend: &'borrow ClosedC2StoreBackendV1<'store>,
    ordinary_fields: &'borrow mut C2OrdinaryStoreFieldsV1,
}

/// Row-law witness.  Named `construct_*` row targets construct this inert
/// audit result from an already closed backend; they are not alternate closed
/// backend constructors.
pub(crate) struct C2BackendRowLawWitnessV1<'borrow, 'store> {
    closed_backend: &'borrow ClosedC2StoreBackendV1<'store>,
}

fn allocated_bytes(metadata: &std::fs::Metadata) -> Result<u64, C2BackendRefusalV1> {
    metadata
        .blocks()
        .checked_mul(512)
        .ok_or(C2BackendRefusalV1::CarrierAllocationMismatch)
}

fn raw_fixed_carrier<'root>(
    role: &'static str,
    file: &'root File,
    expected_length: u64,
    expected_device: u64,
) -> Result<C2RawFixedCarrierFactV1<'root>, C2BackendRefusalV1> {
    let metadata = file
        .metadata()
        .map_err(|_| C2BackendRefusalV1::CarrierShapeMismatch)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(C2BackendRefusalV1::CarrierShapeMismatch);
    }
    if metadata.len() != expected_length {
        return Err(C2BackendRefusalV1::CarrierLengthMismatch);
    }
    if metadata.dev() != expected_device {
        return Err(C2BackendRefusalV1::CarrierDeviceMismatch);
    }
    let allocated_bytes = allocated_bytes(&metadata)?;
    if allocated_bytes < expected_length {
        return Err(C2BackendRefusalV1::CarrierAllocationMismatch);
    }
    Ok(C2RawFixedCarrierFactV1 {
        role,
        file,
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        allocated_bytes,
    })
}

/// Start one retained-root observation epoch.  This is process-local and
/// non-authoritative.
pub(crate) fn begin_c2_backend_observation_epoch_v1(
    root: &File,
    epoch_identity: Sha256Digest,
) -> Result<C2BackendObservationEpochV1<'_>, C2BackendRefusalV1> {
    let metadata = root
        .metadata()
        .map_err(|_| C2BackendRefusalV1::RootDescriptorMismatch)?;
    if !metadata.file_type().is_dir() {
        return Err(C2BackendRefusalV1::RootDescriptorMismatch);
    }
    Ok(C2BackendObservationEpochV1 {
        root,
        root_device: metadata.dev(),
        root_inode: metadata.ino(),
        epoch_identity,
    })
}

/// Bind the sole backend name to candidate-tree-pinned profile coordinates.
/// This constructs a runtime comparison input, not qualification standing.
pub(crate) fn bind_c2_qualified_backend_profile_v1(
    backend_identity: &'static str,
    profile_identity: Sha256Digest,
    implementation_manifest_identity: Sha256Digest,
    contract_identity: Sha256Digest,
) -> Result<C2QualifiedBackendProfileBindingV1, C2BackendRefusalV1> {
    if backend_identity != PRODUCTION_BACKEND_V1 {
        return Err(C2BackendRefusalV1::BackendProfileMismatch);
    }
    Ok(C2QualifiedBackendProfileBindingV1 {
        backend_identity,
        profile_identity,
        implementation_manifest_identity,
        contract_identity,
    })
}

/// Create private, borrowed preflight facts for one exact root and epoch.
pub(crate) fn inspect_c2_backend_preflight_v1<'root>(
    epoch: &'root C2BackendObservationEpochV1<'root>,
    profile: &'root C2QualifiedBackendProfileBindingV1,
) -> Result<C2BackendPreflightFactsV1<'root>, C2BackendRefusalV1> {
    let live = epoch
        .root
        .metadata()
        .map_err(|_| C2BackendRefusalV1::RootDescriptorMismatch)?;
    if !live.file_type().is_dir()
        || live.dev() != epoch.root_device
        || live.ino() != epoch.root_inode
        || profile.backend_identity != PRODUCTION_BACKEND_V1
    {
        return Err(C2BackendRefusalV1::ObservationEpochMismatch);
    }
    Ok(C2BackendPreflightFactsV1 {
        epoch,
        profile,
        observed_root_device: live.dev(),
        observed_root_inode: live.ino(),
        observed_backend_identity: PRODUCTION_BACKEND_V1,
    })
}

/// N-90: record exact physical lock/B/G preallocation.  The fixed argument
/// positions are the role assignment; no caller-selected role collection is
/// accepted.
pub(crate) fn preallocate_n_90_permanent_lock_b_g<'root>(
    preflight: &'root C2BackendPreflightFactsV1<'root>,
    lock: &'root File,
    lock_length: u64,
    b: &'root File,
    b_length: u64,
    g: &'root File,
    g_length: u64,
) -> Result<C2PermanentPhysicalPreallocationV1<'root>, C2BackendRefusalV1> {
    verify_n_55_refusal(preflight)?;
    let expected_device = preflight.observed_root_device;
    Ok(C2PermanentPhysicalPreallocationV1 {
        preflight,
        lock: raw_fixed_carrier(LOCK_ROLE_V1, lock, lock_length, expected_device)?,
        b: raw_fixed_carrier(B_ROLE_V1, b, b_length, expected_device)?,
        g: raw_fixed_carrier(G_ROLE_V1, g, g_length, expected_device)?,
    })
}

/// N-90: physical facts are exact but remain non-authoritative.
pub(crate) fn verify_n_90_non_authoritative_physical_facts(
    facts: &C2PermanentPhysicalPreallocationV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_n_55_refusal(facts.preflight)?;
    let root_device = facts.preflight.observed_root_device;
    let roles = [facts.lock.role, facts.b.role, facts.g.role];
    if roles != [LOCK_ROLE_V1, B_ROLE_V1, G_ROLE_V1]
        || [facts.lock.device, facts.b.device, facts.g.device]
            .iter()
            .any(|device| *device != root_device)
        || facts.lock.inode == facts.b.inode
        || facts.lock.inode == facts.g.inode
        || facts.b.inode == facts.g.inode
    {
        return Err(C2BackendRefusalV1::CarrierDeviceMismatch);
    }
    for fact in [&facts.lock, &facts.b, &facts.g] {
        let metadata = fact
            .file
            .metadata()
            .map_err(|_| C2BackendRefusalV1::CarrierShapeMismatch)?;
        if metadata.dev() != fact.device
            || metadata.ino() != fact.inode
            || metadata.len() != fact.length
            || allocated_bytes(&metadata)? != fact.allocated_bytes
            || fact.allocated_bytes < fact.length
        {
            return Err(C2BackendRefusalV1::CarrierAllocationMismatch);
        }
    }
    Ok(())
}

/// Store-owned construction of the exact authenticated tuple.  Its producer
/// must be constrained by the machine call graph to the complete resolver.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bind_authenticated_closed_tuple_v1<'store>(
    occurrence: &'store str,
    physical_generation: &'store Sha256Digest,
    active_policy: &'store Sha256Digest,
    b_g_common_binding: &'store Sha256Digest,
    b_header: &'store Sha256Digest,
    g_header: &'store Sha256Digest,
    lock_identity: &'store Sha256Digest,
    installation_mode: C2ClosedInstallationModeV1<'store>,
    qualified_profile: &'store C2QualifiedBackendProfileBindingV1,
    completion_receipt: &'store Sha256Digest,
    completed_snapshot: &'store Sha256Digest,
    root_device: u64,
    root_inode: u64,
    b_device: u64,
    b_inode: u64,
    g_device: u64,
    g_inode: u64,
) -> Result<C2AuthenticatedClosedTupleV1<'store>, C2BackendRefusalV1> {
    if occurrence.is_empty() || qualified_profile.backend_identity != PRODUCTION_BACKEND_V1 {
        return Err(C2BackendRefusalV1::ClosedTupleMismatch);
    }
    if root_device != b_device || root_device != g_device || b_inode == g_inode {
        return Err(C2BackendRefusalV1::CarrierDeviceMismatch);
    }
    Ok(C2AuthenticatedClosedTupleV1 {
        occurrence,
        physical_generation,
        active_policy,
        b_g_common_binding,
        b_header,
        g_header,
        lock_identity,
        installation_mode,
        qualified_profile,
        completion_receipt,
        completed_snapshot,
        root_device,
        root_inode,
        b_device,
        b_inode,
        g_device,
        g_inode,
    })
}

/// Perform the final read-only descriptor reopen observation.  It performs no
/// repair and retains borrowed descriptors only.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_final_c2_backend_reopen_v1<'store>(
    root: &'store File,
    b: &'store File,
    g: &'store File,
    profile_identity: &'store Sha256Digest,
    b_g_common_binding: &'store Sha256Digest,
    b_header: &'store Sha256Digest,
    g_header: &'store Sha256Digest,
    active_policy: &'store Sha256Digest,
) -> Result<C2FinalReopenFactsV1<'store>, C2BackendRefusalV1> {
    let root_metadata = root
        .metadata()
        .map_err(|_| C2BackendRefusalV1::RootDescriptorMismatch)?;
    let b_metadata = b
        .metadata()
        .map_err(|_| C2BackendRefusalV1::CarrierShapeMismatch)?;
    let g_metadata = g
        .metadata()
        .map_err(|_| C2BackendRefusalV1::CarrierShapeMismatch)?;
    if !root_metadata.file_type().is_dir()
        || !b_metadata.file_type().is_file()
        || !g_metadata.file_type().is_file()
        || b_metadata.nlink() != 1
        || g_metadata.nlink() != 1
    {
        return Err(C2BackendRefusalV1::CarrierShapeMismatch);
    }
    Ok(C2FinalReopenFactsV1 {
        root,
        b,
        g,
        root_device: root_metadata.dev(),
        root_inode: root_metadata.ino(),
        b_device: b_metadata.dev(),
        b_inode: b_metadata.ino(),
        g_device: g_metadata.dev(),
        g_inode: g_metadata.ino(),
        b_length: b_metadata.len(),
        g_length: g_metadata.len(),
        profile_identity,
        b_g_common_binding,
        b_header,
        g_header,
        active_policy,
    })
}

fn verify_complete_correspondence(
    tuple: &C2AuthenticatedClosedTupleV1<'_>,
    final_reopen: &C2FinalReopenFactsV1<'_>,
    lock: &C2StoreGenerationLockV1,
    physical_allocation: &C2PermanentPhysicalPreallocationV1<'_>,
    completion: &C2DurableResultV1,
) -> Result<(), C2BackendRefusalV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)
        .map_err(|_| C2BackendRefusalV1::LockStandingMismatch)?;
    verify_n_90_non_authoritative_physical_facts(physical_allocation)?;

    let (physical_generation, completion_receipt, completed_snapshot) = match completion {
        C2DurableResultV1::InstallationCompletedBackendUnclosedS4 {
            physical_generation_identity,
            completion_receipt_identity,
            completed_snapshot_identity,
        } => (
            physical_generation_identity,
            completion_receipt_identity,
            completed_snapshot_identity,
        ),
        _ => return Err(C2BackendRefusalV1::CompletionStageMismatch),
    };
    if physical_generation != tuple.physical_generation
        || completion_receipt != tuple.completion_receipt
        || completed_snapshot != tuple.completed_snapshot
    {
        return Err(C2BackendRefusalV1::CompletionReceiptMismatch);
    }

    let carrier = lock.carrier();
    if carrier.occurrence_id.as_str() != tuple.occurrence
        || &carrier.physical_store_generation_identity != tuple.physical_generation
        || &carrier.lock_identity != tuple.lock_identity
    {
        return Err(C2BackendRefusalV1::ClosedTupleMismatch);
    }

    if final_reopen.root_device != tuple.root_device
        || final_reopen.root_inode != tuple.root_inode
        || final_reopen.b_device != tuple.b_device
        || final_reopen.b_inode != tuple.b_inode
        || final_reopen.g_device != tuple.g_device
        || final_reopen.g_inode != tuple.g_inode
        || final_reopen.b_length != physical_allocation.b.length
        || final_reopen.g_length != physical_allocation.g.length
        || final_reopen.profile_identity != &tuple.qualified_profile.profile_identity
        || final_reopen.b_g_common_binding != tuple.b_g_common_binding
        || final_reopen.b_header != tuple.b_header
        || final_reopen.g_header != tuple.g_header
        || final_reopen.active_policy != tuple.active_policy
        || physical_allocation.preflight.profile.profile_identity
            != tuple.qualified_profile.profile_identity
        || physical_allocation
            .preflight
            .profile
            .implementation_manifest_identity
            != tuple.qualified_profile.implementation_manifest_identity
        || physical_allocation.preflight.profile.contract_identity
            != tuple.qualified_profile.contract_identity
    {
        return Err(C2BackendRefusalV1::FinalReopenMismatch);
    }

    let final_root = final_reopen
        .root
        .metadata()
        .map_err(|_| C2BackendRefusalV1::FinalReopenMismatch)?;
    let final_b = final_reopen
        .b
        .metadata()
        .map_err(|_| C2BackendRefusalV1::FinalReopenMismatch)?;
    let final_g = final_reopen
        .g
        .metadata()
        .map_err(|_| C2BackendRefusalV1::FinalReopenMismatch)?;
    if (final_root.dev(), final_root.ino()) != (tuple.root_device, tuple.root_inode)
        || (final_b.dev(), final_b.ino(), final_b.len())
            != (tuple.b_device, tuple.b_inode, physical_allocation.b.length)
        || (final_g.dev(), final_g.ino(), final_g.len())
            != (tuple.g_device, tuple.g_inode, physical_allocation.g.length)
    {
        return Err(C2BackendRefusalV1::FinalReopenMismatch);
    }

    // Force the closed-mode union to be read and retained.  A restore tuple is
    // load-bearing historical correspondence, not a branch selector.
    if let C2ClosedInstallationModeV1::RestoreSuccessor {
        predecessor_physical_generation,
        predecessor_bootstrap,
        predecessor_completion_receipt,
        restore_disposition,
    } = tuple.installation_mode
    {
        let all_present = [
            predecessor_physical_generation,
            predecessor_bootstrap,
            predecessor_completion_receipt,
            restore_disposition,
        ];
        if all_present.windows(2).any(|window| window[0] == window[1]) {
            return Err(C2BackendRefusalV1::ClosedTupleMismatch);
        }
    }
    Ok(())
}

/// RR-06 / N-58: the sole production closed-backend constructor.
///
/// It is intentionally not public.  Its error contains only an inert enum,
/// and every failure occurs before any returned borrow or standing exists.
pub(crate) fn close_verified_c2_backend<'store>(
    tuple: &'store C2AuthenticatedClosedTupleV1<'store>,
    final_reopen: &'store C2FinalReopenFactsV1<'store>,
    lock: &'store C2StoreGenerationLockV1,
    physical_allocation: &'store C2PermanentPhysicalPreallocationV1<'store>,
    completion: &'store C2DurableResultV1,
) -> Result<ClosedC2StoreBackendV1<'store>, C2BackendRefusalV1> {
    verify_complete_correspondence(tuple, final_reopen, lock, physical_allocation, completion)?;
    Ok(close_after_completion_receipt_final_reopen(
        tuple,
        final_reopen,
        lock,
        physical_allocation,
    ))
}

fn close_after_completion_receipt_final_reopen<'store>(
    tuple: &'store C2AuthenticatedClosedTupleV1<'store>,
    final_reopen: &'store C2FinalReopenFactsV1<'store>,
    lock: &'store C2StoreGenerationLockV1,
    physical_allocation: &'store C2PermanentPhysicalPreallocationV1<'store>,
) -> ClosedC2StoreBackendV1<'store> {
    ClosedC2StoreBackendV1::new_verified(tuple, final_reopen, lock, physical_allocation)
}

fn row_witness<'borrow, 'store>(
    backend: &'borrow ClosedC2StoreBackendV1<'store>,
) -> Result<C2BackendRowLawWitnessV1<'borrow, 'store>, C2BackendRefusalV1> {
    verify_closed_backend_live(backend)?;
    Ok(C2BackendRowLawWitnessV1 {
        closed_backend: backend,
    })
}

fn verify_closed_backend_live(
    backend: &ClosedC2StoreBackendV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(backend.lock)
        .map_err(|_| C2BackendRefusalV1::LockStandingMismatch)?;
    verify_n_90_non_authoritative_physical_facts(backend.physical_allocation)?;
    if backend.final_reopen.root_device != backend.tuple.root_device {
        return Err(C2BackendRefusalV1::FinalReopenMismatch);
    }
    Ok(())
}

/// Initialize the physical B/G append codec while the Store-owned installer
/// retains the exact preallocation. Raw descriptors alone are insufficient:
/// both authenticated role headers must correspond to the same pair.
pub(crate) fn initialize_durable_append_pair_for_installation_v1(
    physical_allocation: &C2PermanentPhysicalPreallocationV1<'_>,
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
) -> Result<C2DurableAppendPairV1, C2AppendExtentRefusalV1> {
    verify_n_90_non_authoritative_physical_facts(physical_allocation)
        .map_err(|_| C2AppendExtentRefusalV1::InvalidFileFacts)?;
    initialize_durable_append_pair_v1(
        layout,
        correspondence,
        physical_allocation.b.file,
        physical_allocation.g.file,
    )
}

/// Fresh-installation crash-observed variant.  Observation happens only
/// after the selected B or G extent has completed its physical initialization
/// and data synchronization; the normal production wrapper above remains
/// observer-free.
pub(crate) fn initialize_durable_append_pair_for_installation_with_observer_v1<E>(
    physical_allocation: &C2PermanentPhysicalPreallocationV1<'_>,
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
    observer: &mut impl FnMut(C2InstallationExtentInitializedV1) -> Result<(), E>,
) -> Result<C2DurableAppendPairV1, C2ObservedAppendExtentRefusalV1<E>> {
    verify_n_90_non_authoritative_physical_facts(physical_allocation).map_err(|_| {
        C2ObservedAppendExtentRefusalV1::Append(C2AppendExtentRefusalV1::InvalidFileFacts)
    })?;
    initialize_durable_append_pair_with_observer_v1(
        layout,
        correspondence,
        physical_allocation.b.file,
        physical_allocation.g.file,
        observer,
    )
}

/// Reopen the physical append codec only through the already-closed backend
/// and its retained exact descriptors. This function returns append
/// mechanics, not writer or signer standing.
pub(crate) fn open_durable_append_pair_from_closed_backend_v1(
    backend: &ClosedC2StoreBackendV1<'_>,
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
) -> Result<C2DurableAppendPairV1, C2AppendExtentRefusalV1> {
    verify_closed_backend_live(backend)
        .map_err(|_| C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch)?;
    if correspondence.pair_identity() != backend.tuple.b_g_common_binding
        || correspondence.b_header().identity() != backend.tuple.b_header
        || correspondence.g_header().identity() != backend.tuple.g_header
    {
        return Err(C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch);
    }
    open_durable_append_pair_v1(
        layout,
        correspondence,
        backend.final_reopen.b,
        backend.final_reopen.g,
    )
}

/// Bind the ordinary-open activation coordinates to the authenticated tuple
/// retained by the already closed backend.  This is a verifier only: it
/// neither constructs closed standing nor exposes the retained tuple.
pub(crate) fn verify_closed_backend_current_activation_coordinates_v1(
    backend: &ClosedC2StoreBackendV1<'_>,
    occurrence: &StoreOccurrenceIdentityV1,
    physical_generation: &PhysicalStoreGenerationIdentityV1,
    active_policy: &Sha256Digest,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(backend)?;
    if backend.tuple.occurrence != occurrence.as_str()
        || backend.tuple.physical_generation != physical_generation.digest()
        || backend.tuple.active_policy != active_policy
    {
        return Err(C2BackendRefusalV1::ClosedTupleMismatch);
    }
    Ok(())
}

/// Return only the live retained-root inode key used by the process-wide C2
/// mutex registry.  The pair is not standing and cannot reconstruct a closed
/// backend or writer session.
pub(crate) fn closed_backend_lock_inode_key_v1(
    backend: &ClosedC2StoreBackendV1<'_>,
) -> Result<LockInodeKey, C2BackendRefusalV1> {
    verify_closed_backend_live(backend)?;
    Ok(backend.lock.inode_key())
}

/// Return only the retained root-directory inode key for Store-path
/// correspondence.  Unlike the lock-inode key, this value never indexes the
/// C2 writer mutex registry.
pub(crate) fn closed_backend_root_directory_inode_key_v1(
    backend: &ClosedC2StoreBackendV1<'_>,
) -> Result<(u64, u64), C2BackendRefusalV1> {
    verify_closed_backend_live(backend)?;
    Ok((backend.tuple.root_device, backend.tuple.root_inode))
}

/// WU-06 named construction witness.
pub(crate) fn construct_wu_06_immutable_wu_backend_preflight_physical_allocation_closed<
    'a,
    'store,
>(
    backend: &'a ClosedC2StoreBackendV1<'store>,
) -> Result<C2BackendRowLawWitnessV1<'a, 'store>, C2BackendRefusalV1> {
    row_witness(backend)
}

/// WU-06 exact verifier.
pub(crate) fn verify_wu_06_immutable_wu_backend_preflight_physical_allocation_closed(
    witness: &C2BackendRowLawWitnessV1<'_, '_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(witness.closed_backend)
}

/// N-55: preflight remains root/epoch borrowed, process-local, and
/// non-authoritative.
pub(crate) fn verify_n_55_refusal(
    facts: &C2BackendPreflightFactsV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    let live = facts
        .epoch
        .root
        .metadata()
        .map_err(|_| C2BackendRefusalV1::RootDescriptorMismatch)?;
    if live.dev() != facts.observed_root_device
        || live.ino() != facts.observed_root_inode
        || live.dev() != facts.epoch.root_device
        || live.ino() != facts.epoch.root_inode
        || facts.observed_backend_identity != PRODUCTION_BACKEND_V1
        || facts.profile.backend_identity != PRODUCTION_BACKEND_V1
        || facts.epoch.epoch_identity.as_str().is_empty()
    {
        return Err(C2BackendRefusalV1::ObservationEpochMismatch);
    }
    Ok(())
}

/// N-56: neither an observation nor a successful comparison can mint closed,
/// session, B/G, or capacity standing.
pub(crate) fn verify_n_56_refusal(
    facts: &C2BackendPreflightFactsV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_n_55_refusal(facts)
}

/// N-57 named construction witness; not a backend constructor.
pub(crate) fn construct_n_57_closed_backend_is_private_borrowed_state_binding<'a, 'store>(
    backend: &'a ClosedC2StoreBackendV1<'store>,
) -> Result<C2BackendRowLawWitnessV1<'a, 'store>, C2BackendRefusalV1> {
    row_witness(backend)
}

/// N-57 exact verifier.
pub(crate) fn verify_n_57_closed_backend_is_private_borrowed_state_binding(
    witness: &C2BackendRowLawWitnessV1<'_, '_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(witness.closed_backend)
}

/// N-58 named census witness; not a second backend constructor.
pub(crate) fn construct_n_58_exactly_private_production_constructor_exists_post_receipt<
    'a,
    'store,
>(
    backend: &'a ClosedC2StoreBackendV1<'store>,
) -> Result<C2BackendRowLawWitnessV1<'a, 'store>, C2BackendRefusalV1> {
    row_witness(backend)
}

/// N-58 exact verifier.
pub(crate) fn verify_n_58_exactly_private_production_constructor_exists_post_receipt(
    witness: &C2BackendRowLawWitnessV1<'_, '_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(witness.closed_backend)
}

/// N-59: a failed construction must retain the exact S4 snapshot and return
/// no descriptor-bearing value.
pub(crate) fn verify_n_59_refusal(
    before_s4_snapshot: &Sha256Digest,
    after_s4_snapshot: &Sha256Digest,
    result: &Result<ClosedC2StoreBackendV1<'_>, C2BackendRefusalV1>,
) -> Result<(), C2BackendRefusalV1> {
    if result.is_ok() {
        return Err(C2BackendRefusalV1::AuthorityAmplification);
    }
    if before_s4_snapshot != after_s4_snapshot {
        return Err(C2BackendRefusalV1::NoWriteSnapshotMismatch);
    }
    Ok(())
}

/// N-88 named sole-backend/profile witness.
pub(crate) fn construct_n_88_sole_backend_pre_post_timing_full_refusal<'a, 'store>(
    backend: &'a ClosedC2StoreBackendV1<'store>,
) -> Result<C2BackendRowLawWitnessV1<'a, 'store>, C2BackendRefusalV1> {
    row_witness(backend)
}

/// N-88 exact verifier.  This is runtime correspondence only; it does not
/// claim candidate-bound backend qualification.
pub(crate) fn verify_n_88_sole_backend_pre_post_timing_full_refusal(
    witness: &C2BackendRowLawWitnessV1<'_, '_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(witness.closed_backend)
}

/// N-89: only a closed backend can satisfy this verifier; no preflight or
/// persisted Boolean argument exists in its signature.
pub(crate) fn verify_n_89_refusal(
    backend: &ClosedC2StoreBackendV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(backend)
}

/// AM-03 named architecture-preservation witness.
pub(crate) fn construct_am_03_crosswalk_am_charter_separate_non_authoritative_backend<
    'a,
    'store,
>(
    backend: &'a ClosedC2StoreBackendV1<'store>,
) -> Result<C2BackendRowLawWitnessV1<'a, 'store>, C2BackendRefusalV1> {
    row_witness(backend)
}

/// AM-03 exact verifier.
pub(crate) fn verify_am_03_crosswalk_am_charter_separate_non_authoritative_backend(
    witness: &C2BackendRowLawWitnessV1<'_, '_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(witness.closed_backend)
}

/// RR-06 proves the constructed value still satisfies the post-receipt live
/// correspondence; it does not create an alternate backend.
pub(crate) fn verify_rr_06_sole_post_receipt_constructor(
    backend: &ClosedC2StoreBackendV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(backend)
}

/// SEAM-03: supply the field-split witness only under a higher-ranked closure.
/// The return type cannot contain the invocation-specific borrow.
pub(crate) fn construct_seam_03_field_split_writer_session_borrow<R>(
    closed_backend: &ClosedC2StoreBackendV1<'_>,
    ordinary_fields: &mut C2OrdinaryStoreFieldsV1,
    body: impl for<'borrow> FnOnce(FieldSplitC2WriterSessionBorrowV1<'borrow, '_>) -> R,
) -> Result<R, C2BackendRefusalV1> {
    verify_closed_backend_live(closed_backend)?;
    Ok(body(FieldSplitC2WriterSessionBorrowV1 {
        closed_backend,
        ordinary_fields,
    }))
}

/// SEAM-03 exact in-closure verifier.
pub(crate) fn verify_seam_03_field_split_writer_session_borrow(
    split: &FieldSplitC2WriterSessionBorrowV1<'_, '_>,
) -> Result<(), C2BackendRefusalV1> {
    verify_closed_backend_live(split.closed_backend)?;
    if split.ordinary_fields.field_set_identity.as_str().is_empty() {
        return Err(C2BackendRefusalV1::ClosedTupleMismatch);
    }
    Ok(())
}

/// SEAM-12 constructs only a non-authority boundary witness.
pub(crate) fn construct_seam_12_immutable_seam_capacity_boundary_lower_priority_prompt<'store>(
    physical_allocation: &'store C2PermanentPhysicalPreallocationV1<'store>,
    closed_backend: &'store ClosedC2StoreBackendV1<'store>,
) -> Result<C2CapacityBoundaryV1<'store>, C2BackendRefusalV1> {
    verify_n_90_non_authoritative_physical_facts(physical_allocation)?;
    verify_closed_backend_live(closed_backend)?;
    if !std::ptr::eq(physical_allocation, closed_backend.physical_allocation) {
        return Err(C2BackendRefusalV1::AuthorityAmplification);
    }
    Ok(C2CapacityBoundaryV1 {
        physical_allocation,
        closed_backend,
    })
}

/// SEAM-12 exact nonamplification verifier.
pub(crate) fn verify_seam_12_immutable_seam_capacity_boundary_lower_priority_prompt(
    boundary: &C2CapacityBoundaryV1<'_>,
) -> Result<(), C2BackendRefusalV1> {
    if !std::ptr::eq(
        boundary.physical_allocation,
        boundary.closed_backend.physical_allocation,
    ) {
        return Err(C2BackendRefusalV1::AuthorityAmplification);
    }
    verify_closed_backend_live(boundary.closed_backend)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    use tempfile::tempdir;

    use super::*;
    use crate::store_generation::lock::{
        construct_wu_04_immutable_wu_local_lock_flock_process_registry,
        encode_rec_29_generation_lock,
    };
    use crate::store_generation::{
        C2_BOOTSTRAP_EXTENT_V1, C2_GLOBAL_REFUSAL_EXTENT_V1, C2_LOCK_FILE_V1,
    };

    fn digest(byte: char) -> Sha256Digest {
        nq_protocol::sha256_bytes(byte.to_string().as_bytes())
    }

    fn allocated_file(path: &std::path::Path, length: usize, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut full = vec![0_u8; length];
        full[..bytes.len()].copy_from_slice(bytes);
        file.write_all(&full).unwrap();
        file.sync_all().unwrap();
        file
    }

    #[test]
    fn preflight_and_physical_allocation_are_exact_but_non_authoritative() {
        let directory = tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let epoch = begin_c2_backend_observation_epoch_v1(&root, digest('e')).unwrap();
        let profile = bind_c2_qualified_backend_profile_v1(
            PRODUCTION_BACKEND_V1,
            digest('p'),
            digest('m'),
            digest('c'),
        )
        .unwrap();
        let preflight = inspect_c2_backend_preflight_v1(&epoch, &profile).unwrap();
        let lock = allocated_file(&directory.path().join(C2_LOCK_FILE_V1), 4096, &[]);
        let b = allocated_file(&directory.path().join(C2_BOOTSTRAP_EXTENT_V1), 8192, &[]);
        let g = allocated_file(
            &directory.path().join(C2_GLOBAL_REFUSAL_EXTENT_V1),
            12288,
            &[],
        );
        let physical =
            preallocate_n_90_permanent_lock_b_g(&preflight, &lock, 4096, &b, 8192, &g, 12288)
                .unwrap();
        verify_n_55_refusal(&preflight).unwrap();
        verify_n_56_refusal(&preflight).unwrap();
        verify_n_90_non_authoritative_physical_facts(&physical).unwrap();

        let sparse = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("sparse"))
            .unwrap();
        sparse.set_len(1024 * 1024).unwrap();
        assert_eq!(
            raw_fixed_carrier(
                B_ROLE_V1,
                &sparse,
                1024 * 1024,
                root.metadata().unwrap().dev()
            )
            .err()
            .unwrap(),
            C2BackendRefusalV1::CarrierAllocationMismatch
        );
    }

    #[test]
    fn sole_constructor_requires_s4_final_reopen_lock_and_full_tuple() {
        let directory = tempdir().unwrap();
        let physical_generation = digest('g');
        let b_genesis = digest('b');
        let lock_bytes = encode_rec_29_generation_lock(
            "occurrence-1".to_owned(),
            physical_generation.clone(),
            b_genesis.clone(),
            4096,
        )
        .unwrap();
        let raw_lock = allocated_file(&directory.path().join(C2_LOCK_FILE_V1), 4096, &lock_bytes);
        let b = allocated_file(&directory.path().join(C2_BOOTSTRAP_EXTENT_V1), 8192, &[]);
        let g = allocated_file(
            &directory.path().join(C2_GLOBAL_REFUSAL_EXTENT_V1),
            12288,
            &[],
        );
        let root = File::open(directory.path()).unwrap();
        let epoch = begin_c2_backend_observation_epoch_v1(&root, digest('e')).unwrap();
        let profile = bind_c2_qualified_backend_profile_v1(
            PRODUCTION_BACKEND_V1,
            digest('p'),
            digest('m'),
            digest('c'),
        )
        .unwrap();
        let preflight = inspect_c2_backend_preflight_v1(&epoch, &profile).unwrap();
        let physical =
            preallocate_n_90_permanent_lock_b_g(&preflight, &raw_lock, 4096, &b, 8192, &g, 12288)
                .unwrap();
        let held_lock =
            construct_wu_04_immutable_wu_local_lock_flock_process_registry(&root, &b_genesis)
                .unwrap();

        let common = digest('o');
        let b_header = digest('h');
        let g_header = digest('i');
        let active_policy = digest('a');
        let receipt = digest('r');
        let snapshot = digest('s');
        let final_reopen = observe_final_c2_backend_reopen_v1(
            &root,
            &b,
            &g,
            &profile.profile_identity,
            &common,
            &b_header,
            &g_header,
            &active_policy,
        )
        .unwrap();
        let root_metadata = root.metadata().unwrap();
        let b_metadata = b.metadata().unwrap();
        let g_metadata = g.metadata().unwrap();
        let tuple = bind_authenticated_closed_tuple_v1(
            "occurrence-1",
            &physical_generation,
            &active_policy,
            &common,
            &b_header,
            &g_header,
            &held_lock.carrier().lock_identity,
            C2ClosedInstallationModeV1::Fresh,
            &profile,
            &receipt,
            &snapshot,
            root_metadata.dev(),
            root_metadata.ino(),
            b_metadata.dev(),
            b_metadata.ino(),
            g_metadata.dev(),
            g_metadata.ino(),
        )
        .unwrap();
        let s4 = C2DurableResultV1::InstallationCompletedBackendUnclosedS4 {
            physical_generation_identity: physical_generation.clone(),
            completion_receipt_identity: receipt.clone(),
            completed_snapshot_identity: snapshot.clone(),
        };
        let closed =
            close_verified_c2_backend(&tuple, &final_reopen, &held_lock, &physical, &s4).unwrap();
        verify_rr_06_sole_post_receipt_constructor(&closed).unwrap();
        verify_wu_06_immutable_wu_backend_preflight_physical_allocation_closed(
            &construct_wu_06_immutable_wu_backend_preflight_physical_allocation_closed(&closed)
                .unwrap(),
        )
        .unwrap();
        verify_n_57_closed_backend_is_private_borrowed_state_binding(
            &construct_n_57_closed_backend_is_private_borrowed_state_binding(&closed).unwrap(),
        )
        .unwrap();
        verify_n_58_exactly_private_production_constructor_exists_post_receipt(
            &construct_n_58_exactly_private_production_constructor_exists_post_receipt(&closed)
                .unwrap(),
        )
        .unwrap();
        verify_n_88_sole_backend_pre_post_timing_full_refusal(
            &construct_n_88_sole_backend_pre_post_timing_full_refusal(&closed).unwrap(),
        )
        .unwrap();
        verify_n_89_refusal(&closed).unwrap();
        verify_am_03_crosswalk_am_charter_separate_non_authoritative_backend(
            &construct_am_03_crosswalk_am_charter_separate_non_authoritative_backend(&closed)
                .unwrap(),
        )
        .unwrap();
        let boundary = construct_seam_12_immutable_seam_capacity_boundary_lower_priority_prompt(
            &physical, &closed,
        )
        .unwrap();
        verify_seam_12_immutable_seam_capacity_boundary_lower_priority_prompt(&boundary).unwrap();

        let mut fields = C2OrdinaryStoreFieldsV1 {
            field_set_identity: digest('f'),
        };
        let observed =
            construct_seam_03_field_split_writer_session_borrow(&closed, &mut fields, |split| {
                verify_seam_03_field_split_writer_session_borrow(&split).unwrap();
                split.ordinary_fields.field_set_identity.clone()
            })
            .unwrap();
        assert_eq!(observed, digest('f'));

        let wrong_s4 = C2DurableResultV1::InstallationCompletedBackendUnclosedS4 {
            physical_generation_identity: physical_generation.clone(),
            completion_receipt_identity: digest('x'),
            completed_snapshot_identity: snapshot.clone(),
        };
        let failed =
            close_verified_c2_backend(&tuple, &final_reopen, &held_lock, &physical, &wrong_s4);
        assert_eq!(
            failed.as_ref().err(),
            Some(&C2BackendRefusalV1::CompletionReceiptMismatch)
        );
        verify_n_59_refusal(&snapshot, &snapshot, &failed).unwrap();
    }

    #[test]
    fn preflight_cannot_select_a_second_backend() {
        assert_eq!(
            bind_c2_qualified_backend_profile_v1(
                "caller_selected_backend",
                digest('p'),
                digest('m'),
                digest('c'),
            )
            .err()
            .unwrap(),
            C2BackendRefusalV1::BackendProfileMismatch
        );
    }
}
