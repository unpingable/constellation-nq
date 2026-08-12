//! Closed installation/continuation state machine for C2 Store generations.
//!
//! This module models the five special construction roots and the finite
//! S0--S5 durable-result law.  Its brands are crate-private to construct,
//! linear to consume, and expose no ordinary Store mutation surface.

use std::fs::File;
use std::io;
#[cfg(test)]
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

use nix::fcntl::{FallocateFlags, fallocate};
use nq_protocol::Sha256Digest;
use rustix::fs::{Mode, OFlags, openat};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::lock::{
    C2ProvisionalStoreGenerationLockV1, acquire_provisional_generation_flock_v1,
    reserve_provisional_generation_inode_v1,
};

/// Type-level fresh-installation mode.
#[cfg(test)]
#[derive(Debug)]
pub enum FreshV1 {}

/// Type-level restore-successor installation mode.
#[cfg(test)]
#[derive(Debug)]
pub enum RestoreSuccessorV1 {}

/// Runtime reflection of the two disjoint bootstrap modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2BootstrapModeV1 {
    Fresh,
    RestoreSuccessor,
}

/// Proof that fresh and restore brands are not interchangeable.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2BootstrapModeDisjointnessV1;

/// Exact restore predecessor tuple.  It is absent in fresh mode and complete
/// in restore-successor mode.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2RestoreInstallationPredecessorV1 {
    physical_generation_identity: Sha256Digest,
    bootstrap_identity: Sha256Digest,
    completion_receipt_identity: Sha256Digest,
    restore_disposition_identity: Sha256Digest,
    restore_proof_identity: Sha256Digest,
    predecessor_cut: u64,
}

/// Every pre-write fact consumed by the mode-specific brand constructor.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2InstallationPrerequisitesV1 {
    pub mode: C2BootstrapModeV1,
    pub gen4_resolution_identity: Sha256Digest,
    pub controlling_activation_identity: Sha256Digest,
    pub install_policy_identity: Sha256Digest,
    pub enrollment_identity: Sha256Digest,
    pub physical_lineage_identity: Sha256Digest,
    pub root_descriptor_identity: Sha256Digest,
    pub creation_mutex_identity: Sha256Digest,
    pub root_shape_identity: Sha256Digest,
    pub backend_preflight_identity: Sha256Digest,
    pub qualified_profile_identity: Sha256Digest,
    pub installation_cut: u64,
    pub restore_predecessor: Option<C2RestoreInstallationPredecessorV1>,
}

/// Private bootstrap brand; callers cannot construct its field.
#[cfg(test)]
#[derive(Debug)]
pub struct C2BootstrapBrandV1<Mode> {
    prerequisites: C2InstallationPrerequisitesV1,
    _mode: PhantomData<Mode>,
}

/// Linear bootstrap session.  It exposes only `run_installation`, which
/// consumes the session and returns a durable result.
#[cfg(test)]
#[derive(Debug)]
pub struct C2BootstrapSessionV1<Mode> {
    brand: C2BootstrapBrandV1<Mode>,
}

/// Linear authority to perform the pending schema-v9 projection step after
/// the immutable installation prefix has been durably synchronized.
///
/// There is intentionally no production constructor yet.  The ordered,
/// Store-owned installation driver must eventually construct this value only
/// after retaining the exact root, permanent-lock, B/G carrier, signed-intent,
/// and prefix-sync witnesses assigned to the `PersistPendingSqlProjection`
/// step.  Until that driver exists, the schema mutator is unreachable from
/// production code rather than being exposed through a path-only shortcut.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct C2PendingSqlProjectionPermitV1<Mode> {
    verified_source: crate::schema::VerifiedC2SchemaV8ToV9Sequential,
    _mode: PhantomData<Mode>,
}

#[cfg(test)]
impl<Mode> C2PendingSqlProjectionPermitV1<Mode> {
    pub(crate) fn into_verified_source(self) -> crate::schema::VerifiedC2SchemaV8ToV9Sequential {
        self.verified_source
    }
}

/// Compile-confined positive control for the exact migration transaction.
/// It is not an installation authority source and is absent from product
/// builds; production construction remains intentionally unavailable until
/// the ordered Store-owned driver is implemented.
#[cfg(test)]
pub(crate) fn c2_pending_sql_projection_permit_for_test<Mode>(
    verified_source: crate::schema::VerifiedC2SchemaV8ToV9Sequential,
) -> C2PendingSqlProjectionPermitV1<Mode> {
    C2PendingSqlProjectionPermitV1 {
        verified_source,
        _mode: PhantomData,
    }
}

/// Exact admissible installation-continuation prefix.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2InstallationPrefixStageV1 {
    S2PreGAuthentication,
    S3GAuthenticatedInstallationIncomplete,
}

/// One Store-observed installation prefix.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2InstallationPrefixV1 {
    signed_intent_identity: Option<Sha256Digest>,
    prefix_identity: Sha256Digest,
    stage: C2InstallationPrefixStageV1,
    profile_identity: Sha256Digest,
}

/// Private exact-intent continuation brand.
#[cfg(test)]
#[derive(Debug)]
pub struct C2InstallationContinuationBrandV1 {
    signed_intent_identity: Sha256Digest,
    prefix_identity: Sha256Digest,
    stage: C2InstallationPrefixStageV1,
    profile_identity: Sha256Digest,
}

/// Exact order of the noncircular installation construction graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2InstallationStepV1 {
    AuthenticateAuthorityAndPolicy,
    VerifyPhysicalLineage,
    AcquireCreationMutex,
    VerifyProfilePreflight,
    ConstructModeBrand,
    CreatePermanentLockExclusive,
    TransferToLockIdentityMutexAndFlock,
    PreallocateFixedCarriers,
    VerifyPerEffectProfile,
    DerivePhysicalGenerationIdentity,
    PersistSignedBootstrapHeadersAndIntent,
    SyncImmutablePrefix,
    PersistPendingSqlProjection,
    ReopenAndVerifyPreReceipt,
    PersistCompletionReceipt,
    ReopenAndVerifyCompletedGeneration,
    ConstructClosedBackend,
}

/// Closed durable-result variants.  There is deliberately no catch-all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum C2DurableResultV1 {
    ExactNoWrite {
        snapshot_identity: Sha256Digest,
    },
    InstallationQuarantinedPrefixS1 {
        prefix_identity: Sha256Digest,
    },
    InstallationQuarantinedPrefixS2 {
        prefix_identity: Sha256Digest,
        signed_intent_identity: Option<Sha256Digest>,
    },
    InstallationQuarantinedPrefixS3 {
        prefix_identity: Sha256Digest,
        signed_intent_identity: Sha256Digest,
        authenticated_g_header_identity: Sha256Digest,
    },
    InstallationCompletedBackendUnclosedS4 {
        physical_generation_identity: Sha256Digest,
        completion_receipt_identity: Sha256Digest,
        completed_snapshot_identity: Sha256Digest,
    },
    InstallationCompletedClosedS5 {
        physical_generation_identity: Sha256Digest,
        completion_receipt_identity: Sha256Digest,
        closed_backend_identity: Sha256Digest,
        g_reservation_policy_identity: Sha256Digest,
    },
    TransitionQuarantinedIntentPrefix {
        transition_intent_identity: Sha256Digest,
        prefix_identity: Sha256Digest,
        cut: u64,
    },
    TransitionCompleted {
        transition_identity: Sha256Digest,
        receipt_identity: Sha256Digest,
        completed_frontier_identity: Sha256Digest,
    },
}

/// State machine retains only one forward durable result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2InstallationStateMachineV1 {
    operation_identity: Sha256Digest,
    mode: C2BootstrapModeV1,
    steps: Vec<C2InstallationStepV1>,
    durable_result: C2DurableResultV1,
}

/// Closed crash-cut classifier for load-bearing installation I/O.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2IoCutV1 {
    RootShapeObservation,
    CreationMutexAcquisition,
    BackendProfilePreflight,
    PermanentLockCreate,
    PermanentLockFstat,
    LockMutexTransfer,
    PermanentFlockAcquisition,
    BCarrierCreate,
    BCarrierAllocation,
    GCarrierCreate,
    GCarrierAllocation,
    BootstrapIntentAppend,
    BHeaderWrite,
    GHeaderWrite,
    ImmutablePrefixSync,
    DirectorySync,
    PendingSqlBeginImmediate,
    PendingSqlProjectionInsert,
    PendingSqlCommit,
    PreReceiptDescriptorReopen,
    CompletionReceiptAppend,
    CompletionReceiptSync,
    CompletedDescriptorReopen,
    ClosedBackendConstruction,
    PolicyTransitionIntentAppend,
    AuthoritySuccessorAppend,
    PolicySuccessorAppend,
    TransitionReceiptAppend,
    TransitionReceiptSync,
    BoundedHandleCleanup,
}

/// No-write/refusal classification for installation state.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InstallationRefusalV1 {
    #[error("fresh and restore-successor prerequisite sets were substituted")]
    ModeMismatch,
    #[error("the restore predecessor tuple is absent, partial, or not earlier")]
    RestorePredecessorMismatch,
    #[error("installation may begin only from established Gen4 evidence")]
    Gen4NotEstablished,
    #[error("the installation sequence is not the exact acyclic sequence")]
    SequenceMismatch,
    #[error("zero or multiple admissible intent-bearing prefixes were supplied")]
    PrefixCardinality,
    #[error("the signed intent, prefix, frontier, or profile is substituted")]
    PrefixMismatch,
    #[error("ordinary open or recovery cannot complete an installation")]
    OrdinaryCompletionForbidden,
    #[error("a stage attempted to mint standing outside its exact boundary")]
    PrematureStanding,
    #[error("S5 cannot downgrade to an installation-prefix stage")]
    PhaseDowngrade,
    #[error("an S1/S2/S3 durable result violates its closed prefix law")]
    QuarantinedPrefixMismatch,
    #[error("an S4/S5 durable result violates completion correspondence")]
    CompletionMismatch,
    #[error("the finite I/O cut is absent from the exact manifest")]
    UnclassifiedIoCut,
}

/// Typed I/O refusal for the production installation prefix.  A failure never
/// removes or rewrites an already-created fixed carrier: the exact prefix is
/// retained for restart classification and generic-writer refusal.
#[derive(Debug, Error)]
pub(crate) enum C2LiveInstallationRefusalV1 {
    #[error("a fixed C2 carrier already exists; installation is partial or complete")]
    ExistingC2Footprint,
    #[error("a fixed C2 carrier is not an exact one-link allocated regular file")]
    CarrierShapeMismatch,
    #[error("the installation I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("the installation crash specimen stopped after {0:?}")]
    InjectedCrash(C2IoCutV1),
}

/// Test/qualification observation point for every reachable production I/O
/// cut. Production uses `NoC2InstallationCrashV1`; only tests can request an
/// abrupt stop. The hook runs after the named durable/observable effect, so
/// the next cut's entry is also the exact "before" boundary.
pub(super) trait C2InstallationCrashObserverV1 {
    fn after_cut(&mut self, cut: C2IoCutV1) -> Result<(), C2LiveInstallationRefusalV1>;
}

pub(super) struct NoC2InstallationCrashV1;

impl C2InstallationCrashObserverV1 for NoC2InstallationCrashV1 {
    fn after_cut(&mut self, _cut: C2IoCutV1) -> Result<(), C2LiveInstallationRefusalV1> {
        #[cfg(test)]
        if observe_test_bootstrap_installation_cut_v1(_cut) {
            return Err(C2LiveInstallationRefusalV1::InjectedCrash(_cut));
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone)]
struct TestBootstrapInstallationObserverV1 {
    stop_after: Option<C2IoCutV1>,
    observed: std::rc::Rc<std::cell::RefCell<Vec<C2IoCutV1>>>,
}

#[cfg(test)]
thread_local! {
    static TEST_BOOTSTRAP_INSTALLATION_OBSERVER_V1:
        std::cell::RefCell<Option<TestBootstrapInstallationObserverV1>> = const {
            std::cell::RefCell::new(None)
        };
}

#[cfg(test)]
fn observe_test_bootstrap_installation_cut_v1(cut: C2IoCutV1) -> bool {
    TEST_BOOTSTRAP_INSTALLATION_OBSERVER_V1.with(|slot| {
        let active = slot.borrow();
        let Some(active) = active.as_ref() else {
            return false;
        };
        active.observed.borrow_mut().push(cut);
        active.stop_after == Some(cut)
    })
}

/// Test-only injection around the production `NoC2InstallationCrashV1`
/// observer. The thread-local scope cannot affect another test thread or any
/// non-test build, and the guard clears the injection during unwinding.
#[cfg(test)]
pub(super) fn with_test_bootstrap_installation_observer_v1<R>(
    stop_after: Option<C2IoCutV1>,
    operation: impl FnOnce() -> R,
) -> (R, Vec<C2IoCutV1>) {
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_BOOTSTRAP_INSTALLATION_OBSERVER_V1.with(|slot| {
                slot.replace(None);
            });
        }
    }

    let observed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    TEST_BOOTSTRAP_INSTALLATION_OBSERVER_V1.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "nested C2 crash injection is forbidden"
        );
        slot.replace(Some(TestBootstrapInstallationObserverV1 {
            stop_after,
            observed: observed.clone(),
        }));
    });
    let reset = Reset;
    let result = operation();
    let observed = observed.borrow().clone();
    drop(reset);
    (result, observed)
}

/// Exact newly allocated fixed C2 footprint. It owns the descriptors and is
/// inert until the Store driver authenticates headers, signed intent and the
/// complete S4 receipt. Raw allocation never constructs writer/signer
/// standing.
pub(super) struct C2AllocatedFixedFilesV1 {
    lock: C2ProvisionalStoreGenerationLockV1,
    b: File,
    g: File,
}

impl C2AllocatedFixedFilesV1 {
    pub(super) fn lock(&self) -> &File {
        self.lock.file()
    }

    pub(super) const fn b(&self) -> &File {
        &self.b
    }

    pub(super) const fn g(&self) -> &File {
        &self.g
    }

    /// Consume the allocation only when the Store-owned driver is ready to
    /// publish REC-29. B/G descriptors remain owned by the same result.
    pub(super) fn into_parts(self) -> (C2ProvisionalStoreGenerationLockV1, File, File) {
        (self.lock, self.b, self.g)
    }
}

fn create_fixed_file(
    root: &File,
    name: &str,
    length: u64,
) -> Result<File, C2LiveInstallationRefusalV1> {
    let raw = openat(
        root,
        name,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            C2LiveInstallationRefusalV1::ExistingC2Footprint
        } else {
            C2LiveInstallationRefusalV1::Io(io::Error::from(error))
        }
    })?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-01");
    let file = File::from(raw);
    let length_i64 =
        i64::try_from(length).map_err(|_| C2LiveInstallationRefusalV1::CarrierShapeMismatch)?;
    fallocate(file.as_raw_fd(), FallocateFlags::empty(), 0, length_i64).map_err(io::Error::from)?;
    file.set_len(length)?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-02");
    Ok(file)
}

fn verify_allocated_file(
    file: &File,
    length: u64,
    root_device: u64,
) -> Result<(), C2LiveInstallationRefusalV1> {
    let metadata = file.metadata()?;
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or(C2LiveInstallationRefusalV1::CarrierShapeMismatch)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.dev() != root_device
        || metadata.len() != length
        || allocated < length
    {
        return Err(C2LiveInstallationRefusalV1::CarrierShapeMismatch);
    }
    Ok(())
}

/// Create and physically allocate the exact fixed lock/B/G footprint.
///
/// This helper is visible only inside `store_generation`; the sole production
/// caller is `StoreC2SnapshotActorV1::install_c2_live_v1`, which already owns
/// authority, the maintenance lock and the retained root descriptor. Any
/// failure intentionally leaves the observable partial prefix in place.
pub(super) fn allocate_live_c2_fixed_files_v1(
    root: &File,
    lock_length: u64,
    b_length: u64,
    g_length: u64,
    observer: &mut impl C2InstallationCrashObserverV1,
) -> Result<C2AllocatedFixedFilesV1, C2LiveInstallationRefusalV1> {
    let root_metadata = root.metadata()?;
    if !root_metadata.file_type().is_dir() {
        return Err(C2LiveInstallationRefusalV1::CarrierShapeMismatch);
    }
    observer.after_cut(C2IoCutV1::RootShapeObservation)?;

    let lock_file = create_fixed_file(root, super::C2_LOCK_FILE_V1, lock_length)?;
    observer.after_cut(C2IoCutV1::PermanentLockCreate)?;
    verify_allocated_file(&lock_file, lock_length, root_metadata.dev())?;
    observer.after_cut(C2IoCutV1::PermanentLockFstat)?;
    lock_file.sync_all()?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-03");
    let lock_reservation = reserve_provisional_generation_inode_v1(lock_file)
        .map_err(|error| C2LiveInstallationRefusalV1::Io(io::Error::other(error)))?;
    observer.after_cut(C2IoCutV1::LockMutexTransfer)?;
    let lock = acquire_provisional_generation_flock_v1(lock_reservation)
        .map_err(|error| C2LiveInstallationRefusalV1::Io(io::Error::other(error)))?;
    observer.after_cut(C2IoCutV1::PermanentFlockAcquisition)?;

    let b = create_fixed_file(root, super::C2_BOOTSTRAP_EXTENT_V1, b_length)?;
    observer.after_cut(C2IoCutV1::BCarrierCreate)?;
    verify_allocated_file(&b, b_length, root_metadata.dev())?;
    b.sync_all()?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-04");
    observer.after_cut(C2IoCutV1::BCarrierAllocation)?;

    let g = create_fixed_file(root, super::C2_GLOBAL_REFUSAL_EXTENT_V1, g_length)?;
    observer.after_cut(C2IoCutV1::GCarrierCreate)?;
    verify_allocated_file(&g, g_length, root_metadata.dev())?;
    g.sync_all()?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-05");
    observer.after_cut(C2IoCutV1::GCarrierAllocation)?;

    root.sync_all()?;
    #[cfg(test)]
    super::source_io_crash_test_support::after_source_io_v1("SC-06");
    observer.after_cut(C2IoCutV1::DirectorySync)?;
    Ok(C2AllocatedFixedFilesV1 { lock, b, g })
}

const EXACT_INSTALLATION_SEQUENCE: [C2InstallationStepV1; 17] = [
    C2InstallationStepV1::AuthenticateAuthorityAndPolicy,
    C2InstallationStepV1::VerifyPhysicalLineage,
    C2InstallationStepV1::AcquireCreationMutex,
    C2InstallationStepV1::VerifyProfilePreflight,
    C2InstallationStepV1::ConstructModeBrand,
    C2InstallationStepV1::CreatePermanentLockExclusive,
    C2InstallationStepV1::TransferToLockIdentityMutexAndFlock,
    C2InstallationStepV1::PreallocateFixedCarriers,
    C2InstallationStepV1::VerifyPerEffectProfile,
    C2InstallationStepV1::DerivePhysicalGenerationIdentity,
    C2InstallationStepV1::PersistSignedBootstrapHeadersAndIntent,
    C2InstallationStepV1::SyncImmutablePrefix,
    C2InstallationStepV1::PersistPendingSqlProjection,
    C2InstallationStepV1::ReopenAndVerifyPreReceipt,
    C2InstallationStepV1::PersistCompletionReceipt,
    C2InstallationStepV1::ReopenAndVerifyCompletedGeneration,
    C2InstallationStepV1::ConstructClosedBackend,
];

#[cfg(test)]
fn verify_mode_prerequisites(
    prerequisites: &C2InstallationPrerequisitesV1,
) -> Result<(), InstallationRefusalV1> {
    if prerequisites.installation_cut == 0 {
        return Err(InstallationRefusalV1::Gen4NotEstablished);
    }
    match (&prerequisites.mode, &prerequisites.restore_predecessor) {
        (C2BootstrapModeV1::Fresh, None) => Ok(()),
        (C2BootstrapModeV1::RestoreSuccessor, Some(predecessor))
            if predecessor.predecessor_cut < prerequisites.installation_cut =>
        {
            Ok(())
        }
        (C2BootstrapModeV1::Fresh, Some(_)) => Err(InstallationRefusalV1::ModeMismatch),
        (C2BootstrapModeV1::RestoreSuccessor, None) => {
            Err(InstallationRefusalV1::RestorePredecessorMismatch)
        }
        _ => Err(InstallationRefusalV1::RestorePredecessorMismatch),
    }
}

/// N-51 records type-level mode disjointness.
#[cfg(test)]
pub(crate) fn construct_n_51_bootstrap_mode_disjointness() -> C2BootstrapModeDisjointnessV1 {
    C2BootstrapModeDisjointnessV1
}

#[cfg(test)]
pub fn verify_n_51_fresh_restore_bootstrap_disjointness(
    _: C2BootstrapModeDisjointnessV1,
) -> Result<(), InstallationRefusalV1> {
    Ok(())
}

/// P-01 constructs the fresh brand before any durable effect.
#[cfg(test)]
pub(crate) fn install_c2_fresh(
    prerequisites: C2InstallationPrerequisitesV1,
) -> Result<C2BootstrapSessionV1<FreshV1>, InstallationRefusalV1> {
    verify_mode_prerequisites(&prerequisites)?;
    if prerequisites.mode != C2BootstrapModeV1::Fresh {
        return Err(InstallationRefusalV1::ModeMismatch);
    }
    Ok(C2BootstrapSessionV1 {
        brand: C2BootstrapBrandV1 {
            prerequisites,
            _mode: PhantomData,
        },
    })
}

/// P-02 constructs the restore-successor brand before any durable effect.
#[cfg(test)]
pub(crate) fn install_c2_restore_successor(
    prerequisites: C2InstallationPrerequisitesV1,
) -> Result<C2BootstrapSessionV1<RestoreSuccessorV1>, InstallationRefusalV1> {
    verify_restore_successor_install_inputs(&prerequisites)?;
    Ok(C2BootstrapSessionV1 {
        brand: C2BootstrapBrandV1 {
            prerequisites,
            _mode: PhantomData,
        },
    })
}

/// P-01 verifier for the exact fresh prerequisite set.
#[cfg(test)]
pub(crate) fn verify_fresh_install_inputs(
    prerequisites: &C2InstallationPrerequisitesV1,
) -> Result<(), InstallationRefusalV1> {
    verify_mode_prerequisites(prerequisites)?;
    if prerequisites.mode == C2BootstrapModeV1::Fresh {
        Ok(())
    } else {
        Err(InstallationRefusalV1::ModeMismatch)
    }
}

/// P-02 verifier for the exact restore-successor prerequisite set.
#[cfg(test)]
pub(crate) fn verify_restore_successor_install_inputs(
    prerequisites: &C2InstallationPrerequisitesV1,
) -> Result<(), InstallationRefusalV1> {
    verify_mode_prerequisites(prerequisites)?;
    if prerequisites.mode == C2BootstrapModeV1::RestoreSuccessor {
        Ok(())
    } else {
        Err(InstallationRefusalV1::ModeMismatch)
    }
}

#[cfg(test)]
impl<Mode> C2BootstrapSessionV1<Mode> {
    /// Consume the special session into one closed durable result.
    pub(crate) fn run_installation(
        self,
        operation_identity: Sha256Digest,
        durable_result: C2DurableResultV1,
    ) -> Result<C2InstallationStateMachineV1, InstallationRefusalV1> {
        let mode = self.brand.prerequisites.mode;
        let state = C2InstallationStateMachineV1 {
            operation_identity,
            mode,
            steps: EXACT_INSTALLATION_SEQUENCE.to_vec(),
            durable_result,
        };
        verify_wu_07_immutable_wu_five_special_roots_s0_s5(&state)?;
        Ok(state)
    }
}

/// P-03/N-12 select exactly one signed admissible S2/S3 prefix.
#[cfg(test)]
pub(crate) fn construct_n_12_installation_continuation(
    expected_intent: &Sha256Digest,
    expected_prefix: &Sha256Digest,
    expected_profile: &Sha256Digest,
    prefixes: Vec<C2InstallationPrefixV1>,
) -> Result<C2InstallationContinuationBrandV1, InstallationRefusalV1> {
    if prefixes.len() != 1 {
        return Err(InstallationRefusalV1::PrefixCardinality);
    }
    let prefix = prefixes.into_iter().next().unwrap();
    if prefix.signed_intent_identity.as_ref() != Some(expected_intent)
        || &prefix.prefix_identity != expected_prefix
        || &prefix.profile_identity != expected_profile
    {
        return Err(InstallationRefusalV1::PrefixMismatch);
    }
    Ok(C2InstallationContinuationBrandV1 {
        signed_intent_identity: prefix.signed_intent_identity.unwrap(),
        prefix_identity: prefix.prefix_identity,
        stage: prefix.stage,
        profile_identity: prefix.profile_identity,
    })
}

#[cfg(test)]
pub(crate) fn continue_c2_installation(
    expected_intent: &Sha256Digest,
    expected_prefix: &Sha256Digest,
    expected_profile: &Sha256Digest,
    prefixes: Vec<C2InstallationPrefixV1>,
) -> Result<C2InstallationContinuationBrandV1, InstallationRefusalV1> {
    construct_n_12_installation_continuation(
        expected_intent,
        expected_prefix,
        expected_profile,
        prefixes,
    )
}

#[cfg(test)]
pub fn verify_n_12_exact_signed_prefix(
    brand: &C2InstallationContinuationBrandV1,
    expected_intent: &Sha256Digest,
    expected_prefix: &Sha256Digest,
) -> Result<(), InstallationRefusalV1> {
    if &brand.signed_intent_identity == expected_intent && &brand.prefix_identity == expected_prefix
    {
        Ok(())
    } else {
        Err(InstallationRefusalV1::PrefixMismatch)
    }
}

#[cfg(test)]
pub fn verify_installation_continuation_frontier(
    brand: &C2InstallationContinuationBrandV1,
    expected_stage: C2InstallationPrefixStageV1,
    expected_profile: &Sha256Digest,
) -> Result<(), InstallationRefusalV1> {
    if brand.stage == expected_stage && &brand.profile_identity == expected_profile {
        Ok(())
    } else {
        Err(InstallationRefusalV1::PrefixMismatch)
    }
}

/// WU-07 constructs a forward-only state from the exact sequence.
pub(crate) fn construct_wu_07_immutable_wu_five_special_roots_s0_s5(
    operation_identity: Sha256Digest,
    mode: C2BootstrapModeV1,
    durable_result: C2DurableResultV1,
) -> C2InstallationStateMachineV1 {
    C2InstallationStateMachineV1 {
        operation_identity,
        mode,
        steps: EXACT_INSTALLATION_SEQUENCE.to_vec(),
        durable_result,
    }
}

pub fn verify_wu_07_immutable_wu_five_special_roots_s0_s5(
    state: &C2InstallationStateMachineV1,
) -> Result<(), InstallationRefusalV1> {
    if state.steps.as_slice() != EXACT_INSTALLATION_SEQUENCE {
        return Err(InstallationRefusalV1::SequenceMismatch);
    }
    match &state.durable_result {
        C2DurableResultV1::ExactNoWrite { .. }
        | C2DurableResultV1::InstallationQuarantinedPrefixS1 { .. }
        | C2DurableResultV1::InstallationQuarantinedPrefixS2 { .. }
        | C2DurableResultV1::InstallationQuarantinedPrefixS3 { .. }
        | C2DurableResultV1::InstallationCompletedBackendUnclosedS4 { .. }
        | C2DurableResultV1::InstallationCompletedClosedS5 { .. }
        | C2DurableResultV1::TransitionQuarantinedIntentPrefix { .. }
        | C2DurableResultV1::TransitionCompleted { .. } => Ok(()),
    }
}

/// N-52's runtime verifier is intentionally observational; structural
/// non-convertibility is demonstrated by compile-fail evidence.
#[cfg(test)]
pub fn verify_n_52_bootstrap_session_surface<Mode>(
    session: &C2BootstrapSessionV1<Mode>,
) -> Result<(), InstallationRefusalV1> {
    verify_mode_prerequisites(&session.brand.prerequisites)
}

/// N-53 verifies that the continuation still names its exact intent/prefix.
#[cfg(test)]
pub fn verify_n_53_exact_intent_continuation_surface(
    brand: &C2InstallationContinuationBrandV1,
    intent: &Sha256Digest,
    prefix: &Sha256Digest,
) -> Result<(), InstallationRefusalV1> {
    verify_n_12_exact_signed_prefix(brand, intent, prefix)
}

/// N-68 verifies that installation is rooted in an established Gen4
/// resolution and does not substitute that evidence with C2 outputs.
#[cfg(test)]
pub(crate) fn construct_n_68_installation_applies_established_gen4_store_closed_fresh(
    prerequisites: C2InstallationPrerequisitesV1,
) -> Result<C2InstallationPrerequisitesV1, InstallationRefusalV1> {
    verify_mode_prerequisites(&prerequisites)?;
    Ok(prerequisites)
}

#[cfg(test)]
pub(crate) fn verify_n_68_installation_applies_established_gen4_store_closed_fresh(
    prerequisites: &C2InstallationPrerequisitesV1,
) -> Result<(), InstallationRefusalV1> {
    verify_mode_prerequisites(prerequisites)
}

/// N-69 constructs the exact step sequence; raw allocation steps carry no
/// capacity or session token in this representation.
pub(crate) fn construct_n_69_sequence_authenticate_lineage_mutex_preflight_brand_exclusive(
    operation_identity: Sha256Digest,
    mode: C2BootstrapModeV1,
    durable_result: C2DurableResultV1,
) -> C2InstallationStateMachineV1 {
    construct_wu_07_immutable_wu_five_special_roots_s0_s5(operation_identity, mode, durable_result)
}

pub fn verify_n_69_sequence_authenticate_lineage_mutex_preflight_brand_exclusive(
    state: &C2InstallationStateMachineV1,
) -> Result<(), InstallationRefusalV1> {
    verify_wu_07_immutable_wu_five_special_roots_s0_s5(state)
}

/// N-70 refuses treating any pre-S5 result as ordinary standing.
pub(crate) fn construct_n_70_no_general_session_capacity_launch_repair_during(
    state: C2InstallationStateMachineV1,
) -> Result<C2InstallationStateMachineV1, InstallationRefusalV1> {
    verify_n_70_no_general_session_capacity_launch_repair_during(&state)?;
    Ok(state)
}

pub fn verify_n_70_no_general_session_capacity_launch_repair_during(
    state: &C2InstallationStateMachineV1,
) -> Result<(), InstallationRefusalV1> {
    match state.durable_result {
        C2DurableResultV1::InstallationCompletedClosedS5 { .. } => Ok(()),
        _ => Err(InstallationRefusalV1::PrematureStanding),
    }
}

/// N-71 ordinary-open/recovery paths may observe but never complete a prefix.
pub fn verify_n_71_refusal(
    state: &C2InstallationStateMachineV1,
) -> Result<(), InstallationRefusalV1> {
    match state.durable_result {
        C2DurableResultV1::InstallationCompletedBackendUnclosedS4 { .. }
        | C2DurableResultV1::InstallationCompletedClosedS5 { .. } => Ok(()),
        _ => Err(InstallationRefusalV1::OrdinaryCompletionForbidden),
    }
}

impl C2DurableResultV1 {
    /// S0 exact no-write result.
    pub(crate) fn exact_no_write(snapshot_identity: Sha256Digest) -> Self {
        Self::ExactNoWrite { snapshot_identity }
    }

    /// S1 raw allocation prefix; it carries no authenticated standing.
    pub(crate) fn s1_quarantined_allocation(prefix_identity: Sha256Digest) -> Self {
        Self::InstallationQuarantinedPrefixS1 { prefix_identity }
    }

    /// S2 named pre-authentication prefix.
    pub(crate) fn s2_quarantined_authentication(
        prefix_identity: Sha256Digest,
        signed_intent_identity: Option<Sha256Digest>,
    ) -> Self {
        Self::InstallationQuarantinedPrefixS2 {
            prefix_identity,
            signed_intent_identity,
        }
    }

    /// S3 exact intent-bearing authenticated-header prefix, with no G record.
    pub(crate) fn s3_authenticated_incomplete(
        prefix_identity: Sha256Digest,
        signed_intent_identity: Sha256Digest,
        authenticated_g_header_identity: Sha256Digest,
    ) -> Self {
        Self::InstallationQuarantinedPrefixS3 {
            prefix_identity,
            signed_intent_identity,
            authenticated_g_header_identity,
        }
    }

    /// S4 completed durable generation without process-local closed standing.
    pub(crate) fn s4_completed_unclosed(
        physical_generation_identity: Sha256Digest,
        completion_receipt_identity: Sha256Digest,
        completed_snapshot_identity: Sha256Digest,
    ) -> Self {
        Self::InstallationCompletedBackendUnclosedS4 {
            physical_generation_identity,
            completion_receipt_identity,
            completed_snapshot_identity,
        }
    }

    /// S5 completed durable generation with exact held closed-backend evidence.
    pub(crate) fn s5_completed_closed(
        physical_generation_identity: Sha256Digest,
        completion_receipt_identity: Sha256Digest,
        closed_backend_identity: Sha256Digest,
        g_reservation_policy_identity: Sha256Digest,
    ) -> Self {
        Self::InstallationCompletedClosedS5 {
            physical_generation_identity,
            completion_receipt_identity,
            closed_backend_identity,
            g_reservation_policy_identity,
        }
    }
}

pub fn verify_exact_no_write(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    matches!(result, C2DurableResultV1::ExactNoWrite { .. })
        .then_some(())
        .ok_or(InstallationRefusalV1::QuarantinedPrefixMismatch)
}

pub fn verify_s1_quarantined_allocation(
    result: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    matches!(
        result,
        C2DurableResultV1::InstallationQuarantinedPrefixS1 { .. }
    )
    .then_some(())
    .ok_or(InstallationRefusalV1::QuarantinedPrefixMismatch)
}

pub fn verify_s2_quarantined_authentication(
    result: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    matches!(
        result,
        C2DurableResultV1::InstallationQuarantinedPrefixS2 { .. }
    )
    .then_some(())
    .ok_or(InstallationRefusalV1::QuarantinedPrefixMismatch)
}

pub fn verify_s3_authenticated_incomplete(
    result: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    matches!(
        result,
        C2DurableResultV1::InstallationQuarantinedPrefixS3 { .. }
    )
    .then_some(())
    .ok_or(InstallationRefusalV1::QuarantinedPrefixMismatch)
}

pub fn verify_s4_completed_unclosed(
    result: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    matches!(
        result,
        C2DurableResultV1::InstallationCompletedBackendUnclosedS4 { .. }
    )
    .then_some(())
    .ok_or(InstallationRefusalV1::CompletionMismatch)
}

pub fn verify_s5_completed_closed_completed_durable_state_ordinary_session_may_mutate(
    result: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    matches!(
        result,
        C2DurableResultV1::InstallationCompletedClosedS5 { .. }
    )
    .then_some(())
    .ok_or(InstallationRefusalV1::CompletionMismatch)
}

pub fn verify_n_72_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    verify_exact_no_write(result)
}

pub fn verify_n_73_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    verify_s1_quarantined_allocation(result)
}

pub fn verify_n_74_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    match result {
        C2DurableResultV1::InstallationQuarantinedPrefixS2 { .. } => Ok(()),
        _ => Err(InstallationRefusalV1::QuarantinedPrefixMismatch),
    }
}

pub fn verify_n_75_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    verify_s3_authenticated_incomplete(result)
}

pub fn verify_n_76_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    verify_s4_completed_unclosed(result)
}

pub fn verify_n_77_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    verify_s5_completed_closed_completed_durable_state_ordinary_session_may_mutate(result)
}

/// N-77 constructor retains only the exact S5 completed/closed result.
pub(crate) fn construct_n_77_s5_completed_closed_held_lifetime_reaches_ordinary(
    result: C2DurableResultV1,
) -> Result<C2DurableResultV1, InstallationRefusalV1> {
    verify_s5_completed_closed_completed_durable_state_ordinary_session_may_mutate(&result)?;
    Ok(result)
}

/// N-77 exact matrix verifier alias.
pub fn verify_n_77_s5_completed_closed_held_lifetime_reaches_ordinary(
    result: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    verify_s5_completed_closed_completed_durable_state_ordinary_session_may_mutate(result)
}

pub fn verify_n_78_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    match result {
        C2DurableResultV1::InstallationQuarantinedPrefixS1 { .. }
        | C2DurableResultV1::InstallationQuarantinedPrefixS2 { .. }
        | C2DurableResultV1::InstallationQuarantinedPrefixS3 { .. } => {
            Err(InstallationRefusalV1::OrdinaryCompletionForbidden)
        }
        _ => Ok(()),
    }
}

pub fn verify_n_79_refusal(result: &C2DurableResultV1) -> Result<(), InstallationRefusalV1> {
    verify_n_78_refusal(result)
}

pub fn verify_n_80_refusal(
    current: &C2DurableResultV1,
    proposed: &C2DurableResultV1,
) -> Result<(), InstallationRefusalV1> {
    if matches!(
        current,
        C2DurableResultV1::InstallationCompletedClosedS5 { .. }
    ) && matches!(
        proposed,
        C2DurableResultV1::ExactNoWrite { .. }
            | C2DurableResultV1::InstallationQuarantinedPrefixS1 { .. }
            | C2DurableResultV1::InstallationQuarantinedPrefixS2 { .. }
    ) {
        Err(InstallationRefusalV1::PhaseDowngrade)
    } else {
        Ok(())
    }
}

/// AM-04 binds the same closed S0--S5 verifier.
pub(crate) fn construct_am_04_crosswalk_am_charter_close_pre_g_failure(
    operation_identity: Sha256Digest,
    mode: C2BootstrapModeV1,
    result: C2DurableResultV1,
) -> C2InstallationStateMachineV1 {
    construct_wu_07_immutable_wu_five_special_roots_s0_s5(operation_identity, mode, result)
}

pub fn verify_am_04_crosswalk_am_charter_close_pre_g_failure(
    state: &C2InstallationStateMachineV1,
) -> Result<(), InstallationRefusalV1> {
    verify_wu_07_immutable_wu_five_special_roots_s0_s5(state)
}

/// SEAM-13 constructs one exact closed cut classifier.
pub(crate) fn construct_seam_13_immutable_seam_finite_i_o_finite_crash(
    cut: C2IoCutV1,
) -> C2IoCutV1 {
    cut
}

pub fn verify_seam_13_immutable_seam_finite_i_o_finite_crash(
    cut: C2IoCutV1,
    manifest: &std::collections::BTreeSet<C2IoCutV1>,
) -> Result<(), InstallationRefusalV1> {
    if manifest.contains(&cut) {
        Ok(())
    } else {
        Err(InstallationRefusalV1::UnclassifiedIoCut)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use nix::fcntl::{Flock, FlockArg};
    use tempfile::tempdir;

    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn fresh_prerequisites() -> C2InstallationPrerequisitesV1 {
        C2InstallationPrerequisitesV1 {
            mode: C2BootstrapModeV1::Fresh,
            gen4_resolution_identity: digest('a'),
            controlling_activation_identity: digest('b'),
            install_policy_identity: digest('c'),
            enrollment_identity: digest('d'),
            physical_lineage_identity: digest('e'),
            root_descriptor_identity: digest('f'),
            creation_mutex_identity: digest('0'),
            root_shape_identity: digest('1'),
            backend_preflight_identity: digest('2'),
            qualified_profile_identity: digest('3'),
            installation_cut: 7,
            restore_predecessor: None,
        }
    }

    #[test]
    fn fresh_brand_is_constructed_before_a_closed_result() {
        let session = install_c2_fresh(fresh_prerequisites()).unwrap();
        let state = session
            .run_installation(digest('4'), C2DurableResultV1::exact_no_write(digest('5')))
            .unwrap();
        assert!(
            verify_n_69_sequence_authenticate_lineage_mutex_preflight_brand_exclusive(&state)
                .is_ok()
        );
    }

    #[test]
    fn fresh_mode_rejects_restore_predecessor() {
        let mut prerequisites = fresh_prerequisites();
        prerequisites.restore_predecessor = Some(C2RestoreInstallationPredecessorV1 {
            physical_generation_identity: digest('6'),
            bootstrap_identity: digest('7'),
            completion_receipt_identity: digest('8'),
            restore_disposition_identity: digest('9'),
            restore_proof_identity: digest('a'),
            predecessor_cut: 3,
        });
        assert_eq!(
            install_c2_fresh(prerequisites).unwrap_err(),
            InstallationRefusalV1::ModeMismatch
        );
    }

    #[test]
    fn continuation_refuses_competing_prefixes() {
        let prefix = C2InstallationPrefixV1 {
            signed_intent_identity: Some(digest('a')),
            prefix_identity: digest('b'),
            stage: C2InstallationPrefixStageV1::S2PreGAuthentication,
            profile_identity: digest('c'),
        };
        assert_eq!(
            continue_c2_installation(
                &digest('a'),
                &digest('b'),
                &digest('c'),
                vec![prefix.clone(), prefix],
            )
            .unwrap_err(),
            InstallationRefusalV1::PrefixCardinality
        );
    }

    #[test]
    fn s5_cannot_downgrade_to_a_quarantined_prefix() {
        let s5 = C2DurableResultV1::s5_completed_closed(
            digest('a'),
            digest('b'),
            digest('c'),
            digest('d'),
        );
        let s1 = C2DurableResultV1::s1_quarantined_allocation(digest('e'));
        assert_eq!(
            verify_n_80_refusal(&s5, &s1).unwrap_err(),
            InstallationRefusalV1::PhaseDowngrade
        );
    }

    struct StopAfterCut(C2IoCutV1);

    impl C2InstallationCrashObserverV1 for StopAfterCut {
        fn after_cut(&mut self, cut: C2IoCutV1) -> Result<(), C2LiveInstallationRefusalV1> {
            if cut == self.0 {
                Err(C2LiveInstallationRefusalV1::InjectedCrash(cut))
            } else {
                Ok(())
            }
        }
    }

    fn retained_root(path: &Path) -> File {
        File::open(path).unwrap()
    }

    #[test]
    fn production_prefix_acquires_flock_and_allocates_exact_files() {
        let directory = tempdir().unwrap();
        let root = retained_root(directory.path());
        let allocated = allocate_live_c2_fixed_files_v1(
            &root,
            4096,
            8192,
            12_288,
            &mut NoC2InstallationCrashV1,
        )
        .unwrap();
        assert_eq!(allocated.lock().metadata().unwrap().len(), 4096);
        assert_eq!(allocated.b().metadata().unwrap().len(), 8192);
        assert_eq!(allocated.g().metadata().unwrap().len(), 12_288);

        // The retained Flock is real: a second descriptor cannot acquire the
        // exclusive generation lock while this allocation prefix is live.
        let competing = File::open(directory.path().join(super::super::C2_LOCK_FILE_V1)).unwrap();
        assert!(Flock::lock(competing, FlockArg::LockExclusiveNonblock).is_err());

        assert!(matches!(
            allocate_live_c2_fixed_files_v1(
                &root,
                4096,
                8192,
                12_288,
                &mut NoC2InstallationCrashV1,
            ),
            Err(C2LiveInstallationRefusalV1::ExistingC2Footprint)
        ));
    }

    #[test]
    fn every_reachable_allocation_cut_leaves_an_observable_prefix() {
        let cuts = [
            C2IoCutV1::RootShapeObservation,
            C2IoCutV1::PermanentLockCreate,
            C2IoCutV1::PermanentLockFstat,
            C2IoCutV1::LockMutexTransfer,
            C2IoCutV1::PermanentFlockAcquisition,
            C2IoCutV1::BCarrierCreate,
            C2IoCutV1::BCarrierAllocation,
            C2IoCutV1::GCarrierCreate,
            C2IoCutV1::GCarrierAllocation,
            C2IoCutV1::DirectorySync,
        ];
        for cut in cuts {
            let directory = tempdir().unwrap();
            let root = retained_root(directory.path());
            let error = match allocate_live_c2_fixed_files_v1(
                &root,
                4096,
                8192,
                12_288,
                &mut StopAfterCut(cut),
            ) {
                Err(error) => error,
                Ok(_) => panic!("the selected crash cut must stop allocation"),
            };
            assert!(matches!(
                error,
                C2LiveInstallationRefusalV1::InjectedCrash(observed) if observed == cut
            ));
            let lock_exists = directory
                .path()
                .join(super::super::C2_LOCK_FILE_V1)
                .exists();
            let b_exists = directory
                .path()
                .join(super::super::C2_BOOTSTRAP_EXTENT_V1)
                .exists();
            let g_exists = directory
                .path()
                .join(super::super::C2_GLOBAL_REFUSAL_EXTENT_V1)
                .exists();
            match cut {
                C2IoCutV1::RootShapeObservation => {
                    assert!(!lock_exists && !b_exists && !g_exists)
                }
                C2IoCutV1::PermanentLockCreate
                | C2IoCutV1::PermanentLockFstat
                | C2IoCutV1::LockMutexTransfer
                | C2IoCutV1::PermanentFlockAcquisition => {
                    assert!(lock_exists && !b_exists && !g_exists)
                }
                C2IoCutV1::BCarrierCreate | C2IoCutV1::BCarrierAllocation => {
                    assert!(lock_exists && b_exists && !g_exists)
                }
                C2IoCutV1::GCarrierCreate
                | C2IoCutV1::GCarrierAllocation
                | C2IoCutV1::DirectorySync => assert!(lock_exists && b_exists && g_exists),
                _ => unreachable!("only allocation-prefix cuts are enumerated"),
            }
        }
    }
}
