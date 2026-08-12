//! Crash/restart specimens for production live-C2 bootstrap and transitions.
//!
//! Bootstrap uses the dedicated source observer. Transition specimens use
//! closed temporary SQLite triggers at exact production projection writes;
//! these triggers exercise the real carrier-first path without adding a
//! caller-selectable production fault surface.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::SigningKey;
use nq_protocol::{Sha256Digest, sha256_bytes};
use nq_runtime_dependency_authority::test_support::RawAuthorityFixture;
use nq_runtime_dependency_authority::{
    ControllingActivationSnapshot, resolve_for_restart, verify_for_establishment,
};
use tempfile::{TempDir, tempdir};

use super::install::{
    C2IoCutV1, C2LiveInstallationRefusalV1, with_test_bootstrap_installation_observer_v1,
};
use super::live_c2::tests::{
    apply_exact_quarantine_for_test, apply_exact_revocation_for_test,
    exact_recovery_pair_for_test, exact_restore_pair_for_test,
};
use super::live_c2::{
    C2BootstrapOperatorInstallSelectionV1, C2BootstrapPreparationIntentV1,
    C2CustodyPreparationRefusalV1, C2EnrollmentBridgeRefusalV1, C2GovernedCarrierIngressRefusalV1,
    C2HealthySuccessorIntentV1, C2LiveBootstrapDriverRefusalV1, C2LiveInstallationDriverRefusalV1,
    C2LiveReopenRefusalV1, C2LiveSignerRefusalV1, C2LiveTransitionDriverRefusalV1,
    C2RecoveryPredecessorStatusV1, C2RecoveryPreparationIntentV1, C2SignerAppendRefusalV1,
    StoreC2QualifiedRuntimeEvidenceV1,
};
use super::records::{
    APPEND_EXTENT_LAYOUT_V1, C2InstallationModeV1, C2InstalledCarrierGeometryV1, C2StructuralCutV1,
    QualifiedBackendProfileIdentityV1,
};
use super::signer::custody::with_test_production_custody_root_v1;
use super::signer::external_governance::C2ExternalIngressRefusalV1;
use super::signer::external_governance::StoreIntegrityBootstrapGrantV1;
use super::signer::external_governance::tests::{
    sign_exact_bootstrap_grant_for_test, sign_exact_recovery_grant_for_test,
};
use super::signer::manifest::{
    SignerImplementationManifestDerivationInputV1, StoreIntegritySignerImplementationManifestV1,
    derive_signer_implementation_manifest_v1,
};
use super::signer::result::SignerRefusalV2;
use super::signer::terminal::DurableTerminalAppendRefusalV1;
use super::{
    C2_BOOTSTRAP_EXTENT_V1, C2_GLOBAL_REFUSAL_EXTENT_V1, C2_LOCK_FILE_V1, C2_SQLITE_FILE_V1,
};
use crate::{RuntimeAuthorityRestartSnapshot, Store, StoreError};
use super::source_io_crash_test_support::with_source_io_observer_v1;

/// Exact observer sequence reached by one successful production bootstrap.
/// The ten other enum members are transition/model cuts not currently
/// observed by this production path and are intentionally not claimed here.
const REACHABLE_BOOTSTRAP_INSTALLATION_CUTS_V1: &[C2IoCutV1] = &[
    C2IoCutV1::BackendProfilePreflight,
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
    C2IoCutV1::BHeaderWrite,
    C2IoCutV1::GHeaderWrite,
    C2IoCutV1::BootstrapIntentAppend,
    C2IoCutV1::ImmutablePrefixSync,
    C2IoCutV1::PendingSqlProjectionInsert,
    C2IoCutV1::PreReceiptDescriptorReopen,
    C2IoCutV1::CompletionReceiptAppend,
    C2IoCutV1::CompletionReceiptSync,
    C2IoCutV1::CompletedDescriptorReopen,
];

/// Durable healthy-successor cuts reachable through the current production
/// A-to-B path. Each entry names an exact source table/route insertion; this
/// is deliberately not a claim about CPU-only live-brand refinement points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HealthySuccessorProjectionCutV1 {
    CustodyPreparation,
    Msg07SuccessorPop,
    Msg06PredecessorContinuity,
    Msg11TransitionIntent,
    FoundationAdoption,
    SignerAcceptance,
    Msg12PendingReceipt,
    TerminalCurrentness,
}

const HEALTHY_SUCCESSOR_PROJECTION_CUTS_V1: &[HealthySuccessorProjectionCutV1] = &[
    HealthySuccessorProjectionCutV1::CustodyPreparation,
    HealthySuccessorProjectionCutV1::Msg07SuccessorPop,
    HealthySuccessorProjectionCutV1::Msg06PredecessorContinuity,
    HealthySuccessorProjectionCutV1::Msg11TransitionIntent,
    HealthySuccessorProjectionCutV1::FoundationAdoption,
    HealthySuccessorProjectionCutV1::SignerAcceptance,
    HealthySuccessorProjectionCutV1::Msg12PendingReceipt,
    HealthySuccessorProjectionCutV1::TerminalCurrentness,
];

impl HealthySuccessorProjectionCutV1 {
    const fn trigger_sql(self) -> &'static str {
        match self {
            Self::CustodyPreparation => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_custody_proposal_preparations
                 BEGIN SELECT RAISE(ABORT, 'injected healthy custody preparation cut'); END;"
            }
            Self::Msg07SuccessorPop => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_signer_message_appends
                 WHEN NEW.route = 'msg07_successor_pop'
                 BEGIN SELECT RAISE(ABORT, 'injected healthy MSG-07 cut'); END;"
            }
            Self::Msg06PredecessorContinuity => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_signer_message_appends
                 WHEN NEW.route = 'msg06_normal_rotation_continuity'
                 BEGIN SELECT RAISE(ABORT, 'injected healthy MSG-06 cut'); END;"
            }
            Self::Msg11TransitionIntent => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_signer_message_appends
                 WHEN NEW.route = 'msg11_policy_transition_intent'
                 BEGIN SELECT RAISE(ABORT, 'injected healthy MSG-11 cut'); END;"
            }
            Self::FoundationAdoption => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_foundational_enrollment_adoptions
                 BEGIN SELECT RAISE(ABORT, 'injected healthy foundation adoption cut'); END;"
            }
            Self::SignerAcceptance => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_signer_enrollment_acceptances
                 BEGIN SELECT RAISE(ABORT, 'injected healthy signer acceptance cut'); END;"
            }
            Self::Msg12PendingReceipt => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_signer_message_appends
                 WHEN NEW.route = 'msg12_receipt_pending'
                 BEGIN SELECT RAISE(ABORT, 'injected healthy MSG-12 cut'); END;"
            }
            Self::TerminalCurrentness => {
                "CREATE TEMP TRIGGER c2_test_healthy_projection_cut
                 BEFORE INSERT ON c2_signer_current_binding_projection
                 BEGIN SELECT RAISE(ABORT, 'injected healthy terminal currentness cut'); END;"
            }
        }
    }

    const fn has_carrier_first_suffix(self) -> bool {
        !matches!(self, Self::CustodyPreparation)
    }
}

fn assert_healthy_projection_refusal(
    cut: HealthySuccessorProjectionCutV1,
    refusal: C2LiveTransitionDriverRefusalV1,
) {
    let exact = match cut {
        HealthySuccessorProjectionCutV1::CustodyPreparation => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Custody(C2CustodyPreparationRefusalV1::Store(_))
        ),
        HealthySuccessorProjectionCutV1::Msg07SuccessorPop => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::SuccessorPossession(C2SignerAppendRefusalV1::Signer(
                SignerRefusalV2::CustodyIo
            ),)
        ),
        HealthySuccessorProjectionCutV1::Msg06PredecessorContinuity
        | HealthySuccessorProjectionCutV1::Msg11TransitionIntent => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::HealthyContinuity(C2SignerAppendRefusalV1::Signer(
                SignerRefusalV2::CustodyIo
            ),)
        ),
        HealthySuccessorProjectionCutV1::FoundationAdoption
        | HealthySuccessorProjectionCutV1::SignerAcceptance => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Enrollment(C2EnrollmentBridgeRefusalV1::Signer(
                SignerRefusalV2::SignerStateIo,
            ))
        ),
        HealthySuccessorProjectionCutV1::Msg12PendingReceipt => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::PendingReceipt(C2SignerAppendRefusalV1::Signer(
                SignerRefusalV2::CustodyIo
            ),)
        ),
        HealthySuccessorProjectionCutV1::TerminalCurrentness => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Terminal(DurableTerminalAppendRefusalV1::Sql(_))
        ),
    };
    assert!(exact, "unexpected refusal at {cut:?}: {refusal:?}");
}

/// Closed consequence-bearing paths whose entry authority is external but
/// whose pending signer effects remain Store-owned and route-specific.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscontinuityPathV1 {
    Restore,
    Recovery,
}

impl DiscontinuityPathV1 {
    const fn external_route(self) -> &'static str {
        match self {
            Self::Restore => "msg13_restore_authorization",
            Self::Recovery => "msg15_recovery_grant",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::Recovery => "recovery",
        }
    }
}

/// Exact durable projections shared by the two production discontinuity
/// continuations. Historical resolution, live entry-brand minting, and phase
/// refinement are deliberately absent: they have no durable I/O boundary and
/// cannot be represented honestly by a SQLite projection fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscontinuityProjectionCutV1 {
    ExternalIngress,
    Msg07SuccessorPop,
    FoundationAdoption,
    SignerAcceptance,
    Msg12PendingReceipt,
    TerminalCurrentness,
}

const DISCONTINUITY_PROJECTION_CUTS_V1: &[DiscontinuityProjectionCutV1] = &[
    DiscontinuityProjectionCutV1::ExternalIngress,
    DiscontinuityProjectionCutV1::Msg07SuccessorPop,
    DiscontinuityProjectionCutV1::FoundationAdoption,
    DiscontinuityProjectionCutV1::SignerAcceptance,
    DiscontinuityProjectionCutV1::Msg12PendingReceipt,
    DiscontinuityProjectionCutV1::TerminalCurrentness,
];

impl DiscontinuityProjectionCutV1 {
    fn marker(self, path: DiscontinuityPathV1) -> String {
        format!("injected {} {:?} cut", path.label(), self)
    }

    fn trigger_sql(self, path: DiscontinuityPathV1) -> String {
        let marker = self.marker(path);
        match self {
            Self::ExternalIngress => format!(
                "CREATE TEMP TRIGGER c2_test_discontinuity_projection_cut
                 BEFORE INSERT ON c2_external_carrier_ingress
                 WHEN NEW.route = '{}'
                 BEGIN SELECT RAISE(ABORT, '{}'); END;",
                path.external_route(),
                marker
            ),
            Self::Msg07SuccessorPop => format!(
                "CREATE TEMP TRIGGER c2_test_discontinuity_projection_cut
                 BEFORE INSERT ON c2_signer_message_appends
                 WHEN NEW.route = 'msg07_successor_pop'
                 BEGIN SELECT RAISE(ABORT, '{}'); END;",
                marker
            ),
            Self::FoundationAdoption => format!(
                "CREATE TEMP TRIGGER c2_test_discontinuity_projection_cut
                 BEFORE INSERT ON c2_foundational_enrollment_adoptions
                 BEGIN SELECT RAISE(ABORT, '{}'); END;",
                marker
            ),
            Self::SignerAcceptance => format!(
                "CREATE TEMP TRIGGER c2_test_discontinuity_projection_cut
                 BEFORE INSERT ON c2_signer_enrollment_acceptances
                 BEGIN SELECT RAISE(ABORT, '{}'); END;",
                marker
            ),
            Self::Msg12PendingReceipt => format!(
                "CREATE TEMP TRIGGER c2_test_discontinuity_projection_cut
                 BEFORE INSERT ON c2_signer_message_appends
                 WHEN NEW.route = 'msg12_receipt_pending'
                 BEGIN SELECT RAISE(ABORT, '{}'); END;",
                marker
            ),
            Self::TerminalCurrentness => format!(
                "CREATE TEMP TRIGGER c2_test_discontinuity_projection_cut
                 BEFORE INSERT ON c2_signer_current_binding_projection
                 BEGIN SELECT RAISE(ABORT, '{}'); END;",
                marker
            ),
        }
    }

    const fn has_carrier_first_suffix(self) -> bool {
        !matches!(self, Self::ExternalIngress)
    }
}

fn assert_discontinuity_projection_refusal(
    path: DiscontinuityPathV1,
    cut: DiscontinuityProjectionCutV1,
    refusal: C2LiveTransitionDriverRefusalV1,
) {
    let exact = match cut {
        DiscontinuityProjectionCutV1::ExternalIngress => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Governance(
                C2GovernedCarrierIngressRefusalV1::Durable(
                    C2ExternalIngressRefusalV1::DurableStore(_),
                ),
            )
        ),
        DiscontinuityProjectionCutV1::Msg07SuccessorPop => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Signer(C2SignerAppendRefusalV1::Signer(
                SignerRefusalV2::CustodyIo
            ),)
        ),
        DiscontinuityProjectionCutV1::FoundationAdoption
        | DiscontinuityProjectionCutV1::SignerAcceptance => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Enrollment(C2EnrollmentBridgeRefusalV1::Signer(
                SignerRefusalV2::SignerStateIo,
            ))
        ),
        DiscontinuityProjectionCutV1::Msg12PendingReceipt => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Signer(C2SignerAppendRefusalV1::Signer(
                SignerRefusalV2::CustodyIo
            ),)
        ),
        DiscontinuityProjectionCutV1::TerminalCurrentness => matches!(
            refusal,
            C2LiveTransitionDriverRefusalV1::Terminal(DurableTerminalAppendRefusalV1::Sql(_))
        ),
    };
    assert!(exact, "unexpected {path:?} refusal at {cut:?}: {refusal:?}");
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::store_generation) struct ExactFileSnapshotV1 {
    pub(in crate::store_generation) length: u64,
    pub(in crate::store_generation) content_identity: Sha256Digest,
}

pub(in crate::store_generation) struct PreparedBootstrapHarnessV1 {
    pub(in crate::store_generation) _store_directory: TempDir,
    pub(in crate::store_generation) database: PathBuf,
    pub(in crate::store_generation) store: Store,
    pub(in crate::store_generation) authority_fixture: RawAuthorityFixture,
    pub(in crate::store_generation) qualified: StoreC2QualifiedRuntimeEvidenceV1,
    pub(in crate::store_generation) manifest: StoreIntegritySignerImplementationManifestV1,
    pub(in crate::store_generation) grant: StoreIntegrityBootstrapGrantV1,
}

struct PersistentBootstrapHarnessV1 {
    database: PathBuf,
    store: Store,
    authority_fixture: RawAuthorityFixture,
    qualified: StoreC2QualifiedRuntimeEvidenceV1,
    manifest: StoreIntegritySignerImplementationManifestV1,
}

fn establish_runtime_authority_fixture(
    store: &mut Store,
    fixture: &RawAuthorityFixture,
) -> Result<(), StoreError> {
    let custody = fixture.custody();
    let presented = fixture.presented_set();
    let expectations = fixture.activation_expectations();
    store.with_runtime_authority_writer_session(|brand, session| {
        let resolved = verify_for_establishment(brand, &custody, &presented, None, &expectations)?;
        session.establish_runtime_dependency_trust_root(&resolved)?;
        Ok(())
    })
}

fn resolve_runtime_authority_fixture(
    fixture: &RawAuthorityFixture,
    snapshot: &RuntimeAuthorityRestartSnapshot,
) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1> {
    resolve_for_restart(
        &fixture.custody(),
        &snapshot.presented,
        snapshot.migration_receipt.as_ref(),
        &fixture.restart_expectations(),
    )
    .map_err(StoreError::from)
    .map_err(C2LiveSignerRefusalV1::from)
}

fn initialize_persistent_bootstrap_harness(
    store_root: &Path,
) -> PersistentBootstrapHarnessV1 {
    fs::create_dir_all(store_root).expect("create persistent source-I/O Store root");
    let database = store_root.join(C2_SQLITE_FILE_V1);
    let mut store = Store::initialize_runtime_authority_candidate(&database)
        .expect("initialize persistent runtime-authority Store candidate");
    let authority_fixture = RawAuthorityFixture::fresh_genesis();
    establish_runtime_authority_fixture(&mut store, &authority_fixture)
        .expect("establish persistent exact runtime authority fixture");
    let manifest = executable_manifest();
    let qualified = StoreC2QualifiedRuntimeEvidenceV1::for_test(
        sha256_bytes(b"bootstrap-crash/candidate"),
        sha256_bytes(b"bootstrap-crash/source-tree"),
        sha256_bytes(&fs::read("/proc/self/exe").expect("read running Linux test image")),
        manifest.manifest_identity().clone(),
    );
    PersistentBootstrapHarnessV1 {
        database,
        store,
        authority_fixture,
        qualified,
        manifest,
    }
}

fn prepare_persistent_bootstrap_grant(
    harness: &mut PersistentBootstrapHarnessV1,
) -> StoreIntegrityBootstrapGrantV1 {
    let current = resolve_for_restart(
        &harness.authority_fixture.custody(),
        &harness.authority_fixture.presented_set(),
        None,
        &harness.authority_fixture.restart_expectations(),
    )
    .expect("resolve persistent exact current activation");
    let intent = bootstrap_intent(&current);
    let prepared = harness
        .store
        .prepare_c2_live_bootstrap_v1(
            &harness.qualified,
            &harness.manifest,
            &intent,
            |snapshot| {
                resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
            },
        )
        .expect("prepare persistent exact bootstrap request");
    sign_exact_bootstrap_grant_for_test(
        prepared.request(),
        &SigningKey::from_bytes(&[1_u8; 32]),
    )
}

fn complete_persistent_bootstrap(harness: &mut PersistentBootstrapHarnessV1) {
    let grant = prepare_persistent_bootstrap_grant(harness);
    harness
        .store
        .install_c2_live_from_bootstrap_grant_v1(
            &harness.qualified,
            &harness.manifest,
            &grant,
            |snapshot| {
                resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
            },
        )
        .expect("complete persistent exact bootstrap");
}

fn executable_manifest() -> StoreIntegritySignerImplementationManifestV1 {
    derive_signer_implementation_manifest_v1(SignerImplementationManifestDerivationInputV1 {
        custody_format_identity: sha256_bytes(b"bootstrap-crash/custody-format"),
        signer_message_contract_identity: sha256_bytes(b"bootstrap-crash/msg-01-through-msg-16"),
        source_file_bytes: BTreeMap::from([
            (
                "crates/nq-store/src/store_generation/live_c2.rs".to_owned(),
                b"bootstrap-crash/live-c2-basis".to_vec(),
            ),
            (
                "crates/nq-store/src/store_generation/install.rs".to_owned(),
                b"bootstrap-crash/install-basis".to_vec(),
            ),
        ]),
        cryptographic_backend_identity: sha256_bytes(b"bootstrap-crash/ed25519-dalek-v2-strict"),
        toolchain_identity: sha256_bytes(b"bootstrap-crash/rust-toolchain"),
        target_profile_identity: sha256_bytes(b"bootstrap-crash/linux-target"),
        qualification_assumption_identities: BTreeSet::from([
            sha256_bytes(b"bootstrap-crash/os-process-freshness"),
            sha256_bytes(b"bootstrap-crash/sha256-collision-resistance"),
        ]),
    })
    .expect("derive exact bootstrap-crash implementation manifest")
}

fn bootstrap_intent(current: &ControllingActivationSnapshot) -> C2BootstrapPreparationIntentV1 {
    let authority_cut = current.verification_cut().sequence();
    C2BootstrapPreparationIntentV1::from_operator_install_selection(
        sha256_bytes(b"bootstrap-crash/role-manifest"),
        sha256_bytes(b"bootstrap-crash/signer-scope-policy"),
        C2BootstrapOperatorInstallSelectionV1 {
            operator_installation_nonce: "01".repeat(32),
            installation_cut: C2StructuralCutV1 {
                ledger_position: authority_cut + 1,
                effect_position: 0,
            },
            mode: C2InstallationModeV1::Fresh,
            restore_predecessor: None,
            geometry: C2InstalledCarrierGeometryV1 {
                store_root_layout_version: "nq.c2.store_root_layout.v1".to_owned(),
                lock_format_identity: "nq.c2.lock_format.v1".to_owned(),
                append_extent_layout: APPEND_EXTENT_LAYOUT_V1.to_owned(),
                b_role_identity: "nq.c2.bootstrap_extent.v1".to_owned(),
                b_payload_bound: 1 << 20,
                g_role_identity: "nq.c2.global_refusal_extent.v1".to_owned(),
                g_payload_bound: 1 << 20,
                global_refusal_max_entries: 64,
                global_refusal_entry_max_bytes: 4096,
            },
            qualified_backend_profile: QualifiedBackendProfileIdentityV1::new(sha256_bytes(
                b"bootstrap-crash/qualified-backend-profile",
            )),
            maximum_policy_generations: 16,
            maximum_key_generations: 16,
            predecessor_install_policy: None,
        },
    )
    .expect("construct exact bootstrap-crash preparation intent")
}

pub(in crate::store_generation) fn prepare_bootstrap_harness() -> PreparedBootstrapHarnessV1 {
    let store_directory = tempdir().expect("create Store root");
    let database = store_directory.path().join(C2_SQLITE_FILE_V1);
    let mut store = Store::initialize_runtime_authority_candidate(&database)
        .expect("initialize runtime-authority Store candidate");
    let authority_fixture = RawAuthorityFixture::fresh_genesis();
    establish_runtime_authority_fixture(&mut store, &authority_fixture)
        .expect("establish exact runtime authority fixture");
    let current = resolve_for_restart(
        &authority_fixture.custody(),
        &authority_fixture.presented_set(),
        None,
        &authority_fixture.restart_expectations(),
    )
    .expect("resolve exact current activation");
    let manifest = executable_manifest();
    let qualified = StoreC2QualifiedRuntimeEvidenceV1::for_test(
        sha256_bytes(b"bootstrap-crash/candidate"),
        sha256_bytes(b"bootstrap-crash/source-tree"),
        sha256_bytes(&fs::read("/proc/self/exe").expect("read running Linux test image")),
        manifest.manifest_identity().clone(),
    );
    let intent = bootstrap_intent(&current);
    let prepared = store
        .prepare_c2_live_bootstrap_v1(&qualified, &manifest, &intent, |snapshot| {
            resolve_runtime_authority_fixture(&authority_fixture, snapshot)
        })
        .expect("prepare exact bootstrap request");
    let grant = sign_exact_bootstrap_grant_for_test(
        prepared.request(),
        &SigningKey::from_bytes(&[1_u8; 32]),
    );
    PreparedBootstrapHarnessV1 {
        _store_directory: store_directory,
        database,
        store,
        authority_fixture,
        qualified,
        manifest,
        grant,
    }
}

pub(in crate::store_generation) fn complete_bootstrap_installation(
    harness: &mut PreparedBootstrapHarnessV1,
) {
    harness
        .store
        .install_c2_live_from_bootstrap_grant_v1(
            &harness.qualified,
            &harness.manifest,
            &harness.grant,
            |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
        )
        .expect("complete exact bootstrap basis for transition crash specimen");
}

fn complete_bootstrap_and_revoke(harness: &mut PreparedBootstrapHarnessV1) {
    complete_bootstrap_installation(harness);
    apply_exact_revocation_for_test(
        &mut harness.store,
        &harness.qualified,
        &harness.manifest,
        &harness.authority_fixture,
    );
}

pub(in crate::store_generation) fn fixed_footprint_snapshot(
    root: &Path,
) -> BTreeMap<&'static str, Option<ExactFileSnapshotV1>> {
    [
        C2_LOCK_FILE_V1,
        C2_BOOTSTRAP_EXTENT_V1,
        C2_GLOBAL_REFUSAL_EXTENT_V1,
    ]
    .into_iter()
    .map(|name| {
        let path = root.join(name);
        let snapshot = match fs::read(&path) {
            Ok(bytes) => Some(ExactFileSnapshotV1 {
                length: u64::try_from(bytes.len()).expect("file length fits u64"),
                content_identity: sha256_bytes(&bytes),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("snapshot fixed C2 file {path:?}: {error}"),
        };
        (name, snapshot)
    })
    .collect()
}

pub(in crate::store_generation) fn directory_file_snapshot(
    root: &Path,
) -> BTreeMap<PathBuf, ExactFileSnapshotV1> {
    fn visit(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, ExactFileSnapshotV1>) {
        for entry in fs::read_dir(current).expect("enumerate exact snapshot directory") {
            let entry = entry.expect("enumerate exact snapshot entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("inspect exact snapshot entry");
            if file_type.is_dir() {
                visit(root, &path, output);
            } else if file_type.is_file() {
                let bytes = fs::read(&path).expect("read exact snapshot file");
                output.insert(
                    path.strip_prefix(root)
                        .expect("snapshot path remains below root")
                        .to_path_buf(),
                    ExactFileSnapshotV1 {
                        length: u64::try_from(bytes.len()).expect("file length fits u64"),
                        content_identity: sha256_bytes(&bytes),
                    },
                );
            } else {
                panic!("unexpected non-file custody entry {path:?}");
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

pub(in crate::store_generation) fn logical_store_snapshot(store: &Store) -> String {
    crate::logical_state_digest(
        &store.connection,
        b"nq.c2.bootstrap_installation_crash.no_write.v1\0",
    )
    .expect("compute exact logical Store snapshot")
}

fn assert_discontinuity_restart_no_write(
    harness: PreparedBootstrapHarnessV1,
    custody_root: &Path,
    path: DiscontinuityPathV1,
    cut: DiscontinuityProjectionCutV1,
    logical_before: String,
    fixed_before: BTreeMap<&'static str, Option<ExactFileSnapshotV1>>,
) {
    let store_root = harness
        .database
        .parent()
        .expect("database has Store root")
        .to_path_buf();
    assert_eq!(
        logical_store_snapshot(&harness.store),
        logical_before,
        "outer {path:?} Store transaction did not roll back at {cut:?}"
    );
    let fixed_after_crash = fixed_footprint_snapshot(&store_root);
    assert_eq!(
        fixed_after_crash != fixed_before,
        cut.has_carrier_first_suffix(),
        "{path:?} carrier-first classification disagrees at {cut:?}"
    );
    let custody_after_crash = directory_file_snapshot(custody_root);

    let PreparedBootstrapHarnessV1 {
        _store_directory,
        database,
        store,
        authority_fixture,
        qualified,
        manifest,
        grant: _,
    } = harness;
    drop(store);
    let mut reopened = Store::open(&database).expect("open interrupted discontinuity Store");
    let callback_entered = Cell::new(false);
    let reopen: Result<(), C2LiveReopenRefusalV1> = reopened
        .with_reopened_c2_generation_current_v1(
            &qualified,
            &manifest,
            |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
            |_session| {
                callback_entered.set(true);
                Ok(())
            },
        );
    assert!(
        !callback_entered.get(),
        "an interrupted {path:?} path recreated live current authority at {cut:?}"
    );
    let reopen_debug = format!("{reopen:?}");
    assert!(
        matches!(
            reopen,
            Err(C2LiveReopenRefusalV1::Lifecycle(
                C2LiveInstallationDriverRefusalV1::Live(
                    C2LiveSignerRefusalV1::CurrentSignerRevoked,
                ),
            ))
        ),
        "unexpected {path:?} revoked-current restart classification at {cut:?}: {reopen_debug}"
    );
    assert!(matches!(
        reopened.begin_writer_session(),
        Err(StoreError::C2OrdinaryOpenRequired)
    ));
    assert_eq!(
        logical_store_snapshot(&reopened),
        logical_before,
        "{path:?} restart wrote SQL at {cut:?}"
    );
    drop(reopened);
    assert_eq!(
        fixed_footprint_snapshot(&store_root),
        fixed_after_crash,
        "{path:?} restart rewrote B/G at {cut:?}"
    );
    assert_eq!(
        directory_file_snapshot(custody_root),
        custody_after_crash,
        "{path:?} restart rewrote custody at {cut:?}"
    );
    drop(_store_directory);
}

fn assert_injected_cut(result: Result<(), C2LiveBootstrapDriverRefusalV1>, expected: C2IoCutV1) {
    match result {
        Err(C2LiveBootstrapDriverRefusalV1::Installation(
            C2LiveInstallationDriverRefusalV1::Installation(
                C2LiveInstallationRefusalV1::InjectedCrash(actual),
            ),
        )) => assert_eq!(actual, expected),
        other => panic!("expected injected crash at {expected:?}, got {other:?}"),
    }
}

#[test]
fn production_bootstrap_observes_the_exact_reachable_cut_sequence_and_reopens_complete() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let PreparedBootstrapHarnessV1 {
            _store_directory,
            database,
            mut store,
            authority_fixture,
            qualified,
            manifest,
            grant,
        } = prepare_bootstrap_harness();
        let (result, observed) = with_test_bootstrap_installation_observer_v1(None, || {
            store.install_c2_live_from_bootstrap_grant_v1(
                &qualified,
                &manifest,
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
            )
        });
        result.expect("uninterrupted production bootstrap completes");
        assert_eq!(observed, REACHABLE_BOOTSTRAP_INSTALLATION_CUTS_V1);
        drop(store);

        let mut reopened = Store::open(&database).expect("reopen completed bootstrap Store");
        let callback_entered = Cell::new(false);
        reopened
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |session| {
                    callback_entered.set(true);
                    session.verify_live().map_err(C2LiveReopenRefusalV1::from)
                },
            )
            .expect("completed production bootstrap reopens GenerationCurrent");
        assert!(callback_entered.get());
        assert!(matches!(
            reopened.begin_writer_session(),
            Err(StoreError::C2OrdinaryOpenRequired)
        ));
        drop(_store_directory);
    });
}

#[test]
fn every_reachable_bootstrap_cut_restarts_fail_closed_and_fences_generic_writer() {
    for (index, cut) in REACHABLE_BOOTSTRAP_INSTALLATION_CUTS_V1
        .iter()
        .copied()
        .enumerate()
    {
        let custody_directory = tempdir().expect("create test custody root");
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
            .expect("seal test custody root permissions");

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let PreparedBootstrapHarnessV1 {
                _store_directory,
                database,
                mut store,
                authority_fixture,
                qualified,
                manifest,
                grant,
            } = prepare_bootstrap_harness();
            let (result, observed) =
                with_test_bootstrap_installation_observer_v1(Some(cut), || {
                    store.install_c2_live_from_bootstrap_grant_v1(
                        &qualified,
                        &manifest,
                        &grant,
                        |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                    )
                });
            assert_injected_cut(result, cut);
            assert_eq!(
                observed,
                REACHABLE_BOOTSTRAP_INSTALLATION_CUTS_V1[..=index],
                "observer trace must be the exact source-order prefix at {cut:?}"
            );

            let store_root = database.parent().expect("database has Store root");
            let logical_before = logical_store_snapshot(&store);
            let fixed_before = fixed_footprint_snapshot(store_root);
            let custody_before = directory_file_snapshot(custody_directory.path());
            drop(store);

            let mut reopened = Store::open(&database).expect("open exact interrupted Store");
            let callback_entered = Cell::new(false);
            let reopen: Result<(), C2LiveReopenRefusalV1> = reopened
                .with_reopened_c2_generation_current_v1(
                    &qualified,
                    &manifest,
                    |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                    |_session| {
                        callback_entered.set(true);
                        Ok(())
                    },
                );
            assert!(
                !callback_entered.get(),
                "partial state minted a writer at {cut:?}"
            );
            match (cut, reopen) {
                (
                    C2IoCutV1::BackendProfilePreflight | C2IoCutV1::RootShapeObservation,
                    Err(C2LiveReopenRefusalV1::Lifecycle(C2LiveInstallationDriverRefusalV1::Live(
                        C2LiveSignerRefusalV1::GenerationCurrentAbsent,
                    ))),
                ) => {}
                (
                    _,
                    Err(C2LiveReopenRefusalV1::Lifecycle(C2LiveInstallationDriverRefusalV1::Live(
                        C2LiveSignerRefusalV1::GenerationCurrentIncomplete,
                    ))),
                ) => {}
                (_, other) => panic!("unexpected restart classification at {cut:?}: {other:?}"),
            }
            assert!(matches!(
                reopened.begin_writer_session(),
                Err(StoreError::C2OrdinaryOpenRequired)
            ));
            let logical_after = logical_store_snapshot(&reopened);
            drop(reopened);

            assert_eq!(
                logical_after, logical_before,
                "restart wrote SQL at {cut:?}"
            );
            assert_eq!(
                fixed_footprint_snapshot(store_root),
                fixed_before,
                "restart rewrote fixed C2 carriers at {cut:?}"
            );
            assert_eq!(
                directory_file_snapshot(custody_directory.path()),
                custody_before,
                "restart rewrote signer custody at {cut:?}"
            );
            drop(_store_directory);
        });
    }
}

#[test]
fn healthy_successor_projection_cuts_restart_as_current_or_incomplete_without_writes() {
    for cut in HEALTHY_SUCCESSOR_PROJECTION_CUTS_V1.iter().copied() {
        let custody_directory = tempdir().expect("create test custody root");
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
            .expect("seal test custody root permissions");

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let mut harness = prepare_bootstrap_harness();
            complete_bootstrap_installation(&mut harness);
            let store_root = harness
                .database
                .parent()
                .expect("database has Store root")
                .to_path_buf();
            let logical_before = logical_store_snapshot(&harness.store);
            let fixed_before = fixed_footprint_snapshot(&store_root);
            harness
                .store
                .connection
                .execute_batch(cut.trigger_sql())
                .expect("install exact closed transition fault trigger");

            let intent = C2HealthySuccessorIntentV1::new(
                sha256_bytes(b"healthy-crash/transition/a-to-b"),
                sha256_bytes(b"healthy-crash/challenge/b"),
                10_000,
            )
            .expect("construct exact healthy-successor intent");
            let refusal = harness
                .store
                .rotate_c2_live_healthy_successor_v1(
                    &harness.qualified,
                    &harness.manifest,
                    &intent,
                    |snapshot| {
                        resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
                    },
                )
                .expect_err("the exact selected healthy projection cut must refuse");
            assert_healthy_projection_refusal(cut, refusal);
            assert_eq!(
                logical_store_snapshot(&harness.store),
                logical_before,
                "outer Store transaction did not roll back at {cut:?}"
            );
            let fixed_after_crash = fixed_footprint_snapshot(&store_root);
            assert_eq!(
                fixed_after_crash != fixed_before,
                cut.has_carrier_first_suffix(),
                "physical carrier-first classification disagrees at {cut:?}"
            );
            let custody_after_crash = directory_file_snapshot(custody_directory.path());

            let PreparedBootstrapHarnessV1 {
                _store_directory,
                database,
                store,
                authority_fixture,
                qualified,
                manifest,
                grant: _,
            } = harness;
            drop(store);
            let mut reopened = Store::open(&database).expect("open interrupted healthy Store");
            let callback_entered = Cell::new(false);
            let reopen: Result<(), C2LiveReopenRefusalV1> = reopened
                .with_reopened_c2_generation_current_v1(
                    &qualified,
                    &manifest,
                    |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                    |_session| {
                        callback_entered.set(true);
                        Ok(())
                    },
                );
            if cut.has_carrier_first_suffix() {
                assert!(!callback_entered.get());
                assert!(matches!(
                    reopen,
                    Err(C2LiveReopenRefusalV1::Lifecycle(
                        C2LiveInstallationDriverRefusalV1::Live(
                            C2LiveSignerRefusalV1::GenerationCurrentIncomplete,
                        ),
                    ))
                ));
            } else {
                reopen.expect("pre-carrier refusal must reopen the old exact current signer");
                assert!(callback_entered.get());
            }
            assert!(matches!(
                reopened.begin_writer_session(),
                Err(StoreError::C2OrdinaryOpenRequired)
            ));
            assert_eq!(
                logical_store_snapshot(&reopened),
                logical_before,
                "restart wrote SQL at {cut:?}"
            );
            drop(reopened);
            assert_eq!(
                fixed_footprint_snapshot(&store_root),
                fixed_after_crash,
                "restart rewrote B/G at {cut:?}"
            );
            assert_eq!(
                directory_file_snapshot(custody_directory.path()),
                custody_after_crash,
                "restart rewrote custody at {cut:?}"
            );
            drop(_store_directory);
        });
    }
}

#[test]
fn restore_projection_cuts_restart_revoked_or_incomplete_without_writes() {
    for cut in DISCONTINUITY_PROJECTION_CUTS_V1.iter().copied() {
        let custody_directory = tempdir().expect("create restore custody root");
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
            .expect("seal restore custody root permissions");

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let mut harness = prepare_bootstrap_harness();
            complete_bootstrap_and_revoke(&mut harness);
            let (request, authorization) = exact_restore_pair_for_test(
                &mut harness.store,
                &harness.qualified,
                &harness.authority_fixture,
            );
            let store_root = harness
                .database
                .parent()
                .expect("database has Store root")
                .to_path_buf();
            let logical_before = logical_store_snapshot(&harness.store);
            let fixed_before = fixed_footprint_snapshot(&store_root);
            harness
                .store
                .connection
                .execute_batch(&cut.trigger_sql(DiscontinuityPathV1::Restore))
                .expect("install exact closed restore fault trigger");

            let refusal = harness
                .store
                .restore_c2_live_historical_foundation_v1(
                    &harness.qualified,
                    &harness.manifest,
                    &request,
                    &authorization,
                    |snapshot| {
                        resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
                    },
                )
                .expect_err("the exact selected restore projection cut must refuse");
            assert_discontinuity_projection_refusal(DiscontinuityPathV1::Restore, cut, refusal);
            assert_discontinuity_restart_no_write(
                harness,
                custody_directory.path(),
                DiscontinuityPathV1::Restore,
                cut,
                logical_before,
                fixed_before,
            );
        });
    }
}

#[test]
fn recovery_projection_cuts_restart_revoked_or_incomplete_without_writes() {
    for cut in DISCONTINUITY_PROJECTION_CUTS_V1.iter().copied() {
        let custody_directory = tempdir().expect("create recovery custody root");
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
            .expect("seal recovery custody root permissions");

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let mut harness = prepare_bootstrap_harness();
            complete_bootstrap_and_revoke(&mut harness);
            let intent = C2RecoveryPreparationIntentV1::new(
                C2RecoveryPredecessorStatusV1::InactiveRevoked,
                sha256_bytes(b"recovery-crash/transition"),
                sha256_bytes(b"recovery-crash/challenge"),
            )
            .expect("construct exact recovery crash intent");
            let prepared = harness
                .store
                .prepare_c2_live_recovery_v1(
                    &harness.qualified,
                    &harness.manifest,
                    &intent,
                    |snapshot| {
                        resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
                    },
                )
                .expect("prepare exact recovery crash request");
            let grant = sign_exact_recovery_grant_for_test(
                prepared.request(),
                &SigningKey::from_bytes(&[1_u8; 32]),
            );
            let store_root = harness
                .database
                .parent()
                .expect("database has Store root")
                .to_path_buf();
            let logical_before = logical_store_snapshot(&harness.store);
            let fixed_before = fixed_footprint_snapshot(&store_root);
            harness
                .store
                .connection
                .execute_batch(&cut.trigger_sql(DiscontinuityPathV1::Recovery))
                .expect("install exact closed recovery fault trigger");

            let refusal = harness
                .store
                .recover_c2_live_new_foundation_v1(
                    &harness.qualified,
                    &harness.manifest,
                    prepared.request(),
                    &grant,
                    |snapshot| {
                        resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
                    },
                )
                .expect_err("the exact selected recovery projection cut must refuse");
            assert_discontinuity_projection_refusal(DiscontinuityPathV1::Recovery, cut, refusal);
            assert_discontinuity_restart_no_write(
                harness,
                custody_directory.path(),
                DiscontinuityPathV1::Recovery,
                cut,
                logical_before,
                fixed_before,
            );
        });
    }
}

#[test]
fn restore_msg07_carrier_first_restart_is_fail_stop_without_an_explicit_restart_law() {
    let custody_directory = tempdir().expect("create restore fail-stop custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal restore fail-stop custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_and_revoke(&mut harness);
        let (request, authorization) = exact_restore_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.authority_fixture,
        );
        let store_root = harness
            .database
            .parent()
            .expect("database has Store root")
            .to_path_buf();
        let logical_before = logical_store_snapshot(&harness.store);
        let fixed_before = fixed_footprint_snapshot(&store_root);
        harness
            .store
            .connection
            .execute_batch(
                &DiscontinuityProjectionCutV1::Msg07SuccessorPop
                    .trigger_sql(DiscontinuityPathV1::Restore),
            )
            .expect("install exact restore MSG-07 fault trigger");

        let refusal = harness
            .store
            .restore_c2_live_historical_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect_err("restore MSG-07 carrier-first cut must refuse");
        assert_discontinuity_projection_refusal(
            DiscontinuityPathV1::Restore,
            DiscontinuityProjectionCutV1::Msg07SuccessorPop,
            refusal,
        );
        assert_eq!(logical_store_snapshot(&harness.store), logical_before);
        let fixed_after_crash = fixed_footprint_snapshot(&store_root);
        assert_ne!(
            fixed_after_crash, fixed_before,
            "the selected cut must leave one authenticated carrier-first suffix"
        );
        let custody_after_crash = directory_file_snapshot(custody_directory.path());

        let PreparedBootstrapHarnessV1 {
            _store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        drop(store);
        let mut reopened = Store::open(&database).expect("open interrupted restore Store");
        let callback_entered = Cell::new(false);
        let direct_reopen: Result<(), C2LiveReopenRefusalV1> = reopened
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |_session| {
                    callback_entered.set(true);
                    Ok(())
                },
            );
        assert!(!callback_entered.get());
        assert!(matches!(
            direct_reopen,
            Err(C2LiveReopenRefusalV1::Lifecycle(
                C2LiveInstallationDriverRefusalV1::Live(
                    C2LiveSignerRefusalV1::CurrentSignerRevoked,
                ),
            ))
        ));

        // The external carrier remains inert evidence.  Without a separately
        // frozen restart-continuation law, presenting the exact MSG-13 again
        // to a fresh Store actor must not inherit the old pending brand or
        // silently cross into recovery.
        let retry = reopened
            .restore_c2_live_historical_foundation_v1(
                &qualified,
                &manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
            )
            .expect_err("restore pending prefix must fail-stop after restart");
        assert!(matches!(
            retry,
            C2LiveTransitionDriverRefusalV1::Substrate(C2LiveInstallationDriverRefusalV1::Live(
                C2LiveSignerRefusalV1::GenerationCurrentIncomplete,
            ),)
        ));
        assert!(matches!(
            reopened.begin_writer_session(),
            Err(StoreError::C2OrdinaryOpenRequired)
        ));
        assert_eq!(logical_store_snapshot(&reopened), logical_before);
        drop(reopened);
        assert_eq!(fixed_footprint_snapshot(&store_root), fixed_after_crash);
        assert_eq!(
            directory_file_snapshot(custody_directory.path()),
            custody_after_crash
        );
        drop(_store_directory);
    });
}

#[test]
fn recovery_msg07_carrier_first_restart_is_fail_stop_without_an_explicit_restart_law() {
    let custody_directory = tempdir().expect("create recovery fail-stop custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal recovery fail-stop custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_and_revoke(&mut harness);
        let (prepared, grant) = exact_recovery_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let store_root = harness
            .database
            .parent()
            .expect("database has Store root")
            .to_path_buf();
        let logical_before = logical_store_snapshot(&harness.store);
        let fixed_before = fixed_footprint_snapshot(&store_root);
        harness
            .store
            .connection
            .execute_batch(
                &DiscontinuityProjectionCutV1::Msg07SuccessorPop
                    .trigger_sql(DiscontinuityPathV1::Recovery),
            )
            .expect("install exact recovery MSG-07 fault trigger");

        let refusal = harness
            .store
            .recover_c2_live_new_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                prepared.request(),
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect_err("recovery MSG-07 carrier-first cut must refuse");
        assert_discontinuity_projection_refusal(
            DiscontinuityPathV1::Recovery,
            DiscontinuityProjectionCutV1::Msg07SuccessorPop,
            refusal,
        );
        assert_eq!(logical_store_snapshot(&harness.store), logical_before);
        let fixed_after_crash = fixed_footprint_snapshot(&store_root);
        assert_ne!(
            fixed_after_crash, fixed_before,
            "the selected cut must leave one authenticated carrier-first suffix"
        );
        let custody_after_crash = directory_file_snapshot(custody_directory.path());

        let PreparedBootstrapHarnessV1 {
            _store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        drop(store);
        let mut reopened = Store::open(&database).expect("open interrupted recovery Store");
        let callback_entered = Cell::new(false);
        let direct_reopen: Result<(), C2LiveReopenRefusalV1> = reopened
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |_session| {
                    callback_entered.set(true);
                    Ok(())
                },
            );
        assert!(!callback_entered.get());
        assert!(matches!(
            direct_reopen,
            Err(C2LiveReopenRefusalV1::Lifecycle(
                C2LiveInstallationDriverRefusalV1::Live(
                    C2LiveSignerRefusalV1::CurrentSignerRevoked,
                ),
            ))
        ));

        // A fresh Store actor still cannot turn a serialized MSG-15/request
        // pair into the prior process's RecoveryEntryAuthority.  The orphan
        // requires an explicit restart law; no restore fallback is implied.
        let retry = reopened
            .recover_c2_live_new_foundation_v1(
                &qualified,
                &manifest,
                prepared.request(),
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
            )
            .expect_err("recovery pending prefix must fail-stop after restart");
        assert!(matches!(
            retry,
            C2LiveTransitionDriverRefusalV1::Substrate(C2LiveInstallationDriverRefusalV1::Live(
                C2LiveSignerRefusalV1::GenerationCurrentIncomplete,
            ),)
        ));
        assert!(matches!(
            reopened.begin_writer_session(),
            Err(StoreError::C2OrdinaryOpenRequired)
        ));
        assert_eq!(logical_store_snapshot(&reopened), logical_before);
        drop(reopened);
        assert_eq!(fixed_footprint_snapshot(&store_root), fixed_after_crash);
        assert_eq!(
            directory_file_snapshot(custody_directory.path()),
            custody_after_crash
        );
        drop(_store_directory);
    });
}

const SOURCE_IO_CHILD_CUT_ENV: &str = "NQ_C2_SOURCE_IO_CHILD_CUT";
const SOURCE_IO_CHILD_SCENARIO_ENV: &str = "NQ_C2_SOURCE_IO_CHILD_SCENARIO";
const SOURCE_IO_CHILD_STORE_ROOT_ENV: &str = "NQ_C2_SOURCE_IO_CHILD_STORE_ROOT";
const SOURCE_IO_CHILD_CUSTODY_ROOT_ENV: &str = "NQ_C2_SOURCE_IO_CHILD_CUSTODY_ROOT";

const SOURCE_IO_PREPARE_CUTS_V1: &[&str] = &[
    "SC-18", "SC-19", "SC-23", "SC-26", "SC-32", "SC-33", "SC-34", "SC-35", "SC-36",
    "SC-38", "SC-45", "SC-46", "SC-47", "SC-48", "SC-51", "SC-52", "SC-53",
];
const SOURCE_IO_INSTALL_CUTS_V1: &[&str] = &[
    "SC-01", "SC-02", "SC-03", "SC-04", "SC-05", "SC-06", "SC-07", "SC-08", "SC-09",
    "SC-10", "SC-11", "SC-12", "SC-13", "SC-27", "SC-30", "SC-37", "SC-39", "SC-44",
    "SC-50", "SC-54", "SC-57", "SC-58", "SC-59",
];
const SOURCE_IO_HEALTHY_CUTS_V1: &[&str] = &[
    "SC-15", "SC-16", "SC-17", "SC-25", "SC-40", "SC-60", "SC-61", "SC-62", "SC-63",
    "SC-64", "SC-65", "SC-66", "SC-70",
];

fn source_io_scenario_v1(cut: &str) -> &'static str {
    if SOURCE_IO_PREPARE_CUTS_V1.contains(&cut) || matches!(cut, "SC-21" | "SC-22" | "SC-24") {
        "prepare"
    } else if SOURCE_IO_INSTALL_CUTS_V1.contains(&cut) || cut == "SC-31" {
        "install"
    } else if SOURCE_IO_HEALTHY_CUTS_V1.contains(&cut) {
        "healthy"
    } else {
        match cut {
            "SC-14" => "recovery_prepare",
            "SC-20" => "effect_error",
            "SC-28" => "install_batch_error",
            "SC-29" => "install_post_state_same",
            "SC-41" | "SC-42" => "reproject",
            "SC-43" => "reproject_error",
            "SC-49" => "production_custody_root",
            "SC-55" => "revoke",
            "SC-56" => "quarantine",
            "SC-67" => "terminal_insert_error",
            "SC-68" => "terminal_mismatch",
            "SC-69" => "terminal_resolution_error",
            _ => panic!("source-derived cut {cut} has no closed crash scenario"),
        }
    }
}

fn source_io_manifest_cuts_v1() -> Vec<String> {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/assets/nq.c2_io_crash_cut_manifest.v1.json"
    ))
    .expect("parse checked source-derived crash-cut manifest");
    manifest["nodes"]
        .as_array()
        .expect("source-derived manifest nodes")
        .iter()
        .map(|node| {
            node["cut"]
                .as_str()
                .expect("source-derived manifest cut")
                .to_owned()
        })
        .collect()
}

#[test]
fn source_io_manifest_has_one_closed_scenario_for_every_exact_cut() {
    let cuts = source_io_manifest_cuts_v1();
    assert_eq!(cuts.len(), 70, "source-derived manifest cardinality changed");
    assert_eq!(
        cuts.iter().collect::<BTreeSet<_>>().len(),
        cuts.len(),
        "source-derived manifest contains a duplicate cut",
    );
    for cut in &cuts {
        let scenario = source_io_scenario_v1(cut);
        assert!(!scenario.is_empty(), "{cut} has no exact crash scenario");
    }
}

fn source_io_healthy_intent_v1(label: &[u8]) -> C2HealthySuccessorIntentV1 {
    C2HealthySuccessorIntentV1::new(
        sha256_bytes(label),
        sha256_bytes(&[label, b"/challenge"].concat()),
        10_000,
    )
    .expect("construct exact source-I/O healthy intent")
}

fn run_source_io_healthy_v1(harness: &mut PersistentBootstrapHarnessV1) {
    let intent = source_io_healthy_intent_v1(b"source-io-child/healthy/transition");
    let _ = harness.store.rotate_c2_live_healthy_successor_v1(
        &harness.qualified,
        &harness.manifest,
        &intent,
        |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
    );
}

fn run_source_io_child_operation(
    cut: &'static str,
    scenario: &str,
    store_root: &Path,
    custody_root: &Path,
) {
    let operation = || {
        let mut harness = initialize_persistent_bootstrap_harness(store_root);
        match scenario {
            "prepare" => {
                let _ = with_source_io_observer_v1(Some(cut), || {
                    prepare_persistent_bootstrap_grant(&mut harness)
                });
            }
            "install" => {
                let grant = prepare_persistent_bootstrap_grant(&mut harness);
                let _ = with_source_io_observer_v1(Some(cut), || {
                    harness.store.install_c2_live_from_bootstrap_grant_v1(
                        &harness.qualified,
                        &harness.manifest,
                        &grant,
                        |snapshot| {
                            resolve_runtime_authority_fixture(
                                &harness.authority_fixture,
                                snapshot,
                            )
                        },
                    )
                });
            }
            "healthy" => {
                complete_persistent_bootstrap(&mut harness);
                let _ = with_source_io_observer_v1(Some(cut), || {
                    run_source_io_healthy_v1(&mut harness)
                });
            }
            "revoke" => {
                complete_persistent_bootstrap(&mut harness);
                let _ = with_source_io_observer_v1(Some(cut), || {
                    apply_exact_revocation_for_test(
                        &mut harness.store,
                        &harness.qualified,
                        &harness.manifest,
                        &harness.authority_fixture,
                    )
                });
            }
            "recovery_prepare" => {
                complete_persistent_bootstrap(&mut harness);
                apply_exact_revocation_for_test(
                    &mut harness.store,
                    &harness.qualified,
                    &harness.manifest,
                    &harness.authority_fixture,
                );
                let _ = with_source_io_observer_v1(Some(cut), || {
                    exact_recovery_pair_for_test(
                        &mut harness.store,
                        &harness.qualified,
                        &harness.manifest,
                        &harness.authority_fixture,
                    )
                });
            }
            "effect_error" => {
                harness.store.connection.execute_batch(
                    "CREATE TEMP TRIGGER c2_source_io_effect_error
                     BEFORE INSERT ON c2_custody_proposal_preparations
                     BEGIN SELECT RAISE(ABORT, 'source I/O effect refusal'); END;",
                ).expect("install exact effect-error precursor");
                let _ = with_source_io_observer_v1(Some(cut), || {
                    prepare_persistent_bootstrap_grant(&mut harness)
                });
            }
            "install_batch_error" => {
                let grant = prepare_persistent_bootstrap_grant(&mut harness);
                harness.store.connection.execute_batch(
                    "CREATE TEMP TRIGGER c2_source_io_install_batch_error
                     BEFORE INSERT ON c2_signer_message_appends
                     WHEN NEW.route = 'msg09_installation_intent'
                     BEGIN SELECT RAISE(ABORT, 'source I/O installation batch refusal'); END;",
                ).expect("install exact installation-batch precursor");
                let _ = with_source_io_observer_v1(Some(cut), || {
                    harness.store.install_c2_live_from_bootstrap_grant_v1(
                        &harness.qualified, &harness.manifest, &grant,
                        |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
                    )
                });
            }
            "install_post_state_same" => {
                let grant = prepare_persistent_bootstrap_grant(&mut harness);
                harness.store.connection.execute_batch(
                    "CREATE TEMP TRIGGER c2_source_io_install_post_state_same
                     BEFORE INSERT ON c2_signer_message_appends
                     WHEN NEW.route IN ('msg03_physical_generation_bootstrap', 'msg09_installation_intent')
                     BEGIN SELECT RAISE(IGNORE); END;",
                ).expect("install exact installation post-state precursor");
                let _ = with_source_io_observer_v1(Some(cut), || {
                    harness.store.install_c2_live_from_bootstrap_grant_v1(
                        &harness.qualified, &harness.manifest, &grant,
                        |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
                    )
                });
            }
            "reproject" | "reproject_error" => {
                complete_persistent_bootstrap(&mut harness);
                harness.store.connection.execute_batch(
                    "CREATE TEMP TRIGGER c2_source_io_carrier_first
                     BEFORE INSERT ON c2_signer_message_appends
                     WHEN NEW.route = 'msg07_successor_pop'
                     BEGIN SELECT RAISE(ABORT, 'source I/O carrier-first prefix'); END;",
                ).expect("install exact carrier-first precursor");
                run_source_io_healthy_v1(&mut harness);
                let database = harness.database.clone();
                drop(harness.store);
                let mut reopened = Store::open(&database).expect("open exact carrier-first Store");
                if scenario == "reproject_error" {
                    reopened.connection.execute_batch(
                        "CREATE TEMP TRIGGER c2_source_io_reproject_error
                         BEFORE INSERT ON c2_signer_message_appends
                         BEGIN SELECT RAISE(ABORT, 'source I/O reprojection refusal'); END;",
                    ).expect("install exact reprojection-error precursor");
                }
                let _ = with_source_io_observer_v1(Some(cut), || {
                    reopened.with_reopened_c2_generation_current_v1(
                        &harness.qualified, &harness.manifest,
                        |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
                        |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
                    )
                });
            }
            "terminal_insert_error" | "terminal_mismatch" | "terminal_resolution_error" => {
                complete_persistent_bootstrap(&mut harness);
                let sql = match scenario {
                    "terminal_insert_error" =>
                        "CREATE TEMP TRIGGER c2_source_io_terminal_current BEFORE INSERT ON c2_signer_current_binding_projection BEGIN SELECT RAISE(ABORT, 'terminal insert'); END;",
                    "terminal_mismatch" =>
                        "CREATE TEMP TRIGGER c2_source_io_terminal_current BEFORE INSERT ON c2_signer_current_binding_projection BEGIN SELECT RAISE(IGNORE); END;
                         CREATE TEMP TRIGGER c2_source_io_terminal_succession BEFORE INSERT ON c2_signer_succession_projection BEGIN SELECT RAISE(IGNORE); END;
                         CREATE TEMP TRIGGER c2_source_io_terminal_lineage BEFORE INSERT ON c2_signer_lineage_projection BEGIN SELECT RAISE(IGNORE); END;
                         CREATE TEMP TRIGGER c2_source_io_terminal_edges BEFORE INSERT ON c2_signer_lineage_edge_projection BEGIN SELECT RAISE(IGNORE); END;
                         CREATE TEMP TRIGGER c2_source_io_terminal_completion BEFORE INSERT ON c2_signer_lineage_completion_projection BEGIN SELECT RAISE(IGNORE); END;",
                    _ =>
                        "CREATE TEMP TRIGGER c2_source_io_terminal_completion BEFORE INSERT ON c2_signer_lineage_completion_projection BEGIN SELECT RAISE(IGNORE); END;",
                };
                harness.store.connection.execute_batch(sql).expect("install exact terminal precursor");
                let _ = with_source_io_observer_v1(Some(cut), || run_source_io_healthy_v1(&mut harness));
            }
            "quarantine" => {
                complete_persistent_bootstrap(&mut harness);
                let _ = with_source_io_observer_v1(Some(cut), || {
                    apply_exact_quarantine_for_test(
                        &mut harness.store,
                        &harness.qualified,
                        &harness.manifest,
                        &harness.authority_fixture,
                    )
                });
            }
            "production_custody_root" => {
                let _ = with_source_io_observer_v1(Some(cut), || {
                    prepare_persistent_bootstrap_grant(&mut harness)
                });
            }
            other => panic!("unknown source-I/O child scenario {other}"),
        }
        panic!("selected source-I/O cut {cut} was not reached by {scenario}");
    };
    if scenario == "production_custody_root" {
        operation();
    } else {
        with_test_production_custody_root_v1(custody_root, operation);
    }
}

#[test]
fn source_io_crash_child_role() {
    let Ok(cut) = env::var(SOURCE_IO_CHILD_CUT_ENV) else {
        return;
    };
    let scenario = env::var(SOURCE_IO_CHILD_SCENARIO_ENV).expect("source-I/O child scenario");
    let store_root = PathBuf::from(
        env::var(SOURCE_IO_CHILD_STORE_ROOT_ENV).expect("source-I/O child Store root"),
    );
    let custody_root = PathBuf::from(
        env::var(SOURCE_IO_CHILD_CUSTODY_ROOT_ENV).expect("source-I/O child custody root"),
    );
    let cut: &'static str = Box::leak(cut.into_boxed_str());
    run_source_io_child_operation(cut, &scenario, &store_root, &custody_root);
}

fn assert_source_io_child_restart(cut: &str, scenario: &str) {
    let store_directory = tempdir().expect("create source-I/O child Store root");
    let custody_directory = tempdir().expect("create source-I/O child custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal source-I/O child custody root permissions");
    let output = Command::new(env::current_exe().expect("resolve current test executable"))
        .arg("--exact")
        .arg("store_generation::live_c2_bootstrap_crash_tests::source_io_crash_child_role")
        .arg("--nocapture")
        .env(SOURCE_IO_CHILD_CUT_ENV, cut)
        .env(SOURCE_IO_CHILD_SCENARIO_ENV, scenario)
        .env(SOURCE_IO_CHILD_STORE_ROOT_ENV, store_directory.path())
        .env(SOURCE_IO_CHILD_CUSTODY_ROOT_ENV, custody_directory.path())
        .output()
        .expect("run abrupt source-I/O child");
    assert_eq!(
        output.status.code(),
        Some(197),
        "source-I/O child did not stop at {cut} ({scenario}): stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let database = store_directory.path().join(C2_SQLITE_FILE_V1);
    let fixed_before = fixed_footprint_snapshot(store_directory.path());
    let custody_before = directory_file_snapshot(custody_directory.path());
    let mut reopened = Store::open(&database).expect("open source-I/O interrupted Store");
    let logical_before = logical_store_snapshot(&reopened);
    let has_c2_state = reopened
        .has_c2_generation_state()
        .expect("classify exact interrupted C2 state");
    if has_c2_state {
        assert!(matches!(
            reopened.begin_writer_session(),
            Err(StoreError::C2OrdinaryOpenRequired)
        ));
        let fixture = RawAuthorityFixture::fresh_genesis();
        let manifest = executable_manifest();
        let qualified = StoreC2QualifiedRuntimeEvidenceV1::for_test(
            sha256_bytes(b"bootstrap-crash/candidate"),
            sha256_bytes(b"bootstrap-crash/source-tree"),
            sha256_bytes(&fs::read("/proc/self/exe").expect("read parent Linux test image")),
            manifest.manifest_identity().clone(),
        );
        let callback_entered = Cell::new(false);
        with_test_production_custody_root_v1(custody_directory.path(), || {
            let reopen = reopened.with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                |session| {
                    callback_entered.set(true);
                    session.verify_live().map_err(C2LiveReopenRefusalV1::from)
                },
            );
            assert_eq!(
                reopen.is_ok(),
                callback_entered.get(),
                "{cut} must either mint one freshly reverified current context or refuse before callback: {reopen:?}",
            );
        });
    } else {
        drop(
            reopened
                .begin_writer_session()
                .expect("pre-C2 source cut remains an ordinary Store"),
        );
    }
    assert_eq!(
        logical_store_snapshot(&reopened),
        logical_before,
        "restart inspection wrote logical Store state at {cut}",
    );
    drop(reopened);
    assert_eq!(
        fixed_footprint_snapshot(store_directory.path()),
        fixed_before,
        "restart inspection rewrote fixed carriers at {cut}",
    );
    assert_eq!(
        directory_file_snapshot(custody_directory.path()),
        custody_before,
        "restart inspection rewrote custody at {cut}",
    );
}

#[test]
fn every_normal_source_io_cut_abruptly_restarts_with_exact_fence_and_no_authority_inheritance() {
    let selected = env::var("NQ_C2_SOURCE_IO_PARENT_ONLY").ok();
    let cuts = source_io_manifest_cuts_v1();
    assert_eq!(cuts.len(), 70, "source-derived manifest cardinality changed");
    assert_eq!(cuts.iter().collect::<BTreeSet<_>>().len(), cuts.len(), "duplicate source-derived cut");
    for cut in cuts {
        let scenario = source_io_scenario_v1(&cut);
        if selected.as_deref().is_none_or(|value| value == cut) {
            assert_source_io_child_restart(&cut, scenario);
        }
    }
}
