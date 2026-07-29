//! Opaque exact-byte custody for one governed diagnostic invocation.
//!
//! This module deliberately exposes storage mechanics only. A Store-owned
//! verifier may advance the physical index frontier only after exact arena/SQL
//! correspondence is reopened from a reservation identity. It does not
//! establish native provider correspondence, an evaluator occurrence,
//! diagnostic semantic validity, reliance, or authority; those semantic checks
//! belong to `nq-core` and its consumers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::Value;

use crate::custody_arena::{
    AcquisitionCarrier, ArenaInventoryEntry, ArenaLayout, ArenaPrelaunchBinding, ArenaState,
    CustodyArena, DerivationClaim, DerivedV2ClosureCandidate,
};
use crate::{
    DiagnosticArtifactByteState, DiagnosticArtifactLookup, DiagnosticArtifactOrigin,
    MAX_PUBLIC_QUERY_ROWS, RuntimeCheckpointDependencyBinding,
    RuntimeDependencyGenerationByteState, RuntimeLedgerCheckpoint, RuntimeRecordRow, Store,
    StoreError, diagnostic_artifact_execution_binding_on_connection,
    diagnostic_artifact_on_connection, runtime_checkpoint_by_id_on_connection,
    runtime_checkpoint_dependency_on_connection, runtime_record_by_id_on_connection,
    validate_diagnostic_artifact_invariants, validate_provider_intake_invariants,
    validate_runtime_record_ledger,
};

/// Store-internal carrier schema used to keep the exact core-validated closure
/// in a preallocated custody arena.
///
/// This is an on-disk storage format, not an NQ/Nightshift product contract.
/// Its presence alone establishes no diagnostic or reliance semantics.
pub const GOVERNED_CUSTODY_CLOSURE_SCHEMA: &str = "nq.governed_execution_custody_closure.v1";

/// Exact immutable identity and capacity bound established before launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCustodyReservation {
    pub reservation_record_id: Sha256Digest,
    pub reservation_manifest_digest: Sha256Digest,
    pub outer_request_record_id: Sha256Digest,
    pub outer_request_id: String,
    pub outer_request_digest: Sha256Digest,
    pub dependency_generation_id: Sha256Digest,
    pub dependency_generation_custody_digest: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub prelaunch_checkpoint_id: Sha256Digest,
    pub prelaunch_checkpoint_digest: Sha256Digest,
    pub dependency_closure_capacity_bytes: u64,
    pub raw_capacity_bytes: u64,
    pub final_capacity_bytes: u64,
    pub protected_failure_capacity_bytes: u64,
}

impl GovernedCustodyReservation {
    fn prelaunch(&self) -> ArenaPrelaunchBinding {
        ArenaPrelaunchBinding {
            reservation_record_id: self.reservation_record_id.clone(),
            reservation_manifest_digest: self.reservation_manifest_digest.clone(),
            outer_request_record_id: self.outer_request_record_id.clone(),
            outer_request_id: self.outer_request_id.clone(),
            outer_request_digest: self.outer_request_digest.clone(),
            dependency_generation_id: self.dependency_generation_id.clone(),
            dependency_generation_custody_digest: self.dependency_generation_custody_digest.clone(),
            trust_anchor_id: self.trust_anchor_id.clone(),
            prelaunch_checkpoint_id: self.prelaunch_checkpoint_id.clone(),
            prelaunch_checkpoint_digest: self.prelaunch_checkpoint_digest.clone(),
        }
    }

    fn layout(&self) -> Result<ArenaLayout, StoreError> {
        ArenaLayout::new(
            self.dependency_closure_capacity_bytes,
            self.raw_capacity_bytes,
            self.final_capacity_bytes,
            self.protected_failure_capacity_bytes,
        )
        .map_err(custody_error)
    }
}

/// Public storage state for one arena.
///
/// These are custody states, not diagnostic outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedCustodyState {
    Reserved,
    LaunchClaimed,
    AcquisitionSealed,
    DerivationClaimed,
    FinalClosureIndexPending,
    FinalClosureIndexed,
    FailedIndeterminate,
    ExpiredUnlaunched,
}

impl From<ArenaState> for GovernedCustodyState {
    fn from(value: ArenaState) -> Self {
        match value {
            ArenaState::Reserved => Self::Reserved,
            ArenaState::Claimed => Self::LaunchClaimed,
            ArenaState::RawEvidenceSealed => Self::AcquisitionSealed,
            ArenaState::DerivationClaimed => Self::DerivationClaimed,
            ArenaState::FinalV2SealedIndexPending => Self::FinalClosureIndexPending,
            ArenaState::FinalV2SealedIndexed => Self::FinalClosureIndexed,
            ArenaState::FailedIndeterminate => Self::FailedIndeterminate,
            ArenaState::ExpiredUnlaunched => Self::ExpiredUnlaunched,
        }
    }
}

/// Restart classification of one exact physical custody frontier.
///
/// This is a storage/recovery classification only. It is not a diagnostic
/// result and grants no right to rerun a provider or evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedCustodyRecoveryClass {
    /// Physical capacity exists, but the arena has no physical launch claim.
    ///
    /// This alone does not say whether a SQLite launch record exists; the
    /// future Store-owned launch/index join remains a separate obligation.
    ReservationWithoutPhysicalLaunchClaim,
    /// A launch was durably claimed, but no provider occurrence was sealed.
    LaunchedWithoutAcquisition,
    /// Provider bytes are sealed and may be reopened without reacquisition.
    AcquisitionAwaitingDerivation,
    /// A derivation claim exists without a final closure; it must not mint a
    /// second evaluation occurrence.
    DerivationWithoutFinalClosure,
    /// Exact final bytes exist, but their SQLite projection has not been
    /// independently verified.
    FinalClosureAwaitingProjection,
    /// Exact final bytes reached the projection-verified frontier.
    ///
    /// This physical state bit records the completed transition; it is not a
    /// current integrity oracle. Readers that need present correspondence must
    /// rerun the reservation-only verifier, especially after later SQL
    /// corruption.
    Indexed,
    /// One exact protected failure carrier terminalized the invocation.
    ProtectedFailure,
    /// An unlaunched reservation was terminally expired.
    ExpiredUnlaunched,
}

impl From<ArenaState> for GovernedCustodyRecoveryClass {
    fn from(value: ArenaState) -> Self {
        match value {
            ArenaState::Reserved => Self::ReservationWithoutPhysicalLaunchClaim,
            ArenaState::Claimed => Self::LaunchedWithoutAcquisition,
            ArenaState::RawEvidenceSealed => Self::AcquisitionAwaitingDerivation,
            ArenaState::DerivationClaimed => Self::DerivationWithoutFinalClosure,
            ArenaState::FinalV2SealedIndexPending => Self::FinalClosureAwaitingProjection,
            ArenaState::FinalV2SealedIndexed => Self::Indexed,
            ArenaState::FailedIndeterminate => Self::ProtectedFailure,
            ArenaState::ExpiredUnlaunched => Self::ExpiredUnlaunched,
        }
    }
}

/// Exact relationship between one physical arena and the immutable runtime
/// ledger's custody-reservation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedCustodyReservationLedgerBinding {
    Exact,
    NoCommittedReservation,
    ReservationDigestMismatch {
        ledger_digest: Sha256Digest,
        arena_digest: Sha256Digest,
    },
}

/// Verified physical state of one durable governed-custody arena.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCustodyInspection {
    pub relative_path: PathBuf,
    pub reservation_record_id: Sha256Digest,
    pub reservation_manifest_digest: Sha256Digest,
    pub reservation_ledger_binding: GovernedCustodyReservationLedgerBinding,
    pub outer_request_record_id: Sha256Digest,
    pub outer_request_id: String,
    pub dependency_generation_id: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub state: GovernedCustodyState,
    pub recovery_class: GovernedCustodyRecoveryClass,
    pub arena_sequence: u64,
    pub execution_launch_record_id: Option<Sha256Digest>,
    pub final_closure: Option<GovernedCustodyCommitment>,
    pub protected_failure: Option<GovernedCustodyCommitment>,
    pub recovered_torn_superblock: bool,
}

/// One entry discovered in the database-owned custody directory.
///
/// Unreadable entries remain visible. They are not silently dropped and do
/// not become a diagnostic conclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedCustodyInventoryEntry {
    Verified(Box<GovernedCustodyInspection>),
    MissingForCommittedReservation {
        reservation_record_id: Sha256Digest,
        reservation_manifest_digest: Sha256Digest,
    },
    Unreadable {
        relative_path: PathBuf,
        reason: String,
    },
}

/// Exact protected-failure bytes from one terminal custody arena.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProtectedFailure {
    pub reservation_record_id: Sha256Digest,
    pub bytes_digest: Sha256Digest,
    pub exact_bytes: Vec<u8>,
}

/// Orthogonal arena/failure availability for one protected-failure read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedProtectedFailureAccess {
    ArenaMissing,
    NotPresent { arena_state: GovernedCustodyState },
    VerifiedAvailable(GovernedProtectedFailure),
}

/// Result of comparing one sealed governed closure with the store's exact
/// committed SQL projection.
///
/// This is a storage-correspondence result only. It does not establish that
/// NQ core produced a semantically valid diagnostic, that a consumer may rely
/// on it, or that any action is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProjectionVerification {
    pub reservation_record_id: Sha256Digest,
    pub closure_id: Sha256Digest,
    pub diagnostic_artifact_id: Sha256Digest,
    pub runtime_checkpoint_id: Sha256Digest,
    pub disposition: GovernedProjectionVerificationDisposition,
}

/// Whether exact projection verification advanced the physical frontier or
/// idempotently reverified an already-indexed frontier.
///
/// Neither disposition assigns provider, diagnostic, reliance, or authority
/// semantics. Public callers can assemble matching storage projections; native
/// semantic correspondence remains an independent NQ-core obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedProjectionVerificationDisposition {
    Indexed,
    AlreadyIndexed,
}

/// Exact opaque provider occurrence bytes reopened from durable custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodiedAcquisition {
    pub execution_launch_record_id: Sha256Digest,
    pub provider_intake_record_id: Sha256Digest,
    pub exact_provider_intake_bytes: Vec<u8>,
    pub exact_raw_provider_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ExactRuntimeRecordReference {
    schema: String,
    record_id: Sha256Digest,
    bytes_digest: Sha256Digest,
}

impl ExactRuntimeRecordReference {
    fn matches(&self, record: &RuntimeRecordRow) -> bool {
        self.schema == record.record_schema
            && self.record_id.as_str() == record.record_id
            && self.bytes_digest == record.canonical_bytes_sha256
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionAcquisition {
    execution_launch_record_id: Sha256Digest,
    provider_intake: ExactRuntimeRecordReference,
    intake_id: String,
    raw_provider_bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionLocalOrigin {
    run_id: String,
    evaluation_id: Option<String>,
    completed_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionCheckpoint {
    checkpoint_id: Sha256Digest,
    batch_digest: Sha256Digest,
    runtime_records: Vec<ExactRuntimeRecordReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionPrelaunch {
    outer_request: ExactRuntimeRecordReference,
    invocation_decision: ExactRuntimeRecordReference,
    reservation_checkpoint: GovernedProjectionCheckpoint,
    launch_checkpoint: GovernedProjectionCheckpoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionDerivation {
    derivation_id: Sha256Digest,
    dependency_generation_id: Sha256Digest,
    dependency_generation_custody_digest: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    evaluation_id: Option<String>,
    profile_semantic_id: Sha256Digest,
    evaluator_artifact_digest: Sha256Digest,
    derived_at: String,
    clock_identity: Sha256Digest,
    clock_uncertainty_ms: u64,
}

impl GovernedProjectionDerivation {
    fn matches(&self, claim: &DerivationClaim) -> bool {
        self.derivation_id == claim.derivation_id
            && self.dependency_generation_id == claim.dependency_generation_id
            && self.dependency_generation_custody_digest
                == claim.dependency_generation_custody_digest
            && self.trust_anchor_id == claim.trust_anchor_id
            && self.evaluation_id == claim.evaluation_id
            && self.profile_semantic_id == claim.profile_semantic_id
            && self.evaluator_artifact_digest == claim.evaluator_artifact_digest
            && self.derived_at == claim.derived_at
            && self.clock_identity == claim.clock_identity
            && self.clock_uncertainty_ms == claim.clock_uncertainty_ms
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionDependencyGeneration {
    checkpoint_id: Sha256Digest,
    checkpoint_digest: Sha256Digest,
    generation_id: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    custody_bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionClosure {
    schema: String,
    closure_id: Sha256Digest,
    reservation: ExactRuntimeRecordReference,
    prelaunch: GovernedProjectionPrelaunch,
    acquisition: GovernedProjectionAcquisition,
    derivation: GovernedProjectionDerivation,
    diagnostic: Value,
    local_origin: GovernedProjectionLocalOrigin,
    execution_binding: ExactRuntimeRecordReference,
    runtime_records: Vec<ExactRuntimeRecordReference>,
    dependency_generation: GovernedProjectionDependencyGeneration,
}

impl From<&AcquisitionCarrier> for CustodiedAcquisition {
    fn from(value: &AcquisitionCarrier) -> Self {
        Self {
            execution_launch_record_id: value.execution_launch_record_id.clone(),
            provider_intake_record_id: value.provider_intake_record_id.clone(),
            exact_provider_intake_bytes: value.exact_provider_intake_bytes.clone(),
            exact_raw_provider_bytes: value.exact_raw_provider_bytes.clone(),
        }
    }
}

/// Exact opaque acquisition bytes supplied only after the real provider
/// occurrence has completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedAcquisitionCustodyInput {
    pub execution_launch_record_id: Sha256Digest,
    pub provider_intake_record_id: Sha256Digest,
    pub exact_provider_intake_bytes: Vec<u8>,
    pub exact_raw_provider_bytes: Vec<u8>,
}

/// Durable derivation occurrence metadata.
///
/// The store checks only identity continuity with the prelaunch generation.
/// It does not establish that an evaluator ran or that any result is valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedDerivationCustodyClaim {
    pub derivation_id: Sha256Digest,
    pub dependency_generation_id: Sha256Digest,
    pub dependency_generation_custody_digest: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub evaluation_id: Option<String>,
    pub profile_semantic_id: Sha256Digest,
    pub evaluator_artifact_digest: Sha256Digest,
    pub derived_at: String,
    pub clock_identity: Sha256Digest,
    pub clock_uncertainty_ms: u64,
}

impl From<GovernedDerivationCustodyClaim> for DerivationClaim {
    fn from(value: GovernedDerivationCustodyClaim) -> Self {
        Self {
            derivation_id: value.derivation_id,
            dependency_generation_id: value.dependency_generation_id,
            dependency_generation_custody_digest: value.dependency_generation_custody_digest,
            trust_anchor_id: value.trust_anchor_id,
            evaluation_id: value.evaluation_id,
            profile_semantic_id: value.profile_semantic_id,
            evaluator_artifact_digest: value.evaluator_artifact_digest,
            derived_at: value.derived_at,
            clock_identity: value.clock_identity,
            clock_uncertainty_ms: value.clock_uncertainty_ms,
        }
    }
}

/// Digest and byte length of one durably sealed arena section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCustodyCommitment {
    pub bytes_digest: Sha256Digest,
    pub byte_length: u64,
}

/// Lifetime-locked exact-byte custody handle.
///
/// The handle intentionally has no provider-launch, evaluator, execution
/// binding, or authority API.
pub struct GovernedCustody {
    database_path: PathBuf,
    reservation: GovernedCustodyReservation,
    arena: CustodyArena,
}

impl GovernedCustody {
    pub(crate) fn reserve(
        database_path: &Path,
        reservation: GovernedCustodyReservation,
        exact_dependency_closure_bytes: &[u8],
    ) -> Result<Self, StoreError> {
        let arena = CustodyArena::create(
            database_path,
            reservation.prelaunch(),
            reservation.layout()?,
            exact_dependency_closure_bytes,
        )
        .map_err(custody_error)?;
        Ok(Self {
            database_path: database_path.to_path_buf(),
            reservation,
            arena,
        })
    }

    pub(crate) fn open(
        database_path: &Path,
        reservation: GovernedCustodyReservation,
    ) -> Result<Self, StoreError> {
        let arena =
            CustodyArena::open(database_path, &reservation.prelaunch()).map_err(custody_error)?;
        let observed = arena.inspection().map_err(custody_error)?;
        if observed.layout != reservation.layout()? {
            return Err(StoreError::Invariant(
                "governed custody layout differs from its exact reservation".into(),
            ));
        }
        Ok(Self {
            database_path: database_path.to_path_buf(),
            reservation,
            arena,
        })
    }

    /// Return the exact reservation used to open this handle.
    #[must_use]
    pub const fn reservation(&self) -> &GovernedCustodyReservation {
        &self.reservation
    }

    /// Return the current durable custody state.
    pub fn state(&self) -> Result<GovernedCustodyState, StoreError> {
        Ok(self.arena.inspection().map_err(custody_error)?.state.into())
    }

    /// Return the digest-derived arena path relative to the database-owned
    /// custody root.
    pub fn relative_path(&self) -> Result<PathBuf, StoreError> {
        self.arena
            .relative_path_from(&self.database_path)
            .map_err(custody_error)
    }

    /// Durably claim one exact launch identity.
    pub fn claim_launch(
        &mut self,
        execution_launch_record_id: Sha256Digest,
        claimed_at: String,
    ) -> Result<(), StoreError> {
        self.arena
            .claim(execution_launch_record_id, claimed_at)
            .map_err(custody_error)
    }

    /// Seal and immediately reopen exact opaque provider-intake and raw bytes.
    pub fn seal_acquisition(
        &mut self,
        input: GovernedAcquisitionCustodyInput,
    ) -> Result<CustodiedAcquisition, StoreError> {
        let token = self
            .arena
            .seal_acquisition(AcquisitionCarrier {
                execution_launch_record_id: input.execution_launch_record_id,
                provider_intake_record_id: input.provider_intake_record_id,
                exact_provider_intake_bytes: input.exact_provider_intake_bytes,
                exact_raw_provider_bytes: input.exact_raw_provider_bytes,
            })
            .map_err(custody_error)?;
        Ok(CustodiedAcquisition::from(token.carrier()))
    }

    /// Reopen the exact opaque acquisition carrier without refreshing it.
    pub fn acquisition(&self) -> Result<CustodiedAcquisition, StoreError> {
        let token = self.arena.reopen_raw_token().map_err(custody_error)?;
        Ok(CustodiedAcquisition::from(token.carrier()))
    }

    /// Reopen the exact authenticated dependency-generation closure pinned
    /// before launch.
    pub fn dependency_closure_bytes(&self) -> Result<Vec<u8>, StoreError> {
        self.arena.dependency_closure_bytes().map_err(custody_error)
    }

    /// Durably claim that core has completed one derivation over the reopened
    /// acquisition. This operation assigns no semantic standing itself.
    pub fn claim_derivation(
        &mut self,
        claim: GovernedDerivationCustodyClaim,
    ) -> Result<(), StoreError> {
        let raw = self.arena.reopen_raw_token().map_err(custody_error)?;
        self.arena
            .claim_derivation(raw, claim.into())
            .map(|_| ())
            .map_err(custody_error)
    }

    /// Seal exact bytes of a core-validated complete closure.
    ///
    /// The store validates only the internal carrier's canonical top-level
    /// schema and self-identity. It does not validate nested NQ semantics.
    pub fn seal_final_closure(
        &mut self,
        exact_closure_bytes: Vec<u8>,
    ) -> Result<GovernedCustodyCommitment, StoreError> {
        let derivation = self
            .arena
            .reopen_derivation_token()
            .map_err(custody_error)?;
        let candidate = DerivedV2ClosureCandidate::from_store_internal_precursor(
            derivation,
            exact_closure_bytes,
        )
        .map_err(custody_error)?;
        let token = self
            .arena
            .seal_final_v2_closure(candidate)
            .map_err(custody_error)?;
        let bytes = self
            .arena
            .final_v2_closure_bytes()
            .map_err(custody_error)?
            .ok_or_else(|| {
                StoreError::Invariant("sealed final custody closure is unavailable".into())
            })?;
        let inspection = self.arena.inspection().map_err(custody_error)?;
        let section = inspection.final_v2_closure.ok_or_else(|| {
            StoreError::Invariant("sealed final custody commitment is absent".into())
        })?;
        // Retain token ownership inside the durable state transition. Indexing
        // must reopen and verify the final section independently.
        drop(token);
        debug_assert_eq!(
            nq_protocol::sha256_bytes(&bytes),
            section.payload_digest().clone()
        );
        Ok(GovernedCustodyCommitment {
            bytes_digest: section.payload_digest().clone(),
            byte_length: section.payload_length(),
        })
    }

    /// Return exact final-closure carrier bytes, if committed.
    pub fn final_closure_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.arena.final_v2_closure_bytes().map_err(custody_error)
    }

    /// Return exact protected-failure bytes without interpreting them as a
    /// diagnostic outcome.
    pub fn protected_failure_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.arena.protected_failure_bytes().map_err(custody_error)
    }
}

impl Store {
    /// Physically reserve exact-byte custody before any provider launch.
    pub fn reserve_governed_custody(
        &self,
        reservation: GovernedCustodyReservation,
        exact_dependency_closure_bytes: &[u8],
    ) -> Result<GovernedCustody, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed custody requires a filesystem-backed initialized store".into(),
            )
        })?;
        GovernedCustody::reserve(database_path, reservation, exact_dependency_closure_bytes)
    }

    /// Reopen and verify one exact governed custody reservation.
    pub fn open_governed_custody(
        &self,
        reservation: GovernedCustodyReservation,
    ) -> Result<GovernedCustody, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed custody requires a filesystem-backed initialized store".into(),
            )
        })?;
        GovernedCustody::open(database_path, reservation)
    }

    /// Inspect every physical governed-custody frontier owned by this store.
    ///
    /// This is the startup/recovery read surface. It reports exact durable
    /// states and corrupt entries without resuming work, minting failure
    /// carriers, or assigning diagnostic standing.
    #[allow(clippy::too_many_lines)] // One closed reconciliation keeps omissions visible.
    pub fn governed_custody_inventory(
        &self,
    ) -> Result<Vec<GovernedCustodyInventoryEntry>, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed custody inventory requires a filesystem-backed initialized store".into(),
            )
        })?;
        let mut expected_reservations = self
            .connection
            .prepare(
                "SELECT record_id, canonical_bytes_sha256
                 FROM runtime_record_ledger
                 WHERE record_schema = 'nq.custody_reservation.v1'
                 ORDER BY record_id",
            )?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(record_id, digest)| {
                Ok((
                    Sha256Digest::parse(record_id).map_err(|error| {
                        StoreError::Integrity(format!(
                            "custody-reservation ledger identity is invalid: {error}"
                        ))
                    })?,
                    Sha256Digest::parse(digest).map_err(|error| {
                        StoreError::Integrity(format!(
                            "custody-reservation ledger digest is invalid: {error}"
                        ))
                    })?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
        let physical = CustodyArena::inventory(
            database_path,
            usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000),
        )
        .map_err(custody_error)?;
        let mut inventory =
            Vec::with_capacity(physical.len().saturating_add(expected_reservations.len()));
        for entry in physical {
            inventory.push(match entry {
                ArenaInventoryEntry::Verified {
                    relative_path,
                    inspection,
                } => {
                    let reservation_ledger_binding =
                        match expected_reservations.remove(&inspection.reservation_id) {
                            None => GovernedCustodyReservationLedgerBinding::NoCommittedReservation,
                            Some(ledger_digest)
                                if ledger_digest
                                    == inspection.prelaunch.reservation_manifest_digest =>
                            {
                                GovernedCustodyReservationLedgerBinding::Exact
                            }
                            Some(ledger_digest) => {
                                GovernedCustodyReservationLedgerBinding::ReservationDigestMismatch {
                                    ledger_digest,
                                    arena_digest: inspection
                                        .prelaunch
                                        .reservation_manifest_digest
                                        .clone(),
                                }
                            }
                        };
                    GovernedCustodyInventoryEntry::Verified(Box::new(GovernedCustodyInspection {
                        relative_path,
                        reservation_record_id: inspection.reservation_id,
                        reservation_manifest_digest: inspection
                            .prelaunch
                            .reservation_manifest_digest,
                        reservation_ledger_binding,
                        outer_request_record_id: inspection.prelaunch.outer_request_record_id,
                        outer_request_id: inspection.prelaunch.outer_request_id,
                        dependency_generation_id: inspection.prelaunch.dependency_generation_id,
                        trust_anchor_id: inspection.prelaunch.trust_anchor_id,
                        state: inspection.state.into(),
                        recovery_class: inspection.state.into(),
                        arena_sequence: inspection.sequence,
                        execution_launch_record_id: inspection.execution_launch_record_id,
                        final_closure: inspection.final_v2_closure.map(|section| {
                            GovernedCustodyCommitment {
                                bytes_digest: section.payload_digest().clone(),
                                byte_length: section.payload_length(),
                            }
                        }),
                        protected_failure: inspection.protected_failure.map(|section| {
                            GovernedCustodyCommitment {
                                bytes_digest: section.payload_digest().clone(),
                                byte_length: section.payload_length(),
                            }
                        }),
                        recovered_torn_superblock: inspection.recovered_torn_superblock,
                    }))
                }
                ArenaInventoryEntry::Unreadable {
                    relative_path,
                    reason,
                } => GovernedCustodyInventoryEntry::Unreadable {
                    relative_path,
                    reason,
                },
            });
        }
        inventory.extend(expected_reservations.into_iter().map(
            |(reservation_record_id, reservation_manifest_digest)| {
                GovernedCustodyInventoryEntry::MissingForCommittedReservation {
                    reservation_record_id,
                    reservation_manifest_digest,
                }
            },
        ));
        if inventory.len() > usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000) {
            return Err(StoreError::Invariant(format!(
                "combined custody inventory exceeds {MAX_PUBLIC_QUERY_ROWS} entries"
            )));
        }
        Ok(inventory)
    }

    /// Read one exact protected-failure carrier by its reservation identity.
    ///
    /// A missing arena, a verified arena without a failure, and verified
    /// protected-failure bytes remain distinct. Corrupt or unreadable custody
    /// refuses instead of being represented as absence.
    pub fn governed_protected_failure(
        &self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProtectedFailureAccess, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "protected-failure retrieval requires a filesystem-backed initialized store".into(),
            )
        })?;
        let Some(arena) = CustodyArena::open_by_reservation(database_path, reservation_record_id)
            .map_err(custody_error)?
        else {
            return Ok(GovernedProtectedFailureAccess::ArenaMissing);
        };
        let state: GovernedCustodyState = arena.inspection().map_err(custody_error)?.state.into();
        let Some(exact_bytes) = arena.protected_failure_bytes().map_err(custody_error)? else {
            return Ok(GovernedProtectedFailureAccess::NotPresent { arena_state: state });
        };
        Ok(GovernedProtectedFailureAccess::VerifiedAvailable(
            GovernedProtectedFailure {
                reservation_record_id: reservation_record_id.clone(),
                bytes_digest: nq_protocol::sha256_bytes(&exact_bytes),
                exact_bytes,
            },
        ))
    }

    /// Verify that one sealed physical closure corresponds exactly to the
    /// already-committed SQL artifact, local origin, execution binding,
    /// provider occurrence, runtime-record batch, and dependency generation,
    /// then durably mark the arena indexed.
    ///
    /// The reservation identity is the only caller input. All verdict-shaped
    /// bytes and row identities are reopened from store-owned custody. A
    /// missing or mismatching projection leaves an index-pending arena
    /// unchanged. Repeating the operation on an indexed arena rechecks the
    /// complete correspondence instead of trusting the prior state bit.
    ///
    /// This method proves storage correspondence only. NQ core remains
    /// responsible for native provider, evaluator, profile, and diagnostic
    /// semantic validation before sealing the closure.
    #[allow(clippy::too_many_lines)] // One closed comparison keeps omissions auditable.
    pub fn verify_governed_projection_and_mark_indexed(
        &self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProjectionVerification, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "projection verification requires a filesystem-backed initialized store",
            )
        })?;
        let mut arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "physical custody arena is absent")
            })?;
        let inspection = arena.inspection().map_err(custody_error)?;
        if inspection.reservation_id != *reservation_record_id {
            return Err(projection_integrity(
                reservation_record_id,
                "arena reservation identity differs",
            ));
        }
        let disposition = match inspection.state {
            ArenaState::FinalV2SealedIndexPending => {
                GovernedProjectionVerificationDisposition::Indexed
            }
            ArenaState::FinalV2SealedIndexed => {
                GovernedProjectionVerificationDisposition::AlreadyIndexed
            }
            state => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!("arena state {state:?} has no final projection to verify"),
                ));
            }
        };
        let exact_closure_bytes = arena
            .final_v2_closure_bytes()
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "final closure bytes are absent")
            })?;
        let closure: GovernedProjectionClosure = serde_json::from_slice(&exact_closure_bytes)
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("final closure shape is incompatible: {error}"),
                )
            })?;
        if closure.schema != GOVERNED_CUSTODY_CLOSURE_SCHEMA {
            return Err(projection_integrity(
                reservation_record_id,
                "final closure schema differs",
            ));
        }

        // One SQLite read transaction gives every row comparison below one
        // immutable projection snapshot. The arena sections are themselves
        // sealed and immutable at these frontiers.
        let snapshot = self.connection.unchecked_transaction()?;
        validate_runtime_record_ledger(&snapshot)?;
        validate_provider_intake_invariants(&snapshot)?;
        validate_diagnostic_artifact_invariants(&snapshot)?;

        let reservation_record = exact_runtime_record(
            &snapshot,
            reservation_record_id,
            &closure.reservation,
            "custody reservation",
        )?;
        if closure.reservation.schema != "nq.custody_reservation.v1"
            || closure.reservation.record_id != *reservation_record_id
            || closure.reservation.bytes_digest != inspection.prelaunch.reservation_manifest_digest
            || reservation_record.checkpoint_id
                != inspection.prelaunch.prelaunch_checkpoint_id.as_str()
        {
            return Err(projection_integrity(
                reservation_record_id,
                "reservation reference differs from the arena prelaunch binding",
            ));
        }
        let outer_request_record = exact_runtime_record(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.outer_request,
            "outer request",
        )?;
        let invocation_decision_record = exact_runtime_record(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.invocation_decision,
            "accepted invocation decision",
        )?;
        let (reservation_checkpoint, reservation_checkpoint_records) = exact_checkpoint(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.reservation_checkpoint,
            "reservation",
        )?;
        if reservation_checkpoint.checkpoint_id
            != inspection.prelaunch.prelaunch_checkpoint_id.as_str()
            || reservation_checkpoint.batch_digest
                != inspection.prelaunch.prelaunch_checkpoint_digest
            || reservation_record.checkpoint_id != reservation_checkpoint.checkpoint_id
            || closure.prelaunch.outer_request.record_id
                != inspection.prelaunch.outer_request_record_id
            || closure.prelaunch.outer_request.bytes_digest
                != inspection.prelaunch.outer_request_digest
        {
            return Err(projection_integrity(
                reservation_record_id,
                "reservation checkpoint identity, digest, or arena binding differs",
            ));
        }
        if reservation_checkpoint_records.len() != 3
            || !reservation_checkpoint_records
                .iter()
                .any(|record| record == &outer_request_record)
            || !reservation_checkpoint_records
                .iter()
                .any(|record| record == &invocation_decision_record)
            || !reservation_checkpoint_records
                .iter()
                .any(|record| record == &reservation_record)
            || outer_request_record.record_schema != "nq.diagnostic_invocation_request.v1"
            || invocation_decision_record.record_schema != "nq.invocation_decision.v1"
            || reservation_record.record_schema != "nq.custody_reservation.v1"
            || exact_json_string(
                reservation_record_id,
                &invocation_decision_record,
                "decision",
            )?
            .as_deref()
                != Some("accepted")
        {
            return Err(projection_integrity(
                reservation_record_id,
                "reservation checkpoint membership or accepted-decision state differs",
            ));
        }

        let (launch_checkpoint, launch_checkpoint_records) = exact_checkpoint(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.launch_checkpoint,
            "launch",
        )?;
        let [launch_record] = launch_checkpoint_records.as_slice() else {
            return Err(projection_integrity(
                reservation_record_id,
                "launch checkpoint does not contain exactly one execution launch",
            ));
        };
        if launch_record.record_schema != "nq.execution_launch.v1"
            || launch_record.record_id
                != inspection
                    .execution_launch_record_id
                    .as_ref()
                    .map(Sha256Digest::as_str)
                    .unwrap_or_default()
            || launch_record.record_id != closure.acquisition.execution_launch_record_id.as_str()
            || launch_checkpoint.predecessor_checkpoint_id.as_deref()
                != Some(reservation_checkpoint.checkpoint_id.as_str())
            || inspection.claimed_at.as_deref()
                != exact_json_string(reservation_record_id, launch_record, "launched_at")?
                    .as_deref()
        {
            return Err(projection_integrity(
                reservation_record_id,
                "launch checkpoint membership, predecessor, or physical claim time differs",
            ));
        }
        let physical_derivation = inspection.derivation_claim.as_ref().ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "final physical frontier has no derivation claim",
            )
        })?;
        if !closure.derivation.matches(physical_derivation)
            || closure.derivation.dependency_generation_id
                != closure.dependency_generation.generation_id
            || closure.derivation.dependency_generation_custody_digest
                != closure.dependency_generation.custody_bytes_digest
            || closure.derivation.trust_anchor_id != closure.dependency_generation.trust_anchor_id
            || closure.derivation.evaluation_id != closure.local_origin.evaluation_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "sealed derivation differs from the complete physical claim or local origin",
            ));
        }

        let exact_diagnostic_bytes =
            canonical_json_bytes(&closure.diagnostic).map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("embedded diagnostic cannot be canonicalized: {error}"),
                )
            })?;
        let diagnostic_schema = closure
            .diagnostic
            .get("schema")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "embedded diagnostic schema is absent",
                )
            })?;
        if diagnostic_schema != "nq.diagnostic_execution.v2" {
            return Err(projection_integrity(
                reservation_record_id,
                "only the production V2 diagnostic contract may be indexed",
            ));
        }
        if closure
            .diagnostic
            .pointer("/profile_semantic_id")
            .and_then(Value::as_str)
            != Some(closure.derivation.profile_semantic_id.as_str())
            || closure
                .diagnostic
                .pointer("/evaluator/digest")
                .and_then(Value::as_str)
                != Some(closure.derivation.evaluator_artifact_digest.as_str())
            || closure
                .diagnostic
                .pointer("/completed_at")
                .and_then(Value::as_str)
                != Some(closure.derivation.derived_at.as_str())
            || closure.local_origin.completed_at != closure.derivation.derived_at
            || closure
                .diagnostic
                .pointer("/execution_clock/digest")
                .and_then(Value::as_str)
                != Some(closure.derivation.clock_identity.as_str())
        {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic profile, evaluator, derivation time, or clock differs from custody",
            ));
        }
        if closure
            .diagnostic
            .pointer("/attempt_interval/qualification/state")
            .and_then(Value::as_str)
            == Some("bounded")
            && closure
                .diagnostic
                .pointer("/attempt_interval/qualification/maximum_error_ms")
                .and_then(Value::as_u64)
                != Some(closure.derivation.clock_uncertainty_ms)
        {
            return Err(projection_integrity(
                reservation_record_id,
                "bounded diagnostic clock uncertainty differs from custody",
            ));
        }
        let diagnostic_artifact_id = Sha256Digest::parse(
            closure
                .diagnostic
                .get("artifact_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    projection_integrity(
                        reservation_record_id,
                        "embedded diagnostic artifact identity is absent",
                    )
                })?
                .to_owned(),
        )
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("embedded diagnostic identity is invalid: {error}"),
            )
        })?;
        let DiagnosticArtifactLookup::Found(artifact) = diagnostic_artifact_on_connection(
            &snapshot,
            &diagnostic_artifact_id,
            &[diagnostic_schema],
        )?
        else {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic artifact SQL commitment is absent",
            ));
        };
        let DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes } =
            &artifact.byte_state
        else {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic artifact bytes are unavailable or corrupt",
            ));
        };
        if canonical_bytes.as_bytes() != exact_diagnostic_bytes
            || artifact.commitment.contract_schema != diagnostic_schema
        {
            return Err(projection_integrity(
                reservation_record_id,
                "embedded diagnostic differs from its exact SQL commitment",
            ));
        }
        match &artifact.commitment.origin {
            DiagnosticArtifactOrigin::Local {
                run_id,
                evaluation_id,
                completed_at,
                execution_binding_record_id,
            } if run_id == &closure.local_origin.run_id
                && evaluation_id == &closure.local_origin.evaluation_id
                && completed_at == &closure.local_origin.completed_at
                && execution_binding_record_id.as_deref()
                    == Some(closure.execution_binding.record_id.as_str()) => {}
            _ => {
                return Err(projection_integrity(
                    reservation_record_id,
                    "diagnostic local origin differs from the sealed closure",
                ));
            }
        }

        let binding = diagnostic_artifact_execution_binding_on_connection(
            &snapshot,
            &diagnostic_artifact_id,
        )?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "diagnostic execution binding is absent",
            )
        })?;
        if !closure
            .execution_binding
            .matches(&binding.execution_binding)
            || closure.execution_binding.schema != "nq.execution_identity_binding.v2"
        {
            return Err(projection_integrity(
                reservation_record_id,
                "execution binding reference differs from SQL",
            ));
        }
        if binding.outer_request != outer_request_record
            || binding.invocation_decision != invocation_decision_record
            || binding.execution_launch != *launch_record
            || binding.outer_request.record_id
                != inspection.prelaunch.outer_request_record_id.as_str()
            || binding.outer_request_id != inspection.prelaunch.outer_request_id
            || closure.acquisition.execution_launch_record_id.as_str()
                != binding.execution_launch.record_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "request or launch binding differs from the physical arena",
            ));
        }
        let [(provider_record, provider_attempt)] = binding.provider_attempts.as_slice() else {
            return Err(projection_integrity(
                reservation_record_id,
                "one physical acquisition requires exactly one SQL provider attempt",
            ));
        };
        if !closure.acquisition.provider_intake.matches(provider_record)
            || closure.acquisition.provider_intake.schema != "nq.provider_intake.v1"
            || closure.acquisition.intake_id != provider_attempt.intake_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "provider-attempt binding differs from the sealed closure",
            ));
        }
        let acquisition = arena.acquisition_for_projection().map_err(custody_error)?;
        if acquisition.execution_launch_record_id != closure.acquisition.execution_launch_record_id
            || acquisition.provider_intake_record_id
                != closure.acquisition.provider_intake.record_id
            || acquisition.exact_provider_intake_bytes != provider_record.canonical_bytes.as_bytes()
        {
            return Err(projection_integrity(
                reservation_record_id,
                "physical provider-intake carrier differs from SQL",
            ));
        }
        let provider_projection = snapshot
            .query_row(
                "SELECT intake_digest, raw_sha256, profile_semantic_id,
                        evaluator_artifact_digest, raw_bytes
                 FROM provider_intake_attempts WHERE intake_id = ?1",
                [&closure.acquisition.intake_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "provider intake SQL row is absent")
            })?;
        let (
            provider_intake_digest,
            provider_raw_digest,
            provider_profile_semantic_id,
            provider_evaluator_artifact_digest,
            raw_provider_bytes,
        ) = provider_projection;
        if provider_intake_digest != provider_record.record_id
            || provider_raw_digest != closure.acquisition.raw_provider_bytes_digest.as_str()
            || provider_profile_semantic_id != closure.derivation.profile_semantic_id.as_str()
            || provider_evaluator_artifact_digest
                != closure.derivation.evaluator_artifact_digest.as_str()
            || sha256_bytes(&raw_provider_bytes) != closure.acquisition.raw_provider_bytes_digest
            || raw_provider_bytes != acquisition.exact_raw_provider_bytes
        {
            return Err(projection_integrity(
                reservation_record_id,
                "physical raw acquisition differs from the SQL provider occurrence",
            ));
        }

        let checkpoint_id = Sha256Digest::parse(binding.execution_binding.checkpoint_id.clone())
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("projection checkpoint identity is invalid: {error}"),
                )
            })?;
        if checkpoint_id != closure.dependency_generation.checkpoint_id {
            return Err(projection_integrity(
                reservation_record_id,
                "closure dependency checkpoint differs from the binding batch",
            ));
        }
        let checkpoint = runtime_checkpoint_by_id_on_connection(&snapshot, checkpoint_id.as_str())?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "projection checkpoint is absent")
            })?;
        let checkpoint_records =
            checkpoint_runtime_records(&snapshot, reservation_record_id, &checkpoint)?;
        if checkpoint.batch_digest != closure.dependency_generation.checkpoint_digest
            || checkpoint.record_count
                != u64::try_from(checkpoint_records.len()).map_err(|_| {
                    projection_integrity(
                        reservation_record_id,
                        "projection checkpoint record count overflowed",
                    )
                })?
            || closure.runtime_records.len() != checkpoint_records.len()
            || closure
                .runtime_records
                .iter()
                .zip(&checkpoint_records)
                .any(|(reference, record)| !reference.matches(record))
            || !checkpoint_records
                .iter()
                .any(|record| record.record_id == binding.execution_binding.record_id)
            || !checkpoint_records
                .iter()
                .any(|record| record.record_id == provider_record.record_id)
        {
            return Err(projection_integrity(
                reservation_record_id,
                "sealed runtime-record write set differs from the exact SQL checkpoint",
            ));
        }

        let dependency_bytes = arena.dependency_closure_bytes().map_err(custody_error)?;
        if sha256_bytes(&dependency_bytes) != closure.dependency_generation.custody_bytes_digest
            || closure.dependency_generation.generation_id
                != inspection.prelaunch.dependency_generation_id
            || closure.dependency_generation.trust_anchor_id != inspection.prelaunch.trust_anchor_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "sealed dependency generation differs from arena prelaunch",
            ));
        }
        verify_checkpoint_dependency(
            &snapshot,
            reservation_record_id,
            &reservation_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )?;
        verify_checkpoint_dependency(
            &snapshot,
            reservation_record_id,
            &launch_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )?;
        verify_checkpoint_dependency(
            &snapshot,
            reservation_record_id,
            &checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )?;
        drop(snapshot);

        if disposition == GovernedProjectionVerificationDisposition::Indexed {
            let token = arena.reopen_final_token().map_err(custody_error)?;
            arena.mark_indexed(token).map_err(custody_error)?;
            drop(arena);
            let reopened = CustodyArena::open_by_reservation(database_path, reservation_record_id)
                .map_err(custody_error)?
                .ok_or_else(|| {
                    projection_integrity(
                        reservation_record_id,
                        "indexed arena disappeared during durable reopen",
                    )
                })?;
            let reopened_inspection = reopened.inspection().map_err(custody_error)?;
            if reopened_inspection.state != ArenaState::FinalV2SealedIndexed
                || reopened
                    .final_v2_closure_bytes()
                    .map_err(custody_error)?
                    .as_deref()
                    != Some(exact_closure_bytes.as_slice())
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "indexed transition did not durably preserve the exact closure",
                ));
            }
        }

        Ok(GovernedProjectionVerification {
            reservation_record_id: reservation_record_id.clone(),
            closure_id: closure.closure_id,
            diagnostic_artifact_id,
            runtime_checkpoint_id: checkpoint_id,
            disposition,
        })
    }
}

fn exact_checkpoint(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    expected: &GovernedProjectionCheckpoint,
    label: &str,
) -> Result<(RuntimeLedgerCheckpoint, Vec<RuntimeRecordRow>), StoreError> {
    let checkpoint =
        runtime_checkpoint_by_id_on_connection(connection, expected.checkpoint_id.as_str())?
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    format!("{label} checkpoint is absent"),
                )
            })?;
    if checkpoint.batch_digest != expected.batch_digest {
        return Err(projection_integrity(
            reservation_record_id,
            format!("{label} checkpoint digest differs from its sealed reference"),
        ));
    }
    let records = checkpoint_runtime_records(connection, reservation_record_id, &checkpoint)?;
    if checkpoint.record_count
        != u64::try_from(records.len()).map_err(|_| {
            projection_integrity(
                reservation_record_id,
                format!("{label} checkpoint record count overflowed"),
            )
        })?
        || expected.runtime_records.len() != records.len()
        || expected
            .runtime_records
            .iter()
            .zip(&records)
            .any(|(reference, record)| !reference.matches(record))
    {
        return Err(projection_integrity(
            reservation_record_id,
            format!("{label} checkpoint membership differs from its sealed reference"),
        ));
    }
    Ok((checkpoint, records))
}

fn checkpoint_runtime_records(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    checkpoint: &RuntimeLedgerCheckpoint,
) -> Result<Vec<RuntimeRecordRow>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT record_id FROM runtime_record_ledger
         WHERE checkpoint_id = ?1 ORDER BY record_sequence",
    )?;
    statement
        .query_map([&checkpoint.checkpoint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|record_id| {
            runtime_record_by_id_on_connection(connection, &record_id)?.ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    format!(
                        "checkpoint {} lost runtime record {record_id}",
                        checkpoint.checkpoint_id
                    ),
                )
            })
        })
        .collect()
}

fn exact_json_string(
    reservation_record_id: &Sha256Digest,
    record: &RuntimeRecordRow,
    field: &str,
) -> Result<Option<String>, StoreError> {
    let value: Value =
        serde_json::from_slice(record.canonical_bytes.as_bytes()).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!(
                    "runtime record {} cannot be decoded: {error}",
                    record.record_id
                ),
            )
        })?;
    Ok(value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

fn exact_runtime_record(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    reference: &ExactRuntimeRecordReference,
    label: &str,
) -> Result<RuntimeRecordRow, StoreError> {
    let record = runtime_record_by_id_on_connection(connection, reference.record_id.as_str())?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("{label} runtime record is absent"),
            )
        })?;
    if !reference.matches(&record) {
        return Err(projection_integrity(
            reservation_record_id,
            format!("{label} runtime record differs from its sealed reference"),
        ));
    }
    Ok(record)
}

fn verify_checkpoint_dependency(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    checkpoint_id: &str,
    expected: &GovernedProjectionDependencyGeneration,
    exact_dependency_bytes: &[u8],
) -> Result<(), StoreError> {
    let access = runtime_checkpoint_dependency_on_connection(connection, checkpoint_id)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("checkpoint {checkpoint_id} has no dependency binding"),
            )
        })?;
    let RuntimeCheckpointDependencyBinding::Authenticated {
        dependency_generation_id,
        trust_anchor_id,
        canonical_bytes_sha256,
        ..
    } = access.binding
    else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} has only a legacy dependency binding"),
        ));
    };
    let Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) =
        access.byte_state
    else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} dependency bytes are unavailable or corrupt"),
        ));
    };
    if dependency_generation_id != expected.generation_id
        || trust_anchor_id != expected.trust_anchor_id
        || canonical_bytes_sha256 != expected.custody_bytes_digest
        || canonical_custody.as_bytes() != exact_dependency_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} dependency closure differs"),
        ));
    }
    Ok(())
}

fn projection_integrity(
    reservation_record_id: &Sha256Digest,
    message: impl std::fmt::Display,
) -> StoreError {
    StoreError::Integrity(format!(
        "governed projection {reservation_record_id} failed exact correspondence: {message}"
    ))
}

fn custody_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Invariant(format!("governed exact-byte custody failed: {error}"))
}

#[cfg(test)]
mod tests {
    use nq_protocol::{canonical_json_bytes, semantic_digest, sha256_bytes};
    use serde_json::{Map, Value};
    use tempfile::tempdir;

    use super::*;
    use crate::custody_arena::ArenaFailureCarrierCandidate;

    fn digest(label: &str) -> Sha256Digest {
        sha256_bytes(label.as_bytes())
    }

    fn reservation(dependency_bytes: &[u8]) -> GovernedCustodyReservation {
        GovernedCustodyReservation {
            reservation_record_id: digest("reservation"),
            reservation_manifest_digest: digest("reservation-manifest"),
            outer_request_record_id: digest("outer-request-record"),
            outer_request_id: "outer-request-001".into(),
            outer_request_digest: digest("outer-request"),
            dependency_generation_id: digest("dependency-generation"),
            dependency_generation_custody_digest: sha256_bytes(dependency_bytes),
            trust_anchor_id: digest("trust-anchor"),
            prelaunch_checkpoint_id: digest("prelaunch-checkpoint"),
            prelaunch_checkpoint_digest: digest("prelaunch-checkpoint-bytes"),
            dependency_closure_capacity_bytes: 4_096,
            raw_capacity_bytes: 4_096,
            final_capacity_bytes: 4_096,
            protected_failure_capacity_bytes: 4_096,
        }
    }

    fn protected_failure_bytes(
        reservation: &GovernedCustodyReservation,
        launch: &Sha256Digest,
    ) -> Vec<u8> {
        let mut value = Map::new();
        value.insert(
            "schema".into(),
            Value::String("nq.governed_custody_failure.v1".into()),
        );
        value.insert(
            "reservation_id".into(),
            Value::String(reservation.reservation_record_id.to_string()),
        );
        value.insert(
            "outer_request_id".into(),
            Value::String(reservation.outer_request_id.clone()),
        );
        value.insert("claim_id".into(), Value::String(launch.as_str().to_owned()));
        value.insert(
            "outcome".into(),
            Value::String("indeterminate_write_refusal".into()),
        );
        value.insert(
            "failed_at".into(),
            Value::String("2026-07-29T22:30:00Z".into()),
        );
        let failure_id = semantic_digest(&value).expect("failure identity");
        value.insert("failure_id".into(), Value::String(failure_id.to_string()));
        canonical_json_bytes(&value).expect("failure carrier")
    }

    #[test]
    fn startup_inventory_and_protected_failure_read_preserve_terminal_bytes() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        let store = Store::initialize(&database).expect("store");
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        let exact_failure = protected_failure_bytes(&reservation, &launch);
        custody
            .arena
            .seal_failure(
                ArenaFailureCarrierCandidate::parse_precursor(exact_failure.clone())
                    .expect("failure precursor"),
                ArenaState::FailedIndeterminate,
            )
            .expect("terminal protected failure");
        drop(custody);

        let inventory = store
            .governed_custody_inventory()
            .expect("startup inventory");
        let [GovernedCustodyInventoryEntry::Verified(frontier)] = inventory.as_slice() else {
            panic!("one verified frontier");
        };
        assert_eq!(
            frontier.recovery_class,
            GovernedCustodyRecoveryClass::ProtectedFailure
        );
        assert_eq!(
            frontier.reservation_ledger_binding,
            GovernedCustodyReservationLedgerBinding::NoCommittedReservation
        );
        assert_eq!(
            frontier.protected_failure,
            Some(GovernedCustodyCommitment {
                bytes_digest: sha256_bytes(&exact_failure),
                byte_length: u64::try_from(exact_failure.len()).expect("failure length"),
            })
        );
        let reopened = store
            .governed_protected_failure(&reservation.reservation_record_id)
            .expect("protected failure read");
        let GovernedProtectedFailureAccess::VerifiedAvailable(reopened) = reopened else {
            panic!("protected failure exists");
        };
        assert_eq!(reopened.exact_bytes, exact_failure);
        assert_eq!(reopened.bytes_digest, sha256_bytes(&reopened.exact_bytes));
    }
}
