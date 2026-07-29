//! Opaque exact-byte custody for one governed diagnostic invocation.
//!
//! This module deliberately exposes storage mechanics only. It does not parse
//! provider intake, establish an evaluator occurrence, validate a diagnostic
//! execution, construct an execution binding, or authorize SQLite indexing.
//! Those semantic checks belong to `nq-core`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nq_protocol::Sha256Digest;

use crate::custody_arena::{
    AcquisitionCarrier, ArenaInventoryEntry, ArenaLayout, ArenaPrelaunchBinding, ArenaState,
    CustodyArena, DerivationClaim, DerivedV2ClosureCandidate,
};
use crate::{MAX_PUBLIC_QUERY_ROWS, Store, StoreError};

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
    /// Exact final bytes and their verified projection were both recorded.
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

/// Exact opaque provider occurrence bytes reopened from durable custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodiedAcquisition {
    pub execution_launch_record_id: Sha256Digest,
    pub provider_intake_record_id: Sha256Digest,
    pub exact_provider_intake_bytes: Vec<u8>,
    pub exact_raw_provider_bytes: Vec<u8>,
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
