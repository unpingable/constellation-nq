//! Opaque exact-byte custody for one governed diagnostic invocation.
//!
//! This module deliberately exposes storage mechanics only. It does not parse
//! provider intake, establish an evaluator occurrence, validate a diagnostic
//! execution, construct an execution binding, or authorize SQLite indexing.
//! Those semantic checks belong to `nq-core`.

use std::path::{Path, PathBuf};

use nq_protocol::Sha256Digest;

use crate::custody_arena::{
    AcquisitionCarrier, ArenaLayout, ArenaPrelaunchBinding, ArenaState, CustodyArena,
    DerivationClaim, DerivedV2ClosureCandidate,
};
use crate::{Store, StoreError};

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

    /// Mark the already-sealed closure indexed only after core has verified and
    /// committed the exact idempotent SQLite write set.
    pub fn mark_indexed(&mut self) -> Result<(), StoreError> {
        let token = self.arena.reopen_final_token().map_err(custody_error)?;
        self.arena.mark_indexed(token).map_err(custody_error)
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
}

fn custody_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Invariant(format!("governed exact-byte custody failed: {error}"))
}
