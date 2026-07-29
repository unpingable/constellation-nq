//! Durable governed prelaunch support.
//!
//! This module ends at authenticated graph validation, physical reservation,
//! ledger commitment, and a one-use launch claim. It deliberately contains no
//! provider invocation, engine result source, finalizer, or execution-binding
//! constructor.

use nq_host_role_contract::{IdentityRef, RecordRef, RuntimeRecordSet};
use nq_protocol::Sha256Digest;
use nq_store::{
    CustodiedAcquisition, GovernedAcquisitionCustodyInput, GovernedCustody,
    GovernedCustodyCommitment, GovernedCustodyReservation, GovernedCustodyState,
    GovernedDerivationCustodyClaim, GovernedProtectedTerminalInput,
    GovernedProtectedTerminalization, RuntimeLedgerCheckpoint,
};

use crate::{Result, RuntimeDependencies, runtime::AppendRequest};

/// Two-phase prelaunch plan.
///
/// `reservation_custody` contains the request, accepted decision, and reserved
/// custody closure. `launch_custody` contains the exact launch record and is
/// appended only after physical reservation and the reservation checkpoint
/// have committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedPrelaunchRequest {
    /// First atomic checkpoint: request, accepted decision, and reservation.
    pub reservation_custody: AppendRequest,
    /// Second atomic checkpoint containing the exact launch record.
    pub launch_custody: AppendRequest,
    /// Exact outer request record identity.
    pub outer_request_record_id: Sha256Digest,
    /// Exact accepted decision record identity.
    pub invocation_decision_record_id: Sha256Digest,
    /// Exact custody-reservation record identity.
    pub custody_reservation_record_id: Sha256Digest,
    /// Exact execution-launch record identity.
    pub execution_launch_record_id: Sha256Digest,
}

/// Caller-supplied non-temporal material for a runtime-owned deadline launch.
///
/// Unlike [`GovernedPrelaunchRequest`], this request has no execution-launch
/// carrier, launch timestamp, attempt deadline, monotonic sample, boot epoch,
/// or deadline-evaluation record. The runtime constructs those values from
/// its own Linux clock and boot-identity observations.
///
/// The three record references are already-governed prelaunch evidence. They
/// remain exact inputs; possession of them grants no invocation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeadlinePrelaunchRequest {
    /// First atomic checkpoint: request, accepted decision, reservation, and
    /// the complete prelaunch graph other than the runtime-owned deadline and
    /// launch records.
    pub reservation_custody: AppendRequest,
    /// Exact outer request record identity.
    pub outer_request_record_id: Sha256Digest,
    /// Exact accepted decision record identity.
    pub invocation_decision_record_id: Sha256Digest,
    /// Exact custody-reservation record identity.
    pub custody_reservation_record_id: Sha256Digest,
    /// Exact generation-compatibility evidence referenced by the launch.
    pub generation_match: RecordRef,
    /// Exact capability evidence referenced by the launch.
    pub capability: RecordRef,
    /// Exact durable launch-commit evidence referenced by the launch.
    pub launch_commit: RecordRef,
    /// Identified policy governing the realtime/boottime sample bracket.
    pub bracket_policy: IdentityRef,
    /// Maximum accepted width of the runtime-owned realtime bracket.
    pub maximum_bracket_width_ns: u64,
}

/// Unforgeable-by-construction runtime-owned deadline provenance.
///
/// Fields are private and this type has no public constructor. An ordinary
/// caller can create deadline-shaped contract records, but cannot attach this
/// provenance to a [`PreparedGovernedInvocation`].
#[derive(Debug, PartialEq, Eq)]
pub struct NativeDeadlineProvenance {
    pub(crate) evaluation: RecordRef,
    pub(crate) clock_qualification: RecordRef,
    pub(crate) boot_epoch: Sha256Digest,
    pub(crate) boottime_observed_ns: u64,
    pub(crate) boottime_expiry_ns: u64,
}

impl NativeDeadlineProvenance {
    /// Return the exact runtime-constructed deadline evaluation.
    #[must_use]
    pub const fn evaluation(&self) -> &RecordRef {
        &self.evaluation
    }

    /// Return the exact cohort-qualified native clock correspondence.
    #[must_use]
    pub const fn clock_qualification(&self) -> &RecordRef {
        &self.clock_qualification
    }

    /// Return the exact digest of the Linux boot-id bytes sampled for launch.
    #[must_use]
    pub const fn boot_epoch(&self) -> &Sha256Digest {
        &self.boot_epoch
    }

    /// Return the exact `CLOCK_BOOTTIME` observation in nanoseconds.
    #[must_use]
    pub const fn boottime_observed_ns(&self) -> u64 {
        self.boottime_observed_ns
    }

    /// Return the exact governed `CLOCK_BOOTTIME` expiry in nanoseconds.
    #[must_use]
    pub const fn boottime_expiry_ns(&self) -> u64 {
        self.boottime_expiry_ns
    }
}

/// Exact production identity recovered from the validated runtime graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedProductionIdentity {
    pub(crate) node: IdentityRef,
    pub(crate) subject: IdentityRef,
    pub(crate) vantage: IdentityRef,
    pub(crate) cohort: IdentityRef,
}

impl GovernedProductionIdentity {
    /// Return the exact enrolled NQ node.
    #[must_use]
    pub const fn node(&self) -> &IdentityRef {
        &self.node
    }

    /// Return the exact diagnostic subject.
    #[must_use]
    pub const fn subject(&self) -> &IdentityRef {
        &self.subject
    }

    /// Return the exact vantage generation.
    #[must_use]
    pub const fn vantage(&self) -> &IdentityRef {
        &self.vantage
    }

    /// Return the exact static-profile cohort generation.
    #[must_use]
    pub const fn cohort(&self) -> &IdentityRef {
        &self.cohort
    }
}

/// Non-cloneable result of a validated and durably claimed prelaunch.
///
/// This is not an execution grant. It exposes only the exact material NQ core
/// must privately revalidate, the immutable storage reservation specification,
/// and narrow custody transitions for this exact one-use launch. It cannot
/// launch a provider, schedule work, construct a diagnostic binding, or expose
/// the underlying custody handle.
pub struct PreparedGovernedInvocation {
    pub(crate) request_id: String,
    pub(crate) production: GovernedProductionIdentity,
    pub(crate) reservation_checkpoint: RuntimeLedgerCheckpoint,
    pub(crate) launch_checkpoint: RuntimeLedgerCheckpoint,
    pub(crate) outer_request: RecordRef,
    pub(crate) invocation_decision: RecordRef,
    pub(crate) custody_reservation: RecordRef,
    pub(crate) execution_launch: RecordRef,
    pub(crate) prelaunch_records: RuntimeRecordSet,
    pub(crate) existing_provider_intakes: Vec<RecordRef>,
    pub(crate) dependencies: RuntimeDependencies,
    pub(crate) dependency_custody_bytes: Vec<u8>,
    pub(crate) custody_reservation_spec: GovernedCustodyReservation,
    pub(crate) native_deadline: Option<NativeDeadlineProvenance>,
    pub(crate) live_custody: GovernedCustody,
}

impl PreparedGovernedInvocation {
    fn require_exact_launch(&self, launch: &Sha256Digest) -> Result<()> {
        if launch != &self.execution_launch.record_id {
            return Err(crate::RuntimeError::PreparedCustodyLaunchSubstitution);
        }
        Ok(())
    }

    /// Return the exact authorized outer request occurrence.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Return the graph-resolved production identity.
    #[must_use]
    pub const fn production_identity(&self) -> &GovernedProductionIdentity {
        &self.production
    }

    /// Return the committed reservation checkpoint.
    #[must_use]
    pub const fn reservation_checkpoint(&self) -> &RuntimeLedgerCheckpoint {
        &self.reservation_checkpoint
    }

    /// Return the committed launch checkpoint.
    #[must_use]
    pub const fn launch_checkpoint(&self) -> &RuntimeLedgerCheckpoint {
        &self.launch_checkpoint
    }

    /// Return the exact outer request reference.
    #[must_use]
    pub const fn outer_request(&self) -> &RecordRef {
        &self.outer_request
    }

    /// Return the exact accepted invocation-decision reference.
    #[must_use]
    pub const fn invocation_decision(&self) -> &RecordRef {
        &self.invocation_decision
    }

    /// Return the exact custody-reservation reference.
    #[must_use]
    pub const fn custody_reservation(&self) -> &RecordRef {
        &self.custody_reservation
    }

    /// Return the exact execution-launch reference.
    #[must_use]
    pub const fn execution_launch(&self) -> &RecordRef {
        &self.execution_launch
    }

    /// Return the complete prelaunch graph frozen at launch.
    #[must_use]
    pub const fn prelaunch_records(&self) -> &RuntimeRecordSet {
        &self.prelaunch_records
    }

    /// Return the exact provider-intake references preceding this invocation.
    #[must_use]
    pub fn existing_provider_intakes(&self) -> &[RecordRef] {
        &self.existing_provider_intakes
    }

    /// Return the authenticated dependency generation frozen at launch.
    #[must_use]
    pub const fn dependencies(&self) -> &RuntimeDependencies {
        &self.dependencies
    }

    /// Return the exact dependency-generation custody carrier.
    #[must_use]
    pub fn dependency_custody_bytes(&self) -> &[u8] {
        &self.dependency_custody_bytes
    }

    /// Return the immutable physical reservation specification.
    #[must_use]
    pub const fn custody_reservation_spec(&self) -> &GovernedCustodyReservation {
        &self.custody_reservation_spec
    }

    /// Return runtime-owned native-deadline provenance when this invocation
    /// used the sealed native preparation path.
    ///
    /// The generic 3A preparation path always returns `None`, even if a caller
    /// supplied a deadline-shaped record.
    #[must_use]
    pub const fn native_deadline(&self) -> Option<&NativeDeadlineProvenance> {
        self.native_deadline.as_ref()
    }

    /// Return the durable state of the exact live custody handle retained by
    /// this one-use prepared occurrence.
    ///
    /// This is a physical custody fact, not a diagnostic disposition.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable or corrupt arena.
    pub fn live_custody_state(&self) -> Result<GovernedCustodyState> {
        self.live_custody.state().map_err(Into::into)
    }

    /// Seal and reopen exact provider-intake and raw bytes through this
    /// prepared occurrence's live custody handle.
    ///
    /// This is a physical custody transition only. It assigns no provider,
    /// evidence, diagnostic, reliance, or authorization standing.
    ///
    /// # Errors
    ///
    /// Refuses launch substitution, capacity overflow, replay, or persistence
    /// failure.
    pub fn seal_acquisition(
        &mut self,
        input: GovernedAcquisitionCustodyInput,
    ) -> Result<CustodiedAcquisition> {
        self.require_exact_launch(&input.execution_launch_record_id)?;
        self.live_custody
            .seal_acquisition(input)
            .map_err(Into::into)
    }

    /// Claim one derivation transition over the exact sealed acquisition.
    ///
    /// This retains the one-use custody handle inside the prepared token and
    /// assigns no semantic validity itself.
    ///
    /// # Errors
    ///
    /// Refuses a missing/substituted acquisition, replay, or persistence
    /// failure.
    pub fn claim_derivation(&mut self, claim: GovernedDerivationCustodyClaim) -> Result<()> {
        self.live_custody
            .claim_derivation(claim)
            .map_err(Into::into)
    }

    /// Seal exact bytes of a core-validated complete closure.
    ///
    /// The runtime forwards only to the already-owned custody handle. It does
    /// not validate or mint NQ semantics.
    ///
    /// # Errors
    ///
    /// Refuses a missing derivation claim, capacity overflow, malformed store
    /// carrier, replay, or persistence failure.
    pub fn seal_final_closure(
        &mut self,
        exact_closure_bytes: Vec<u8>,
    ) -> Result<GovernedCustodyCommitment> {
        self.live_custody
            .seal_final_closure(exact_closure_bytes)
            .map_err(Into::into)
    }

    /// Reopen exact final-closure bytes without refreshing or interpreting
    /// them.
    ///
    /// # Errors
    ///
    /// Refuses unreadable or corrupt custody.
    pub fn final_closure_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.live_custody.final_closure_bytes().map_err(Into::into)
    }

    /// Terminalize the exact launch using the one-use custody authority owned
    /// by this prepared occurrence.
    ///
    /// A merely reopened custody handle cannot perform this transition. The
    /// method records custody-only failure/refusal material; it does not create
    /// an NQ diagnostic disposition.
    ///
    /// # Errors
    ///
    /// Refuses substitution, invalid ordering/deadline classification, a
    /// nonterminal handle reopened after restart, or persistence failure.
    pub fn terminalize_immediate_launch(
        &mut self,
        input: GovernedProtectedTerminalInput,
    ) -> Result<GovernedProtectedTerminalization> {
        self.require_exact_launch(&input.execution_launch_record_id)?;
        self.live_custody
            .terminalize_immediate_launch(input)
            .map_err(Into::into)
    }
}

pub(crate) fn production_identity(
    node: IdentityRef,
    subject: IdentityRef,
    vantage: IdentityRef,
    cohort: IdentityRef,
) -> GovernedProductionIdentity {
    GovernedProductionIdentity {
        node,
        subject,
        vantage,
        cohort,
    }
}
