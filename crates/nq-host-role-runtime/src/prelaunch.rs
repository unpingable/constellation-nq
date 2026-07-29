//! Durable governed prelaunch support.
//!
//! This module ends at authenticated graph validation, physical reservation,
//! ledger commitment, and a one-use launch claim. It deliberately contains no
//! provider invocation, engine result source, finalizer, or execution-binding
//! constructor.

use nq_host_role_contract::{IdentityRef, RecordRef, RuntimeRecordSet};
use nq_protocol::Sha256Digest;
use nq_store::{GovernedCustodyReservation, RuntimeLedgerCheckpoint};

use crate::{RuntimeDependencies, runtime::AppendRequest};

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
/// must privately revalidate and the immutable storage reservation
/// specification. It cannot launch a provider, mutate custody, or construct a
/// diagnostic binding.
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
}

impl PreparedGovernedInvocation {
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
