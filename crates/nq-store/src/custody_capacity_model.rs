//! Pure, checked custody-capacity arithmetic.
//!
//! This module deliberately stops before allocation.  Its values describe
//! semantic adequacy, canonical-carrier geometry, logical aggregate usage,
//! and whether a candidate is within the installed logical limits.  They do
//! not report filesystem free space, prove that bytes were allocated, grant
//! invocation authority, or authorize a provider effect.

use std::collections::BTreeSet;

pub use nq_host_role_contract::{
    AppendExtentGeometryV1, CAPACITY_IJSON_SAFE_INTEGER_MAX_V1, CUSTODY_CAPACITY_ALIGNMENT_V1,
    CustodyArenaGeometryV1,
};
use nq_host_role_contract::{
    CAPACITY_FUTURE_ARTIFACT_SLOT, CapacityArithmeticError, CapacityCandidateChargeV1,
    CapacityDeliveryRequirementSelection,
    CapacityDeliveryRequirementV1 as ContractDeliveryRequirementV1,
    CapacityLimitRefusalV1 as ContractCapacityLimitRefusalV1,
    CapacityLogicalDispositionV1 as ContractCapacityLogicalDispositionV1, CapacityLogicalLimitsV1,
    CapacitySemanticComponentsV1, CapacityUsageComponentsV1,
    CapacityWatermarkClassificationV1 as ContractCapacityWatermarkClassificationV1,
    ReservationPlanDeliveryRequirementSelection, capacity_queue_occurrence_identity,
    checked_append_extent_geometry_v1 as contract_append_extent_geometry_v1,
    checked_capacity_integer_v1, checked_capacity_post_usage_v1 as contract_capacity_post_usage_v1,
    checked_capacity_retained_charge_v1 as contract_capacity_retained_charge_v1,
    checked_capacity_semantic_sum_v1 as contract_capacity_semantic_sum_v1,
    checked_capacity_single_execution_bound_v1 as contract_capacity_single_execution_bound_v1,
    checked_capacity_usage_v1 as contract_capacity_usage_v1,
    checked_custody_arena_geometry_v1 as contract_custody_arena_geometry_v1,
    checked_logical_preallocated_custody_carriers_v1 as contract_logical_preallocated_custody_carriers_v1,
    classify_capacity_high_watermark_v1 as contract_classify_capacity_high_watermark_v1,
};
use nq_protocol::Sha256Digest;
use serde::Serialize;
use thiserror::Error;

/// Fixed, authority-neutral placeholder committed before an artifact exists.
pub const FUTURE_ARTIFACT_SLOT_V1: &str = CAPACITY_FUTURE_ARTIFACT_SLOT;

/// A failure in the pure capacity model.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CapacityModelError {
    /// Checked integer arithmetic overflowed.
    #[error("custody capacity arithmetic overflowed while calculating {0}")]
    ArithmeticOverflow(&'static str),
    /// A serialized capacity input, intermediate, or result exceeded the
    /// exact I-JSON/JCS integer domain.
    #[error("custody capacity integer is unsafe while calculating {0}")]
    UnsafeInteger(&'static str),
    /// The reservation's declared semantic total differs from the eight-part
    /// checked sum.
    #[error(
        "semantic total differs: declared {declared_bytes} bytes, computed {computed_bytes} bytes"
    )]
    SemanticTotalMismatch {
        /// Total recorded by the reservation.
        declared_bytes: u64,
        /// Checked sum of all eight semantic components.
        computed_bytes: u64,
    },
    /// A new launchable reservation must reserve the exact semantic sum.
    #[error(
        "semantic reservation differs: reserved {reserved_bytes} bytes, required exactly {required_bytes} bytes"
    )]
    SemanticReservationMismatch {
        /// Bytes recorded as reserved.
        reserved_bytes: u64,
        /// Exact checked semantic sum.
        required_bytes: u64,
    },
    /// A physical carrier that must exist was assigned no payload capacity.
    #[error("{carrier} payload capacity must be nonzero")]
    ZeroCarrierPayload {
        /// Closed carrier label.
        carrier: &'static str,
    },
    /// A semantic component or actual payload does not fit its own carrier.
    #[error(
        "{carrier} requires {required_bytes} bytes but its independent bound is {available_bytes} bytes"
    )]
    CarrierBoundExceeded {
        /// Closed carrier label.
        carrier: &'static str,
        /// Bytes that must fit.
        required_bytes: u64,
        /// Independently derived carrier bound.
        available_bytes: u64,
    },
    /// A delivery plan violates the closed required/not-required forms.
    #[error("delivery capacity plan is invalid: {0}")]
    InvalidDeliveryPlan(&'static str),
    /// A required-delivery destination was repeated.
    #[error("delivery capacity plan repeats destination generation {0}")]
    DuplicateDeliveryDestination(Sha256Digest),
    /// A Store delivery plan or queue occurrence list differs from the exact
    /// neutral-plan delivery set selected by the contract graph.
    #[error("delivery capacity correspondence is invalid: {0}")]
    InvalidDeliveryCorrespondence(&'static str),
    /// An installed capacity policy is internally inconsistent.
    #[error("capacity policy is invalid: {0}")]
    InvalidCapacityPolicy(&'static str),
    /// A derived carrier map was evaluated under a different protected-failure
    /// policy from the one that produced it.
    #[error(
        "protected-failure carrier is {carrier_bytes} bytes but policy requires exactly {policy_bytes} bytes"
    )]
    ProtectedFailurePolicyMismatch {
        /// `P` in the already-derived carrier map.
        carrier_bytes: u64,
        /// `P` required by the policy used for evaluation.
        policy_bytes: u64,
    },
    /// A retained carrier contribution must be a real, nonzero charge.
    #[error("{carrier} logical carrier charge must be nonzero")]
    ZeroLogicalCarrierCharge {
        /// Closed carrier label.
        carrier: &'static str,
    },
    /// Canonical encoding of the queue-occurrence key preimage failed.
    #[error("cannot encode queue occurrence key preimage: {0}")]
    QueueOccurrenceEncoding(String),
}

/// The eight semantic component bounds in `nq.custody_reservation.v1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticComponentBoundsV1 {
    /// Request, authentication, authorization, and decision material.
    pub request_and_decision_bytes: u64,
    /// Raw acquisition evidence.
    pub raw_evidence_bytes: u64,
    /// Admitted normalized facts.
    pub normalized_bytes: u64,
    /// Admitted projected facts.
    pub projected_bytes: u64,
    /// Diagnostic or typed non-success artifact.
    pub diagnostic_artifact_bytes: u64,
    /// Authenticated dependency closure.
    pub dependency_closure_bytes: u64,
    /// Capacity, launch, checkpoint, and commit records.
    pub commit_checkpoint_overhead_bytes: u64,
    /// Required immutable delivery-ledger chain.
    pub mandatory_delivery_ledger_bytes: u64,
}

/// Compute the exact checked sum of all eight semantic components.
///
/// This is semantic accounting, not physical-carrier accounting.
pub fn checked_semantic_sum_v1(
    bounds: &SemanticComponentBoundsV1,
) -> Result<u64, CapacityModelError> {
    contract_capacity_semantic_sum_v1(&contract_semantic_components(bounds))
        .map_err(map_arithmetic_error)
}

const fn contract_semantic_components(
    bounds: &SemanticComponentBoundsV1,
) -> CapacitySemanticComponentsV1 {
    CapacitySemanticComponentsV1 {
        request_and_decision_bytes: bounds.request_and_decision_bytes,
        raw_evidence_bytes: bounds.raw_evidence_bytes,
        normalized_bytes: bounds.normalized_bytes,
        projected_bytes: bounds.projected_bytes,
        diagnostic_artifact_bytes: bounds.diagnostic_artifact_bytes,
        dependency_closure_bytes: bounds.dependency_closure_bytes,
        commit_checkpoint_overhead_bytes: bounds.commit_checkpoint_overhead_bytes,
        mandatory_delivery_ledger_bytes: bounds.mandatory_delivery_ledger_bytes,
    }
}

/// Require both declared semantic totals to equal the checked eight-part sum.
///
/// A one-byte surplus is refused just like a one-byte deficit.  This function
/// does not allocate anything or make a launch decision.
pub fn validate_exact_semantic_reservation_v1(
    bounds: &SemanticComponentBoundsV1,
    total_required_bytes: u64,
    reserved_bytes: u64,
) -> Result<u64, CapacityModelError> {
    checked_capacity_integer_v1(total_required_bytes, "declared semantic total")
        .map_err(map_arithmetic_error)?;
    checked_capacity_integer_v1(reserved_bytes, "semantic reservation")
        .map_err(map_arithmetic_error)?;
    let semantic_sum_bytes = checked_semantic_sum_v1(bounds)?;
    if total_required_bytes != semantic_sum_bytes {
        return Err(CapacityModelError::SemanticTotalMismatch {
            declared_bytes: total_required_bytes,
            computed_bytes: semantic_sum_bytes,
        });
    }
    if reserved_bytes != semantic_sum_bytes {
        return Err(CapacityModelError::SemanticReservationMismatch {
            reserved_bytes,
            required_bytes: semantic_sum_bytes,
        });
    }
    Ok(semantic_sum_bytes)
}

/// Closed delivery-capacity state selected before any provider effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryCapacityRequirementV1 {
    /// Delivery is explicitly absent from this bounded request.
    NotRequired,
    /// Delivery to a closed set of destination generations is required.
    Required,
}

/// Pure capacity inputs for one delivery requirement.
///
/// Public fields allow a decoded contract to be checked without first
/// laundering it through a trusted constructor.  [`validate`](Self::validate)
/// is called by every carrier-map entry point.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryCapacityPlanV1 {
    /// Required versus explicitly not required.
    pub requirement: DeliveryCapacityRequirementV1,
    /// Closed destination generations.  Their order is preserved; duplicates
    /// are invalid.
    pub destination_generation_ids: Vec<Sha256Digest>,
    /// Exact delivery-policy generation, absent only for `not_required`.
    pub delivery_policy_generation_id: Option<Sha256Digest>,
    /// Independently derived delivery-ledger payload bound.
    pub delivery_ledger_payload_bytes: u64,
    /// Exact queue slots reserved by the plan.
    pub queue_slots: u64,
}

impl DeliveryCapacityPlanV1 {
    /// Construct the sole valid no-delivery form.
    #[must_use]
    pub const fn not_required() -> Self {
        Self {
            requirement: DeliveryCapacityRequirementV1::NotRequired,
            destination_generation_ids: Vec::new(),
            delivery_policy_generation_id: None,
            delivery_ledger_payload_bytes: 0,
            queue_slots: 0,
        }
    }

    /// Construct and validate a required-delivery plan.
    pub fn required(
        destination_generation_ids: Vec<Sha256Digest>,
        delivery_policy_generation_id: Sha256Digest,
        delivery_ledger_payload_bytes: u64,
    ) -> Result<Self, CapacityModelError> {
        let queue_slots = u64::try_from(destination_generation_ids.len())
            .map_err(|_| CapacityModelError::ArithmeticOverflow("required delivery queue slots"))?;
        let plan = Self {
            requirement: DeliveryCapacityRequirementV1::Required,
            destination_generation_ids,
            delivery_policy_generation_id: Some(delivery_policy_generation_id),
            delivery_ledger_payload_bytes,
            queue_slots,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validate the complete closed form, including destination uniqueness.
    pub fn validate(&self) -> Result<(), CapacityModelError> {
        checked_capacity_integer_v1(
            self.delivery_ledger_payload_bytes,
            "delivery-ledger payload capacity",
        )
        .map_err(map_arithmetic_error)?;
        checked_capacity_integer_v1(self.queue_slots, "delivery queue slots")
            .map_err(map_arithmetic_error)?;
        match self.requirement {
            DeliveryCapacityRequirementV1::NotRequired => {
                if !self.destination_generation_ids.is_empty() {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "not_required has destination generations",
                    ));
                }
                if self.delivery_policy_generation_id.is_some() {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "not_required has a delivery-policy generation",
                    ));
                }
                if self.delivery_ledger_payload_bytes != 0 {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "not_required has delivery-ledger bytes",
                    ));
                }
                if self.queue_slots != 0 {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "not_required has queue slots",
                    ));
                }
            }
            DeliveryCapacityRequirementV1::Required => {
                if self.destination_generation_ids.is_empty() {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "required delivery has no destination generation",
                    ));
                }
                if self.delivery_policy_generation_id.is_none() {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "required delivery has no policy generation",
                    ));
                }
                if self.delivery_ledger_payload_bytes == 0 {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "required delivery has no ledger payload capacity",
                    ));
                }
                let expected_slots =
                    u64::try_from(self.destination_generation_ids.len()).map_err(|_| {
                        CapacityModelError::ArithmeticOverflow(
                            "required delivery destination count",
                        )
                    })?;
                checked_capacity_integer_v1(expected_slots, "required delivery destination count")
                    .map_err(map_arithmetic_error)?;
                if self.queue_slots != expected_slots {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "required delivery queue slots differ from destination generations",
                    ));
                }
                let mut unique = BTreeSet::new();
                for destination in &self.destination_generation_ids {
                    if !unique.insert(destination) {
                        return Err(CapacityModelError::DuplicateDeliveryDestination(
                            (*destination).clone(),
                        ));
                    }
                }
                if self
                    .destination_generation_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                {
                    return Err(CapacityModelError::InvalidDeliveryPlan(
                        "required delivery destinations are not in canonical sorted order",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Independently derived payload bounds consumed by the carrier map.
///
/// No field is calculated as residue from a semantic total or another
/// carrier.  The projection-capsule and final-closure bounds are deliberately
/// separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierPayloadBoundsV1 {
    /// `D`: authenticated dependency-section payload.
    pub dependency_payload_bytes: u64,
    /// `R`: typed acquisition/raw-section payload.
    pub raw_acquisition_payload_bytes: u64,
    /// `C`: complete closed V3 projection-capsule bound.
    pub projection_capsule_bound_bytes: u64,
    /// `V`: complete immutable final-closure payload.
    pub final_closure_payload_bytes: u64,
    /// Payload of the canonical prelaunch/commit record extent.
    pub canonical_record_payload_bytes: u64,
}

fn checked_add(left: u64, right: u64, operation: &'static str) -> Result<u64, CapacityModelError> {
    checked_capacity_integer_v1(left, operation).map_err(map_arithmetic_error)?;
    checked_capacity_integer_v1(right, operation).map_err(map_arithmetic_error)?;
    let result = left
        .checked_add(right)
        .ok_or(CapacityModelError::ArithmeticOverflow(operation))?;
    checked_capacity_integer_v1(result, operation).map_err(map_arithmetic_error)
}

fn checked_sum(
    values: impl IntoIterator<Item = u64>,
    operation: &'static str,
) -> Result<u64, CapacityModelError> {
    values
        .into_iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, value, operation))
}

fn map_arithmetic_error(error: CapacityArithmeticError) -> CapacityModelError {
    match error {
        CapacityArithmeticError::UnsafeInteger(operation) => {
            CapacityModelError::UnsafeInteger(operation)
        }
        CapacityArithmeticError::ZeroCarrierPayload(carrier) => {
            CapacityModelError::ZeroCarrierPayload { carrier }
        }
        CapacityArithmeticError::InvalidPolicy(detail) => {
            CapacityModelError::InvalidCapacityPolicy(detail)
        }
        CapacityArithmeticError::ProtectedFailurePolicyMismatch {
            carrier_bytes,
            policy_bytes,
        } => CapacityModelError::ProtectedFailurePolicyMismatch {
            carrier_bytes,
            policy_bytes,
        },
    }
}

fn require_nonzero_carrier(carrier: &'static str, bytes: u64) -> Result<(), CapacityModelError> {
    checked_capacity_integer_v1(bytes, carrier).map_err(map_arithmetic_error)?;
    if bytes == 0 {
        return Err(CapacityModelError::ZeroCarrierPayload { carrier });
    }
    Ok(())
}

/// Derive the exact checked arena geometry used by the v1 physical format.
///
/// This function performs no allocation and makes no backend-support claim.
pub fn checked_arena_geometry_v1(
    dependency_payload_bytes: u64,
    raw_payload_bytes: u64,
    final_payload_bytes: u64,
    failure_payload_bytes: u64,
) -> Result<CustodyArenaGeometryV1, CapacityModelError> {
    contract_custody_arena_geometry_v1(
        dependency_payload_bytes,
        raw_payload_bytes,
        final_payload_bytes,
        failure_payload_bytes,
    )
    .map_err(map_arithmetic_error)
}

/// Derive one exact append-only carrier extent.
///
/// `payload_bytes == 0` is not a null-delivery encoding; null delivery has no
/// extent and is represented by [`DeliveryCapacityPlanV1::not_required`].
pub fn checked_append_extent_geometry_v1(
    payload_bytes: u64,
) -> Result<AppendExtentGeometryV1, CapacityModelError> {
    contract_append_extent_geometry_v1(payload_bytes).map_err(map_arithmetic_error)
}

/// Derive `B = A + extent_length(b_payload_bound)`.
///
/// This is only logical geometry for the bootstrap carrier; it does not
/// create the permanent lock page or authenticate bootstrap material.
pub fn checked_bootstrap_carrier_length_v1(
    bootstrap_payload_bytes: u64,
) -> Result<u64, CapacityModelError> {
    let extent = checked_append_extent_geometry_v1(bootstrap_payload_bytes)?;
    checked_add(
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        extent.extent_length_bytes,
        "bootstrap carrier length",
    )
}

/// A closed physical carrier role used for independent fit checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyCarrierRoleV1 {
    /// Arena dependency closure `D`.
    DependencyClosure,
    /// Arena raw acquisition carrier `R`.
    RawAcquisition,
    /// Arena final closure `V`.
    FinalClosure,
    /// Arena protected failure payload `P`.
    ProtectedFailure,
    /// Canonical record append payload inside `M`.
    CanonicalRecord,
    /// Delivery ledger append payload inside `L`.
    DeliveryLedger,
}

impl CustodyCarrierRoleV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::DependencyClosure => "dependency",
            Self::RawAcquisition => "raw_acquisition",
            Self::FinalClosure => "final_closure",
            Self::ProtectedFailure => "protected_failure",
            Self::CanonicalRecord => "canonical_record",
            Self::DeliveryLedger => "delivery_ledger",
        }
    }
}

/// Require one actual or semantic payload to fit its own independent bound.
///
/// No other carrier's unused capacity is considered.
pub fn validate_carrier_payload_fit_v1(
    carrier: CustodyCarrierRoleV1,
    required_bytes: u64,
    available_bytes: u64,
) -> Result<(), CapacityModelError> {
    checked_capacity_integer_v1(required_bytes, "required carrier payload")
        .map_err(map_arithmetic_error)?;
    checked_capacity_integer_v1(available_bytes, "available carrier payload")
        .map_err(map_arithmetic_error)?;
    if required_bytes > available_bytes {
        return Err(CapacityModelError::CarrierBoundExceeded {
            carrier: carrier.label(),
            required_bytes,
            available_bytes,
        });
    }
    Ok(())
}

/// Total closed carrier map for one pre-effect candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyCarrierMapV1 {
    /// Checked semantic sum `S`.
    semantic_sum_bytes: u64,
    /// Complete V3 projection capsule bound `C`.
    projection_capsule_bound_bytes: u64,
    /// Exact `D/R/V/P` arena geometry and complete arena charge `F`.
    arena: CustodyArenaGeometryV1,
    /// Exact canonical-record extent `M`.
    canonical_record_extent: AppendExtentGeometryV1,
    /// Exact delivery extent `L`, absent only for explicit `not_required`.
    delivery_ledger_extent: Option<AppendExtentGeometryV1>,
    /// Exact queue slots (one per unique destination generation).
    queue_slots: u64,
    /// `T = F + M + L`, charged once.
    retained_charge_bytes: u64,
}

impl CustodyCarrierMapV1 {
    /// Checked semantic sum `S`.
    #[must_use]
    pub const fn semantic_sum_bytes(&self) -> u64 {
        self.semantic_sum_bytes
    }

    /// Complete independently derived V3 projection-capsule bound `C`.
    #[must_use]
    pub const fn projection_capsule_bound_bytes(&self) -> u64 {
        self.projection_capsule_bound_bytes
    }

    /// Exact `D/R/V/P` geometry.
    #[must_use]
    pub const fn arena(&self) -> &CustodyArenaGeometryV1 {
        &self.arena
    }

    /// `F`.
    #[must_use]
    pub const fn arena_file_length_bytes(&self) -> u64 {
        self.arena.file_length_bytes
    }

    /// Exact canonical-record append extent.
    #[must_use]
    pub const fn canonical_record_extent(&self) -> &AppendExtentGeometryV1 {
        &self.canonical_record_extent
    }

    /// `M`.
    #[must_use]
    pub const fn canonical_record_extent_length_bytes(&self) -> u64 {
        self.canonical_record_extent.extent_length_bytes
    }

    /// Exact delivery-ledger extent, absent only for explicit
    /// `not_required`.
    #[must_use]
    pub const fn delivery_ledger_extent(&self) -> Option<&AppendExtentGeometryV1> {
        self.delivery_ledger_extent.as_ref()
    }

    /// `L`, or zero for explicit `not_required`.
    #[must_use]
    pub fn delivery_ledger_extent_length_bytes(&self) -> u64 {
        self.delivery_ledger_extent
            .as_ref()
            .map_or(0, |extent| extent.extent_length_bytes)
    }

    /// Exact queue slots, one per closed destination generation.
    #[must_use]
    pub const fn queue_slots(&self) -> u64 {
        self.queue_slots
    }

    /// Exact retained carrier charge `T`.
    #[must_use]
    pub const fn retained_charge_bytes(&self) -> u64 {
        self.retained_charge_bytes
    }
}

/// Derive the total carrier map from independent pre-effect bounds.
///
/// The map enforces the semantic destination of every v1 component.  Wrapper
/// and format overhead must already be included in the supplied independent
/// payload bounds; slack in one carrier never repairs another.  `P` is taken
/// only from the validated installed policy and is not caller-selected.
#[allow(clippy::too_many_lines)] // One total carrier map keeps all no-borrow joins together.
pub fn derive_custody_carrier_map_v1(
    policy: &CapacityPolicyV1,
    semantic: &SemanticComponentBoundsV1,
    payloads: &CarrierPayloadBoundsV1,
    delivery: &DeliveryCapacityPlanV1,
) -> Result<CustodyCarrierMapV1, CapacityModelError> {
    policy.validate()?;
    delivery.validate()?;
    for (carrier, bytes) in [
        ("dependency", payloads.dependency_payload_bytes),
        ("raw_acquisition", payloads.raw_acquisition_payload_bytes),
        (
            "projection_capsule",
            payloads.projection_capsule_bound_bytes,
        ),
        ("final_closure", payloads.final_closure_payload_bytes),
        ("protected_failure", policy.protected_failure_receipt_bytes),
        ("canonical_record", payloads.canonical_record_payload_bytes),
    ] {
        require_nonzero_carrier(carrier, bytes)?;
    }

    let semantic_sum_bytes = checked_semantic_sum_v1(semantic)?;
    validate_carrier_payload_fit_v1(
        CustodyCarrierRoleV1::DependencyClosure,
        semantic.dependency_closure_bytes,
        payloads.dependency_payload_bytes,
    )?;
    validate_carrier_payload_fit_v1(
        CustodyCarrierRoleV1::RawAcquisition,
        semantic.raw_evidence_bytes,
        payloads.raw_acquisition_payload_bytes,
    )?;
    // The exhaustive V3 field manifest owns C; Store must not invent a second
    // capsule rule by re-deriving it from semantic components.  Store checks
    // the independent C and the combined final semantic components against V.
    let final_semantic_bytes = checked_sum(
        [
            semantic.normalized_bytes,
            semantic.projected_bytes,
            semantic.diagnostic_artifact_bytes,
        ],
        "final semantic components",
    )?;
    validate_carrier_payload_fit_v1(
        CustodyCarrierRoleV1::FinalClosure,
        final_semantic_bytes,
        payloads.final_closure_payload_bytes,
    )?;
    validate_carrier_payload_fit_v1(
        CustodyCarrierRoleV1::FinalClosure,
        payloads.projection_capsule_bound_bytes,
        payloads.final_closure_payload_bytes,
    )?;
    let canonical_semantic_bytes = checked_sum(
        [
            semantic.request_and_decision_bytes,
            semantic.commit_checkpoint_overhead_bytes,
        ],
        "canonical-record semantic components",
    )?;
    validate_carrier_payload_fit_v1(
        CustodyCarrierRoleV1::CanonicalRecord,
        canonical_semantic_bytes,
        payloads.canonical_record_payload_bytes,
    )?;

    let delivery_ledger_extent = match delivery.requirement {
        DeliveryCapacityRequirementV1::NotRequired => {
            if semantic.mandatory_delivery_ledger_bytes != 0 {
                return Err(CapacityModelError::InvalidDeliveryPlan(
                    "not_required has nonzero semantic delivery bytes",
                ));
            }
            None
        }
        DeliveryCapacityRequirementV1::Required => {
            if semantic.mandatory_delivery_ledger_bytes == 0 {
                return Err(CapacityModelError::InvalidDeliveryPlan(
                    "required delivery has zero semantic delivery bytes",
                ));
            }
            validate_carrier_payload_fit_v1(
                CustodyCarrierRoleV1::DeliveryLedger,
                semantic.mandatory_delivery_ledger_bytes,
                delivery.delivery_ledger_payload_bytes,
            )?;
            Some(checked_append_extent_geometry_v1(
                delivery.delivery_ledger_payload_bytes,
            )?)
        }
    };

    let arena = checked_arena_geometry_v1(
        payloads.dependency_payload_bytes,
        payloads.raw_acquisition_payload_bytes,
        payloads.final_closure_payload_bytes,
        policy.protected_failure_receipt_bytes,
    )?;
    let canonical_record_extent =
        checked_append_extent_geometry_v1(payloads.canonical_record_payload_bytes)?;
    let retained_charge_bytes = checked_retained_charge_v1(
        arena.file_length_bytes,
        canonical_record_extent.extent_length_bytes,
        delivery_ledger_extent
            .as_ref()
            .map_or(0, |extent| extent.extent_length_bytes),
    )?;

    Ok(CustodyCarrierMapV1 {
        semantic_sum_bytes,
        projection_capsule_bound_bytes: payloads.projection_capsule_bound_bytes,
        arena,
        canonical_record_extent,
        delivery_ledger_extent,
        queue_slots: delivery.queue_slots,
        retained_charge_bytes,
    })
}

/// Compute `T = F + M + L` exactly once.
pub fn checked_retained_charge_v1(
    arena_file_length_bytes: u64,
    canonical_record_extent_length_bytes: u64,
    delivery_ledger_extent_length_bytes: u64,
) -> Result<u64, CapacityModelError> {
    contract_capacity_retained_charge_v1(
        arena_file_length_bytes,
        canonical_record_extent_length_bytes,
        delivery_ledger_extent_length_bytes,
    )
    .map_err(map_arithmetic_error)
}

/// Exact aggregate logical usage before one candidate allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalCarrierUsageV1 {
    /// Fixed bootstrap/integrity carrier `B`.
    bootstrap_carrier_bytes: u64,
    /// Fixed global refusal journal `G`.
    global_refusal_carrier_bytes: u64,
    /// Sum of all retained allocated `T_i`.
    retained_allocation_bytes: u64,
    /// Sum of all charged orphan `T_i`.
    charged_orphan_bytes: u64,
    /// Bytes committed by the canonical record plane but absent from the
    /// matched physical-carrier inventory.
    missing_committed_bytes: u64,
    /// `U = B + G + retained + physical_orphans + missing_committed`.
    logical_preallocated_carrier_bytes: u64,
    /// Active queue occurrences before this candidate.
    active_queue_entries: u64,
}

impl LogicalCarrierUsageV1 {
    /// Fixed bootstrap/integrity carrier `B`.
    #[must_use]
    pub const fn bootstrap_carrier_bytes(&self) -> u64 {
        self.bootstrap_carrier_bytes
    }

    /// Fixed global refusal journal `G`.
    #[must_use]
    pub const fn global_refusal_carrier_bytes(&self) -> u64 {
        self.global_refusal_carrier_bytes
    }

    /// Sum of retained allocation charges.
    #[must_use]
    pub const fn retained_allocation_bytes(&self) -> u64 {
        self.retained_allocation_bytes
    }

    /// Sum of charged orphan carrier sets.
    #[must_use]
    pub const fn charged_orphan_bytes(&self) -> u64 {
        self.charged_orphan_bytes
    }

    /// Canonically committed bytes missing from the matched physical
    /// inventory.
    #[must_use]
    pub const fn missing_committed_bytes(&self) -> u64 {
        self.missing_committed_bytes
    }

    /// Exact logical Store usage `U`.
    #[must_use]
    pub const fn logical_preallocated_carrier_bytes(&self) -> u64 {
        self.logical_preallocated_carrier_bytes
    }

    /// Active queue occurrences before the candidate.
    #[must_use]
    pub const fn active_queue_entries(&self) -> u64 {
        self.active_queue_entries
    }
}

/// Compute one exact Store usage snapshot from complete retained populations.
pub fn checked_logical_carrier_usage_v1(
    bootstrap_carrier_bytes: u64,
    global_refusal_carrier_bytes: u64,
    retained_allocation_charges: &[u64],
    charged_orphan_charges: &[u64],
    missing_committed_bytes: u64,
    active_queue_entries: u64,
) -> Result<LogicalCarrierUsageV1, CapacityModelError> {
    checked_capacity_integer_v1(missing_committed_bytes, "missing committed bytes")
        .map_err(map_arithmetic_error)?;
    checked_capacity_integer_v1(active_queue_entries, "active queue entries")
        .map_err(map_arithmetic_error)?;
    if bootstrap_carrier_bytes == 0 {
        return Err(CapacityModelError::ZeroLogicalCarrierCharge {
            carrier: "bootstrap",
        });
    }
    if global_refusal_carrier_bytes == 0 {
        return Err(CapacityModelError::ZeroLogicalCarrierCharge {
            carrier: "global_refusal",
        });
    }
    for charge in retained_allocation_charges {
        if *charge == 0 {
            return Err(CapacityModelError::ZeroLogicalCarrierCharge {
                carrier: "retained_allocation",
            });
        }
    }
    for charge in charged_orphan_charges {
        if *charge == 0 {
            return Err(CapacityModelError::ZeroLogicalCarrierCharge {
                carrier: "charged_orphan",
            });
        }
    }
    let retained_allocation_bytes = checked_sum(
        retained_allocation_charges.iter().copied(),
        "retained allocation charges",
    )?;
    let charged_orphan_bytes = checked_sum(
        charged_orphan_charges.iter().copied(),
        "charged orphan charges",
    )?;
    let contract_usage = CapacityUsageComponentsV1 {
        bootstrap_integrity_carrier_bytes: bootstrap_carrier_bytes,
        global_prelaunch_refusal_bytes: global_refusal_carrier_bytes,
        matched_retained_bytes: retained_allocation_bytes,
        physical_orphan_bytes: charged_orphan_bytes,
        missing_committed_bytes,
        active_queue_entries,
    };
    let logical_preallocated_carrier_bytes =
        contract_capacity_usage_v1(&contract_usage).map_err(map_arithmetic_error)?;
    Ok(LogicalCarrierUsageV1 {
        bootstrap_carrier_bytes,
        global_refusal_carrier_bytes,
        retained_allocation_bytes,
        charged_orphan_bytes,
        missing_committed_bytes,
        logical_preallocated_carrier_bytes,
        active_queue_entries,
    })
}

/// Compute checked `post = U + candidate_T`.
pub fn checked_post_allocation_usage_v1(
    usage: &LogicalCarrierUsageV1,
    candidate_retained_charge_bytes: u64,
) -> Result<u64, CapacityModelError> {
    contract_capacity_post_usage_v1(
        usage.logical_preallocated_carrier_bytes,
        candidate_retained_charge_bytes,
    )
    .map_err(map_arithmetic_error)
}

/// The installed logical capacity policy used by the pure evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityPolicyV1 {
    /// Complete logical length of preallocated canonical carriers.
    pub total_bytes: u64,
    /// Backpressure classification boundary; not a second total.
    pub high_watermark_bytes: u64,
    /// Exact required `P`.
    pub protected_failure_receipt_bytes: u64,
    /// Limit applied to `max(S, V)`.
    pub maximum_single_execution_closure_bytes: u64,
    /// Maximum active queue occurrences.
    pub maximum_queue_entries: u64,
}

impl CapacityPolicyV1 {
    /// Mirror the closed relations already ratified by
    /// `nq.buffer_delivery_policy.v1`.
    ///
    /// These are contract correspondence checks, not Store-owned policy.
    pub fn validate(&self) -> Result<(), CapacityModelError> {
        for (value, operation) in [
            (self.total_bytes, "capacity policy total bytes"),
            (
                self.high_watermark_bytes,
                "capacity policy high-watermark bytes",
            ),
            (
                self.protected_failure_receipt_bytes,
                "capacity policy protected-failure bytes",
            ),
            (
                self.maximum_single_execution_closure_bytes,
                "capacity policy single-execution bytes",
            ),
            (
                self.maximum_queue_entries,
                "capacity policy maximum queue entries",
            ),
        ] {
            checked_capacity_integer_v1(value, operation).map_err(map_arithmetic_error)?;
        }
        if self.protected_failure_receipt_bytes == 0 {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "protected failure receipt bytes are zero",
            ));
        }
        if self.high_watermark_bytes == 0 {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "high watermark bytes are zero",
            ));
        }
        if self.total_bytes == 0 {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "total bytes are zero",
            ));
        }
        if self.protected_failure_receipt_bytes >= self.high_watermark_bytes {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "protected failure bytes are not below the high watermark",
            ));
        }
        if self.high_watermark_bytes >= self.total_bytes {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "high watermark is not below total bytes",
            ));
        }
        if self.maximum_single_execution_closure_bytes == 0 {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "maximum single-execution closure bytes are zero",
            ));
        }
        if self.maximum_queue_entries == 0 {
            return Err(CapacityModelError::InvalidCapacityPolicy(
                "maximum queue entries are zero",
            ));
        }
        Ok(())
    }
}

/// Classification relative to the high-watermark boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HighWatermarkClassificationV1 {
    /// Logical carrier use is strictly below the watermark.
    Below,
    /// Logical carrier use equals or exceeds the watermark.
    AtOrAbove,
}

/// Closed reasons that a pure candidate is outside logical capacity limits.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLimitRefusalV1 {
    /// `max(S, V)` exceeds the installed single-execution limit.
    MaximumSingleExecutionClosureExceeded,
    /// Active plus newly reserved queue occurrences exceed the limit.
    MaximumQueueEntriesExceeded,
    /// `U + T` exceeds the installed logical carrier total.
    LogicalPreallocatedCarrierTotalExceeded,
}

/// Pure arithmetic disposition; never an allocation-success token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityEvaluationDispositionV1 {
    /// All logical arithmetic limits permit a later physical allocation
    /// attempt.
    WithinLogicalLimits,
    /// One or more closed logical limits refused the candidate.
    Refused,
}

/// Complete pure evaluation of one candidate against one usage snapshot.
///
/// Its fields are deliberately private. A caller can inspect a value returned
/// by [`evaluate_capacity_v1`], but cannot forge a favorable disposition and
/// pass it onward as an allocation capability:
///
/// ```compile_fail
/// use nq_store::{
///     CapacityEvaluationDispositionV1, CapacityEvaluationV1,
///     HighWatermarkClassificationV1,
/// };
///
/// let _forged = CapacityEvaluationV1 {
///     semantic_sum_bytes: 1,
///     single_execution_bound_bytes: 1,
///     used_before_bytes: 1,
///     candidate_retained_charge_bytes: 1,
///     used_after_bytes: 2,
///     used_before_watermark: HighWatermarkClassificationV1::Below,
///     used_after_watermark: HighWatermarkClassificationV1::Below,
///     queue_entries_before: 0,
///     queue_entries_reserved: 0,
///     queue_entries_after: 0,
///     disposition: CapacityEvaluationDispositionV1::WithinLogicalLimits,
///     refusal_reasons: Vec::new(),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityEvaluationV1 {
    /// Exact semantic `S`.
    semantic_sum_bytes: u64,
    /// `max(S, V)`.
    single_execution_bound_bytes: u64,
    /// `U`.
    used_before_bytes: u64,
    /// Candidate `T`.
    candidate_retained_charge_bytes: u64,
    /// Checked `U + T`.
    used_after_bytes: u64,
    /// Classification of `U`.
    used_before_watermark: HighWatermarkClassificationV1,
    /// Classification of `U + T`.
    used_after_watermark: HighWatermarkClassificationV1,
    /// Active queue entries before the candidate.
    queue_entries_before: u64,
    /// Exact queue occurrences reserved by the candidate.
    queue_entries_reserved: u64,
    /// Checked active queue entries after reservation.
    queue_entries_after: u64,
    /// Pure arithmetic disposition.
    disposition: CapacityEvaluationDispositionV1,
    /// All violated logical limits in stable enum order.
    refusal_reasons: Vec<CapacityLimitRefusalV1>,
}

impl CapacityEvaluationV1 {
    /// Exact semantic `S`.
    #[must_use]
    pub const fn semantic_sum_bytes(&self) -> u64 {
        self.semantic_sum_bytes
    }

    /// `max(S, V)`.
    #[must_use]
    pub const fn single_execution_bound_bytes(&self) -> u64 {
        self.single_execution_bound_bytes
    }

    /// Logical usage `U` before the candidate.
    #[must_use]
    pub const fn used_before_bytes(&self) -> u64 {
        self.used_before_bytes
    }

    /// Candidate retained charge `T`.
    #[must_use]
    pub const fn candidate_retained_charge_bytes(&self) -> u64 {
        self.candidate_retained_charge_bytes
    }

    /// Checked post-candidate usage `U + T`.
    #[must_use]
    pub const fn used_after_bytes(&self) -> u64 {
        self.used_after_bytes
    }

    /// Watermark classification before the candidate.
    #[must_use]
    pub const fn used_before_watermark(&self) -> HighWatermarkClassificationV1 {
        self.used_before_watermark
    }

    /// Watermark classification after the candidate.
    #[must_use]
    pub const fn used_after_watermark(&self) -> HighWatermarkClassificationV1 {
        self.used_after_watermark
    }

    /// Active queue occurrences before the candidate.
    #[must_use]
    pub const fn queue_entries_before(&self) -> u64 {
        self.queue_entries_before
    }

    /// Queue occurrences reserved by the candidate.
    #[must_use]
    pub const fn queue_entries_reserved(&self) -> u64 {
        self.queue_entries_reserved
    }

    /// Checked queue occurrences after the candidate.
    #[must_use]
    pub const fn queue_entries_after(&self) -> u64 {
        self.queue_entries_after
    }

    /// Pure arithmetic disposition.
    #[must_use]
    pub const fn disposition(&self) -> CapacityEvaluationDispositionV1 {
        self.disposition
    }

    /// Stable ordered logical-limit refusals.
    #[must_use]
    pub fn refusal_reasons(&self) -> &[CapacityLimitRefusalV1] {
        &self.refusal_reasons
    }
}

/// Compute the checked single-execution surface `max(S, V)`.
///
/// Both operands and the returned maximum remain inside the exact
/// I-JSON/JCS integer domain.
pub fn single_execution_bound_v1(
    semantic_sum_bytes: u64,
    final_closure_payload_bytes: u64,
) -> Result<u64, CapacityModelError> {
    contract_capacity_single_execution_bound_v1(semantic_sum_bytes, final_closure_payload_bytes)
        .map_err(map_arithmetic_error)
}

/// Classify one exact logical usage against the installed high watermark.
pub fn classify_high_watermark_v1(
    logical_preallocated_carrier_bytes: u64,
    high_watermark_bytes: u64,
) -> Result<HighWatermarkClassificationV1, CapacityModelError> {
    contract_classify_capacity_high_watermark_v1(
        logical_preallocated_carrier_bytes,
        high_watermark_bytes,
    )
    .map(contract_watermark)
    .map_err(map_arithmetic_error)
}

const fn contract_watermark(
    value: ContractCapacityWatermarkClassificationV1,
) -> HighWatermarkClassificationV1 {
    match value {
        ContractCapacityWatermarkClassificationV1::Below => HighWatermarkClassificationV1::Below,
        ContractCapacityWatermarkClassificationV1::AtOrAbove => {
            HighWatermarkClassificationV1::AtOrAbove
        }
    }
}

/// Evaluate one already-derived carrier map against logical policy limits.
///
/// The semantic declaration is rechecked here so an evaluation cannot be
/// detached from its exact reservation.  `WithinLogicalLimits` means only
/// that a separately governed physical allocation attempt may be considered.
pub fn evaluate_capacity_v1(
    policy: &CapacityPolicyV1,
    semantic: &SemanticComponentBoundsV1,
    total_required_bytes: u64,
    reserved_bytes: u64,
    carriers: &CustodyCarrierMapV1,
    usage: &LogicalCarrierUsageV1,
) -> Result<CapacityEvaluationV1, CapacityModelError> {
    policy.validate()?;
    let semantic_sum_bytes =
        validate_exact_semantic_reservation_v1(semantic, total_required_bytes, reserved_bytes)?;
    if semantic_sum_bytes != carriers.semantic_sum_bytes {
        return Err(CapacityModelError::SemanticTotalMismatch {
            declared_bytes: carriers.semantic_sum_bytes,
            computed_bytes: semantic_sum_bytes,
        });
    }

    let contract_usage = CapacityUsageComponentsV1 {
        bootstrap_integrity_carrier_bytes: usage.bootstrap_carrier_bytes,
        global_prelaunch_refusal_bytes: usage.global_refusal_carrier_bytes,
        matched_retained_bytes: usage.retained_allocation_bytes,
        physical_orphan_bytes: usage.charged_orphan_bytes,
        missing_committed_bytes: usage.missing_committed_bytes,
        active_queue_entries: usage.active_queue_entries,
    };
    let contract_candidate = CapacityCandidateChargeV1 {
        arena_file_length_bytes: carriers.arena.file_length_bytes,
        canonical_record_extent_length_bytes: carriers.canonical_record_extent.extent_length_bytes,
        delivery_ledger_extent_length_bytes: carriers.delivery_ledger_extent_length_bytes(),
        final_closure_payload_bytes: carriers.arena.final_payload_bytes,
        protected_failure_payload_bytes: carriers.arena.failure_payload_bytes,
        queue_entries_reserved: carriers.queue_slots,
    };
    let contract_limits = CapacityLogicalLimitsV1 {
        total_bytes: policy.total_bytes,
        high_watermark_bytes: policy.high_watermark_bytes,
        protected_failure_receipt_bytes: policy.protected_failure_receipt_bytes,
        maximum_single_execution_closure_bytes: policy.maximum_single_execution_closure_bytes,
        maximum_queue_entries: policy.maximum_queue_entries,
    };
    let contract_evaluation = contract_logical_preallocated_custody_carriers_v1(
        &contract_semantic_components(semantic),
        &contract_usage,
        &contract_candidate,
        &contract_limits,
    )
    .map_err(map_arithmetic_error)?;
    let refusal_reasons = contract_evaluation
        .refusal_reasons()
        .iter()
        .copied()
        .map(contract_refusal)
        .collect();

    Ok(CapacityEvaluationV1 {
        semantic_sum_bytes: contract_evaluation.semantic_sum_bytes(),
        single_execution_bound_bytes: contract_evaluation.single_execution_bound_bytes(),
        used_before_bytes: contract_evaluation.logical_preallocated_carrier_bytes_before(),
        candidate_retained_charge_bytes: contract_evaluation.retained_charge_bytes(),
        used_after_bytes: contract_evaluation.logical_preallocated_carrier_bytes_after(),
        used_before_watermark: contract_watermark(contract_evaluation.used_before_watermark()),
        used_after_watermark: contract_watermark(contract_evaluation.used_after_watermark()),
        queue_entries_before: contract_evaluation.queue_entries_before(),
        queue_entries_reserved: contract_evaluation.queue_entries_reserved(),
        queue_entries_after: contract_evaluation.queue_entries_after(),
        disposition: match contract_evaluation.disposition() {
            ContractCapacityLogicalDispositionV1::WithinLogicalLimits => {
                CapacityEvaluationDispositionV1::WithinLogicalLimits
            }
            ContractCapacityLogicalDispositionV1::Refused => {
                CapacityEvaluationDispositionV1::Refused
            }
        },
        refusal_reasons,
    })
}

const fn contract_refusal(value: ContractCapacityLimitRefusalV1) -> CapacityLimitRefusalV1 {
    match value {
        ContractCapacityLimitRefusalV1::MaximumSingleExecutionClosureExceeded => {
            CapacityLimitRefusalV1::MaximumSingleExecutionClosureExceeded
        }
        ContractCapacityLimitRefusalV1::MaximumQueueEntriesExceeded => {
            CapacityLimitRefusalV1::MaximumQueueEntriesExceeded
        }
        ContractCapacityLimitRefusalV1::LogicalPreallocatedCarrierTotalExceeded => {
            CapacityLimitRefusalV1::LogicalPreallocatedCarrierTotalExceeded
        }
    }
}

/// Derive one deterministic, authority-neutral delivery queue occurrence key.
///
/// Identical inputs replay the same key.  Every verdict-relevant input is
/// domain separated by the host-role contract's single canonical derivation;
/// no artifact identity exists yet and no authorization is implied.
pub fn deterministic_queue_occurrence_key_v1(
    capacity_allocation_id: &Sha256Digest,
    request_occurrence_id: &Sha256Digest,
    destination_generation_id: &Sha256Digest,
    delivery_policy_generation_id: &Sha256Digest,
) -> Result<Sha256Digest, CapacityModelError> {
    capacity_queue_occurrence_identity(
        capacity_allocation_id,
        request_occurrence_id,
        destination_generation_id,
        delivery_policy_generation_id,
    )
    .map_err(|error| CapacityModelError::QueueOccurrenceEncoding(error.to_string()))
}

/// Require one preallocation delivery plan to correspond exactly to the
/// source-bound delivery set selected by the authority-neutral plan.
///
/// This check intentionally occurs before any allocation, queue occurrence,
/// or final-reservation identity exists. The expected requirement,
/// destinations, and policy generation can enter only through the opaque
/// contract-graph selection. A successful result grants no allocation,
/// reservation, launch, delivery, or action authority.
pub fn validate_preallocation_delivery_capacity_correspondence_v1(
    delivery: &DeliveryCapacityPlanV1,
    selection: &ReservationPlanDeliveryRequirementSelection,
) -> Result<(), CapacityModelError> {
    validate_delivery_capacity_source_correspondence_parts_v1(
        delivery,
        selection.requirement(),
        selection.destination_generation_ids(),
        selection.delivery_policy_generation_id(),
    )
}

/// Require one Store delivery plan and its queue occurrences to correspond
/// exactly to the completed allocation selected by the contract graph.
///
/// The expected set, policy, allocation, request occurrence, and derived
/// occurrence identities can enter only through the opaque contract-graph
/// selection. Construction of that selection also requires exactly one
/// inspectable final reservation realizing the neutral plan. This pure check
/// does not upgrade possession of that witness into allocation, delivery, or
/// action authority. Both expected and Store destination lists use the same
/// strict canonical digest order; a resealed reorder is therefore rejected.
pub fn validate_post_allocation_delivery_capacity_correspondence_v1(
    delivery: &DeliveryCapacityPlanV1,
    selection: &CapacityDeliveryRequirementSelection,
    queue_occurrence_ids: &[Sha256Digest],
) -> Result<(), CapacityModelError> {
    validate_delivery_capacity_correspondence_parts_v1(
        delivery,
        selection.requirement(),
        selection.destination_generation_ids(),
        selection.delivery_policy_generation_id(),
        &selection.allocation().record_id,
        selection.request_occurrence_id(),
        queue_occurrence_ids,
    )?;
    if queue_occurrence_ids != selection.expected_occurrence_ids() {
        return Err(CapacityModelError::InvalidDeliveryCorrespondence(
            "Store queue occurrences differ from the exact contract-graph selection",
        ));
    }
    Ok(())
}

fn validate_delivery_capacity_source_correspondence_parts_v1(
    delivery: &DeliveryCapacityPlanV1,
    expected_requirement: ContractDeliveryRequirementV1,
    expected_destination_generation_ids: &[Sha256Digest],
    expected_delivery_policy_generation_id: Option<&Sha256Digest>,
) -> Result<(), CapacityModelError> {
    delivery.validate()?;
    let expected_requirement = match expected_requirement {
        ContractDeliveryRequirementV1::NotRequired => DeliveryCapacityRequirementV1::NotRequired,
        ContractDeliveryRequirementV1::Required => DeliveryCapacityRequirementV1::Required,
    };
    if delivery.requirement != expected_requirement {
        return Err(CapacityModelError::InvalidDeliveryCorrespondence(
            "Store delivery requirement differs from the neutral plan",
        ));
    }
    if expected_destination_generation_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(CapacityModelError::InvalidDeliveryCorrespondence(
            "neutral-plan destinations are not unique and canonically sorted",
        ));
    }
    if delivery.destination_generation_ids.as_slice() != expected_destination_generation_ids {
        return Err(CapacityModelError::InvalidDeliveryCorrespondence(
            "Store destinations differ from the neutral-plan destination set or order",
        ));
    }
    if delivery.delivery_policy_generation_id.as_ref() != expected_delivery_policy_generation_id {
        return Err(CapacityModelError::InvalidDeliveryCorrespondence(
            "Store delivery-policy generation differs from the neutral plan",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_delivery_capacity_correspondence_parts_v1(
    delivery: &DeliveryCapacityPlanV1,
    expected_requirement: ContractDeliveryRequirementV1,
    expected_destination_generation_ids: &[Sha256Digest],
    expected_delivery_policy_generation_id: Option<&Sha256Digest>,
    capacity_allocation_id: &Sha256Digest,
    request_occurrence_id: &Sha256Digest,
    queue_occurrence_ids: &[Sha256Digest],
) -> Result<(), CapacityModelError> {
    validate_delivery_capacity_source_correspondence_parts_v1(
        delivery,
        expected_requirement,
        expected_destination_generation_ids,
        expected_delivery_policy_generation_id,
    )?;

    match delivery.requirement {
        DeliveryCapacityRequirementV1::NotRequired => {
            if !expected_destination_generation_ids.is_empty()
                || expected_delivery_policy_generation_id.is_some()
                || !queue_occurrence_ids.is_empty()
            {
                return Err(CapacityModelError::InvalidDeliveryCorrespondence(
                    "not_required does not have an exact empty delivery correspondence",
                ));
            }
        }
        DeliveryCapacityRequirementV1::Required => {
            let policy_generation_id = expected_delivery_policy_generation_id.ok_or(
                CapacityModelError::InvalidDeliveryCorrespondence(
                    "required delivery lacks the neutral-plan policy generation",
                ),
            )?;
            if queue_occurrence_ids.len() != expected_destination_generation_ids.len() {
                return Err(CapacityModelError::InvalidDeliveryCorrespondence(
                    "queue occurrence cardinality differs from the neutral-plan destination set",
                ));
            }
            for (index, destination_generation_id) in
                expected_destination_generation_ids.iter().enumerate()
            {
                let expected_occurrence = deterministic_queue_occurrence_key_v1(
                    capacity_allocation_id,
                    request_occurrence_id,
                    destination_generation_id,
                    policy_generation_id,
                )?;
                if queue_occurrence_ids[index] != expected_occurrence {
                    return Err(CapacityModelError::InvalidDeliveryCorrespondence(
                        "queue occurrence identity differs from its exact ordered destination",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).expect("digest")
    }

    fn semantic(delivery_bytes: u64) -> SemanticComponentBoundsV1 {
        SemanticComponentBoundsV1 {
            request_and_decision_bytes: 1_000,
            raw_evidence_bytes: 2_000,
            normalized_bytes: 3_000,
            projected_bytes: 4_000,
            diagnostic_artifact_bytes: 5_000,
            dependency_closure_bytes: 6_000,
            commit_checkpoint_overhead_bytes: 7_000,
            mandatory_delivery_ledger_bytes: delivery_bytes,
        }
    }

    fn payloads() -> CarrierPayloadBoundsV1 {
        CarrierPayloadBoundsV1 {
            dependency_payload_bytes: 6_100,
            raw_acquisition_payload_bytes: 2_100,
            projection_capsule_bound_bytes: 7_100,
            final_closure_payload_bytes: 12_100,
            canonical_record_payload_bytes: 8_100,
        }
    }

    fn required_delivery(payload_bytes: u64) -> DeliveryCapacityPlanV1 {
        DeliveryCapacityPlanV1::required(vec![digest('a'), digest('b')], digest('c'), payload_bytes)
            .expect("required delivery")
    }

    fn policy(total_bytes: u64, high_watermark_bytes: u64) -> CapacityPolicyV1 {
        CapacityPolicyV1 {
            total_bytes,
            high_watermark_bytes,
            protected_failure_receipt_bytes: 8_192,
            maximum_single_execution_closure_bytes: 100_000,
            maximum_queue_entries: 4,
        }
    }

    fn carrier_policy() -> CapacityPolicyV1 {
        policy(1_000_000, 500_000)
    }

    #[test]
    fn cap_h01_semantic_total_and_reservation_are_exact() {
        let bounds = semantic(8_000);
        let sum = checked_semantic_sum_v1(&bounds).expect("semantic sum");
        assert_eq!(sum, 36_000);
        assert_eq!(
            validate_exact_semantic_reservation_v1(&bounds, sum, sum),
            Ok(sum)
        );
        assert!(matches!(
            validate_exact_semantic_reservation_v1(&bounds, sum - 1, sum),
            Err(CapacityModelError::SemanticTotalMismatch { .. })
        ));
        assert!(matches!(
            validate_exact_semantic_reservation_v1(&bounds, sum + 1, sum),
            Err(CapacityModelError::SemanticTotalMismatch { .. })
        ));
        assert!(matches!(
            validate_exact_semantic_reservation_v1(&bounds, sum, sum - 1),
            Err(CapacityModelError::SemanticReservationMismatch { .. })
        ));
        assert!(matches!(
            validate_exact_semantic_reservation_v1(&bounds, sum, sum + 1),
            Err(CapacityModelError::SemanticReservationMismatch { .. })
        ));

        let overflow = SemanticComponentBoundsV1 {
            request_and_decision_bytes: u64::MAX,
            ..SemanticComponentBoundsV1 {
                request_and_decision_bytes: 0,
                raw_evidence_bytes: 1,
                normalized_bytes: 0,
                projected_bytes: 0,
                diagnostic_artifact_bytes: 0,
                dependency_closure_bytes: 0,
                commit_checkpoint_overhead_bytes: 0,
                mandatory_delivery_ledger_bytes: 0,
            }
        };
        assert!(matches!(
            checked_semantic_sum_v1(&overflow),
            Err(CapacityModelError::UnsafeInteger("semantic component sum"))
        ));
    }

    #[test]
    fn every_serialized_capacity_integer_closes_at_the_i_json_boundary() {
        let maximum = CAPACITY_IJSON_SAFE_INTEGER_MAX_V1;
        let successor = maximum + 1;
        let maximum_semantic = SemanticComponentBoundsV1 {
            request_and_decision_bytes: maximum,
            raw_evidence_bytes: 0,
            normalized_bytes: 0,
            projected_bytes: 0,
            diagnostic_artifact_bytes: 0,
            dependency_closure_bytes: 0,
            commit_checkpoint_overhead_bytes: 0,
            mandatory_delivery_ledger_bytes: 0,
        };
        assert_eq!(
            validate_exact_semantic_reservation_v1(&maximum_semantic, maximum, maximum),
            Ok(maximum)
        );
        let unsafe_semantic = SemanticComponentBoundsV1 {
            request_and_decision_bytes: successor,
            ..maximum_semantic
        };
        assert!(matches!(
            checked_semantic_sum_v1(&unsafe_semantic),
            Err(CapacityModelError::UnsafeInteger("semantic component sum"))
        ));
        assert_eq!(
            validate_carrier_payload_fit_v1(CustodyCarrierRoleV1::FinalClosure, maximum, maximum,),
            Ok(())
        );
        assert!(matches!(
            validate_carrier_payload_fit_v1(
                CustodyCarrierRoleV1::FinalClosure,
                successor,
                successor,
            ),
            Err(CapacityModelError::UnsafeInteger(
                "required carrier payload"
            ))
        ));

        let delivery = DeliveryCapacityPlanV1 {
            requirement: DeliveryCapacityRequirementV1::Required,
            destination_generation_ids: vec![digest('a')],
            delivery_policy_generation_id: Some(digest('b')),
            delivery_ledger_payload_bytes: maximum,
            queue_slots: 1,
        };
        assert_eq!(delivery.validate(), Ok(()));
        assert!(matches!(
            DeliveryCapacityPlanV1 {
                delivery_ledger_payload_bytes: successor,
                ..delivery
            }
            .validate(),
            Err(CapacityModelError::UnsafeInteger(
                "delivery-ledger payload capacity"
            ))
        ));

        let safe_policy = CapacityPolicyV1 {
            total_bytes: maximum,
            high_watermark_bytes: maximum - 1,
            protected_failure_receipt_bytes: 1,
            maximum_single_execution_closure_bytes: maximum,
            maximum_queue_entries: maximum,
        };
        assert_eq!(safe_policy.validate(), Ok(()));
        assert!(matches!(
            CapacityPolicyV1 {
                total_bytes: successor,
                ..safe_policy
            }
            .validate(),
            Err(CapacityModelError::UnsafeInteger(
                "capacity policy total bytes"
            ))
        ));

        assert!(
            checked_logical_carrier_usage_v1(1, 1, &[], &[], 0, maximum).is_ok(),
            "the exact queue-count ceiling is representable"
        );
        assert!(matches!(
            checked_logical_carrier_usage_v1(1, 1, &[], &[], 0, successor),
            Err(CapacityModelError::UnsafeInteger("active queue entries"))
        ));
        let maximum_aggregate = checked_logical_carrier_usage_v1(1, 1, &[], &[], maximum - 2, 0)
            .expect("exact aggregate ceiling");
        assert_eq!(
            maximum_aggregate.logical_preallocated_carrier_bytes(),
            maximum
        );
        assert!(matches!(
            checked_logical_carrier_usage_v1(1, 1, &[], &[], maximum, 0),
            Err(CapacityModelError::UnsafeInteger(
                "logical preallocated carrier usage"
            ))
        ));
        assert!(matches!(
            checked_logical_carrier_usage_v1(1, 1, &[], &[], successor, 0),
            Err(CapacityModelError::UnsafeInteger("missing committed bytes"))
        ));
    }

    #[test]
    fn capacity_evaluation_is_not_accepted_by_any_store_effect_surface() {
        let store_root = include_str!("lib.rs");
        assert_eq!(
            store_root.matches("CapacityEvaluationV1").count(),
            1,
            "the Store root may reexport the read-only result but no Store effect may accept it"
        );
        for (name, source) in [
            ("custody arena", include_str!("custody_arena.rs")),
            ("governed custody", include_str!("governed_custody.rs")),
            (
                "projection capsule",
                include_str!("governed_projection_capsule.rs"),
            ),
        ] {
            assert!(
                !source.contains("CapacityEvaluationV1"),
                "{name} acquired an injectable capacity-evaluation dependency"
            );
        }
    }

    #[test]
    fn arena_and_append_geometry_match_the_frozen_v1_formulas() {
        let arena = checked_arena_geometry_v1(3_073, 4_097, 8_193, 2_049).expect("arena geometry");
        assert_eq!(arena.dependency_header_offset, 8_192);
        assert_eq!(arena.dependency_payload_offset, 12_288);
        assert_eq!(arena.raw_header_offset, 16_384);
        assert_eq!(arena.raw_payload_offset, 20_480);
        assert_eq!(arena.final_header_offset, 28_672);
        assert_eq!(arena.final_payload_offset, 32_768);
        assert_eq!(arena.failure_header_offset, 45_056);
        assert_eq!(arena.failure_payload_offset, 49_152);
        assert_eq!(arena.file_length_bytes, 53_248);
        assert_eq!(arena.fixed_format_bytes, 24_576);
        assert_eq!(arena.alignment_bytes, 11_260);
        for offset in [
            arena.dependency_header_offset,
            arena.dependency_payload_offset,
            arena.raw_header_offset,
            arena.raw_payload_offset,
            arena.final_header_offset,
            arena.final_payload_offset,
            arena.failure_header_offset,
            arena.failure_payload_offset,
            arena.file_length_bytes,
        ] {
            assert_eq!(offset % CUSTODY_CAPACITY_ALIGNMENT_V1, 0);
        }

        let extent = checked_append_extent_geometry_v1(4_097).expect("extent geometry");
        assert_eq!(extent.superblock_0_offset, 0);
        assert_eq!(extent.superblock_1_offset, 4_096);
        assert_eq!(extent.extent_header_offset, 8_192);
        assert_eq!(extent.payload_offset, 12_288);
        assert_eq!(extent.extent_length_bytes, 20_480);
        assert_eq!(extent.fixed_format_bytes, 12_288);
        assert_eq!(extent.alignment_bytes, 4_095);
        assert_eq!(checked_bootstrap_carrier_length_v1(4_097), Ok(24_576));
    }

    #[test]
    fn geometry_refuses_zero_and_every_checked_overflow_edge() {
        assert!(matches!(
            checked_arena_geometry_v1(0, 1, 1, 1),
            Err(CapacityModelError::ZeroCarrierPayload {
                carrier: "dependency"
            })
        ));
        assert!(matches!(
            checked_arena_geometry_v1(u64::MAX, 1, 1, 1),
            Err(CapacityModelError::UnsafeInteger(_))
        ));
        assert!(matches!(
            checked_arena_geometry_v1(1, u64::MAX, 1, 1),
            Err(CapacityModelError::UnsafeInteger(_))
        ));
        assert!(matches!(
            checked_arena_geometry_v1(1, 1, u64::MAX, 1),
            Err(CapacityModelError::UnsafeInteger(_))
        ));
        assert!(matches!(
            checked_arena_geometry_v1(1, 1, 1, u64::MAX),
            Err(CapacityModelError::UnsafeInteger(_))
        ));
        assert!(matches!(
            checked_append_extent_geometry_v1(0),
            Err(CapacityModelError::ZeroCarrierPayload {
                carrier: "append_extent"
            })
        ));
        assert!(matches!(
            checked_append_extent_geometry_v1(u64::MAX),
            Err(CapacityModelError::UnsafeInteger(_))
        ));
    }

    #[test]
    fn cap_h02_and_h03_each_component_has_one_independent_carrier() {
        let semantic = semantic(8_000);
        let delivery = required_delivery(8_100);
        let exact =
            derive_custody_carrier_map_v1(&carrier_policy(), &semantic, &payloads(), &delivery)
                .expect("exact carrier map");
        assert_eq!(exact.semantic_sum_bytes, 36_000);
        assert_eq!(exact.queue_slots, 2);
        assert_eq!(
            exact.arena.final_payload_bytes,
            payloads().final_closure_payload_bytes
        );
        assert_ne!(
            exact.arena.final_payload_bytes,
            exact
                .semantic_sum_bytes
                .checked_sub(semantic.raw_evidence_bytes)
                .and_then(|residue| residue.checked_sub(semantic.dependency_closure_bytes))
                .expect("legacy arithmetic residue")
        );
        assert_eq!(
            exact.retained_charge_bytes,
            exact.arena.file_length_bytes
                + exact.canonical_record_extent.extent_length_bytes
                + exact
                    .delivery_ledger_extent
                    .expect("delivery extent")
                    .extent_length_bytes
        );

        let hostile_bounds = [
            CarrierPayloadBoundsV1 {
                dependency_payload_bytes: semantic.dependency_closure_bytes - 1,
                ..payloads()
            },
            CarrierPayloadBoundsV1 {
                raw_acquisition_payload_bytes: semantic.raw_evidence_bytes - 1,
                ..payloads()
            },
            CarrierPayloadBoundsV1 {
                final_closure_payload_bytes: semantic.normalized_bytes
                    + semantic.projected_bytes
                    + semantic.diagnostic_artifact_bytes
                    - 1,
                ..payloads()
            },
            CarrierPayloadBoundsV1 {
                canonical_record_payload_bytes: semantic.request_and_decision_bytes
                    + semantic.commit_checkpoint_overhead_bytes
                    - 1,
                ..payloads()
            },
        ];
        for hostile in hostile_bounds {
            assert!(matches!(
                derive_custody_carrier_map_v1(&carrier_policy(), &semantic, &hostile, &delivery),
                Err(CapacityModelError::CarrierBoundExceeded { .. })
            ));
        }
        let capsule_larger_than_final = CarrierPayloadBoundsV1 {
            projection_capsule_bound_bytes: payloads().final_closure_payload_bytes + 1,
            ..payloads()
        };
        assert!(matches!(
            derive_custody_carrier_map_v1(
                &carrier_policy(),
                &semantic,
                &capsule_larger_than_final,
                &delivery
            ),
            Err(CapacityModelError::CarrierBoundExceeded {
                carrier: "final_closure",
                ..
            })
        ));

        let short_delivery = required_delivery(semantic.mandatory_delivery_ledger_bytes - 1);
        assert!(matches!(
            derive_custody_carrier_map_v1(
                &carrier_policy(),
                &semantic,
                &payloads(),
                &short_delivery
            ),
            Err(CapacityModelError::CarrierBoundExceeded {
                carrier: "delivery_ledger",
                ..
            })
        ));
    }

    #[test]
    fn cap_h03_payload_fit_is_exact_and_cannot_borrow_slack() {
        for role in [
            CustodyCarrierRoleV1::DependencyClosure,
            CustodyCarrierRoleV1::RawAcquisition,
            CustodyCarrierRoleV1::FinalClosure,
            CustodyCarrierRoleV1::CanonicalRecord,
            CustodyCarrierRoleV1::DeliveryLedger,
        ] {
            assert_eq!(validate_carrier_payload_fit_v1(role, 4_096, 4_096), Ok(()));
            assert!(matches!(
                validate_carrier_payload_fit_v1(role, 4_097, 4_096),
                Err(CapacityModelError::CarrierBoundExceeded { .. })
            ));
        }
    }

    #[test]
    fn cap_h04_and_h07_delivery_forms_are_closed() {
        let no_delivery_semantic = semantic(0);
        let no_delivery = derive_custody_carrier_map_v1(
            &carrier_policy(),
            &no_delivery_semantic,
            &payloads(),
            &DeliveryCapacityPlanV1::not_required(),
        )
        .expect("not-required map");
        assert_eq!(no_delivery.queue_slots, 0);
        assert_eq!(no_delivery.delivery_ledger_extent, None);
        assert_eq!(no_delivery.delivery_ledger_extent_length_bytes(), 0);

        assert!(matches!(
            derive_custody_carrier_map_v1(
                &carrier_policy(),
                &semantic(1),
                &payloads(),
                &DeliveryCapacityPlanV1::not_required()
            ),
            Err(CapacityModelError::InvalidDeliveryPlan(
                "not_required has nonzero semantic delivery bytes"
            ))
        ));
        assert!(matches!(
            derive_custody_carrier_map_v1(
                &carrier_policy(),
                &no_delivery_semantic,
                &payloads(),
                &required_delivery(1)
            ),
            Err(CapacityModelError::InvalidDeliveryPlan(
                "required delivery has zero semantic delivery bytes"
            ))
        ));

        let malformed = DeliveryCapacityPlanV1 {
            requirement: DeliveryCapacityRequirementV1::Required,
            destination_generation_ids: vec![digest('a')],
            delivery_policy_generation_id: Some(digest('b')),
            delivery_ledger_payload_bytes: 1,
            queue_slots: 0,
        };
        assert!(matches!(
            malformed.validate(),
            Err(CapacityModelError::InvalidDeliveryPlan(
                "required delivery queue slots differ from destination generations"
            ))
        ));
        let malformed_not_required = DeliveryCapacityPlanV1 {
            delivery_ledger_payload_bytes: 1,
            ..DeliveryCapacityPlanV1::not_required()
        };
        assert!(matches!(
            malformed_not_required.validate(),
            Err(CapacityModelError::InvalidDeliveryPlan(
                "not_required has delivery-ledger bytes"
            ))
        ));
        let duplicate = DeliveryCapacityPlanV1 {
            requirement: DeliveryCapacityRequirementV1::Required,
            destination_generation_ids: vec![digest('a'), digest('a')],
            delivery_policy_generation_id: Some(digest('b')),
            delivery_ledger_payload_bytes: 1,
            queue_slots: 2,
        };
        assert!(matches!(
            duplicate.validate(),
            Err(CapacityModelError::DuplicateDeliveryDestination(_))
        ));
    }

    #[test]
    fn cap_h05_queue_exact_fit_passes_and_one_over_refuses() {
        let semantic = semantic(8_000);
        let sum = checked_semantic_sum_v1(&semantic).expect("sum");
        let carriers = derive_custody_carrier_map_v1(
            &carrier_policy(),
            &semantic,
            &payloads(),
            &required_delivery(8_100),
        )
        .expect("carriers");
        let usage = checked_logical_carrier_usage_v1(4_096, 4_096, &[], &[], 0, 2).expect("usage");
        let exact_total = usage.logical_preallocated_carrier_bytes + carriers.retained_charge_bytes;
        let exact = evaluate_capacity_v1(
            &policy(exact_total, exact_total - 1),
            &semantic,
            sum,
            sum,
            &carriers,
            &usage,
        )
        .expect("exact queue evaluation");
        assert_eq!(exact.queue_entries_after(), 4);
        assert_eq!(
            exact.disposition(),
            CapacityEvaluationDispositionV1::WithinLogicalLimits
        );

        let over_usage = LogicalCarrierUsageV1 {
            active_queue_entries: 3,
            ..usage
        };
        let over = evaluate_capacity_v1(
            &policy(exact_total, exact_total - 1),
            &semantic,
            sum,
            sum,
            &carriers,
            &over_usage,
        )
        .expect("queue refusal");
        assert_eq!(over.queue_entries_after(), 5);
        assert!(
            over.refusal_reasons()
                .contains(&CapacityLimitRefusalV1::MaximumQueueEntriesExceeded)
        );
    }

    #[test]
    fn cap_h06_queue_occurrence_replay_is_deterministic_and_input_bound() {
        let allocation = digest('a');
        let request = digest('b');
        let destination = digest('c');
        let policy = digest('d');
        let key =
            deterministic_queue_occurrence_key_v1(&allocation, &request, &destination, &policy)
                .expect("queue key");
        assert_eq!(
            deterministic_queue_occurrence_key_v1(&allocation, &request, &destination, &policy),
            Ok(key.clone())
        );
        for hostile in [
            deterministic_queue_occurrence_key_v1(&digest('e'), &request, &destination, &policy),
            deterministic_queue_occurrence_key_v1(&allocation, &digest('e'), &destination, &policy),
            deterministic_queue_occurrence_key_v1(&allocation, &request, &digest('e'), &policy),
            deterministic_queue_occurrence_key_v1(
                &allocation,
                &request,
                &destination,
                &digest('e'),
            ),
        ] {
            assert_ne!(hostile.expect("hostile key"), key);
        }
    }

    fn queue_occurrences(
        allocation: &Sha256Digest,
        request: &Sha256Digest,
        destinations: &[Sha256Digest],
        policy: &Sha256Digest,
    ) -> Vec<Sha256Digest> {
        destinations
            .iter()
            .map(|destination| {
                deterministic_queue_occurrence_key_v1(allocation, request, destination, policy)
                    .expect("queue occurrence")
            })
            .collect()
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exact source-set hostiles stay together as one correspondence matrix.
    fn delivery_capacity_correspondence_requires_exact_source_bound_order_and_occurrences() {
        let allocation = digest('a');
        let request = digest('b');
        let destinations = vec![digest('c'), digest('d')];
        let policy = digest('e');
        let delivery =
            DeliveryCapacityPlanV1::required(destinations.clone(), policy.clone(), 4_096)
                .expect("required delivery");
        let occurrences = queue_occurrences(&allocation, &request, &destinations, &policy);
        assert_eq!(
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::Required,
                &destinations,
                Some(&policy),
                &allocation,
                &request,
                &occurrences,
            ),
            Ok(())
        );

        let resealed_reorder = DeliveryCapacityPlanV1 {
            destination_generation_ids: vec![destinations[1].clone(), destinations[0].clone()],
            ..delivery.clone()
        };
        assert!(matches!(
            validate_delivery_capacity_correspondence_parts_v1(
                &resealed_reorder,
                ContractDeliveryRequirementV1::Required,
                &destinations,
                Some(&policy),
                &allocation,
                &request,
                &occurrences,
            ),
            Err(CapacityModelError::InvalidDeliveryPlan(
                "required delivery destinations are not in canonical sorted order"
            ))
        ));
        assert!(matches!(
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::Required,
                &[destinations[1].clone(), destinations[0].clone()],
                Some(&policy),
                &allocation,
                &request,
                &occurrences,
            ),
            Err(CapacityModelError::InvalidDeliveryCorrespondence(
                "neutral-plan destinations are not unique and canonically sorted"
            ))
        ));

        for substituted_destinations in [
            vec![destinations[0].clone()],
            vec![
                destinations[0].clone(),
                destinations[1].clone(),
                digest('f'),
            ],
            vec![destinations[0].clone(), digest('f')],
        ] {
            let substituted_occurrences =
                queue_occurrences(&allocation, &request, &substituted_destinations, &policy);
            let substituted =
                DeliveryCapacityPlanV1::required(substituted_destinations, policy.clone(), 4_096)
                    .expect("internally valid substituted delivery");
            assert!(matches!(
                validate_delivery_capacity_correspondence_parts_v1(
                    &substituted,
                    ContractDeliveryRequirementV1::Required,
                    &destinations,
                    Some(&policy),
                    &allocation,
                    &request,
                    &substituted_occurrences,
                ),
                Err(CapacityModelError::InvalidDeliveryCorrespondence(
                    "Store destinations differ from the neutral-plan destination set or order"
                ))
            ));
        }

        let duplicate = DeliveryCapacityPlanV1 {
            destination_generation_ids: vec![destinations[0].clone(), destinations[0].clone()],
            ..delivery.clone()
        };
        assert!(matches!(
            validate_delivery_capacity_correspondence_parts_v1(
                &duplicate,
                ContractDeliveryRequirementV1::Required,
                &destinations,
                Some(&policy),
                &allocation,
                &request,
                &occurrences,
            ),
            Err(CapacityModelError::DuplicateDeliveryDestination(_))
        ));

        assert!(matches!(
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::Required,
                &destinations,
                Some(&digest('f')),
                &allocation,
                &request,
                &occurrences,
            ),
            Err(CapacityModelError::InvalidDeliveryCorrespondence(
                "Store delivery-policy generation differs from the neutral plan"
            ))
        ));
        let mut wrong_occurrences = occurrences.clone();
        wrong_occurrences.swap(0, 1);
        assert!(matches!(
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::Required,
                &destinations,
                Some(&policy),
                &allocation,
                &request,
                &wrong_occurrences,
            ),
            Err(CapacityModelError::InvalidDeliveryCorrespondence(
                "queue occurrence identity differs from its exact ordered destination"
            ))
        ));
        assert!(matches!(
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::Required,
                &destinations,
                Some(&policy),
                &allocation,
                &request,
                &occurrences[..1],
            ),
            Err(CapacityModelError::InvalidDeliveryCorrespondence(
                "queue occurrence cardinality differs from the neutral-plan destination set"
            ))
        ));
        assert!(matches!(
            validate_delivery_capacity_source_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::NotRequired,
                &[],
                None,
            ),
            Err(CapacityModelError::InvalidDeliveryCorrespondence(
                "Store delivery requirement differs from the neutral plan"
            ))
        ));
    }

    #[test]
    fn delivery_capacity_correspondence_preserves_exact_not_required_form() {
        let allocation = digest('a');
        let request = digest('b');
        let delivery = DeliveryCapacityPlanV1::not_required();
        assert_eq!(
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::NotRequired,
                &[],
                None,
                &allocation,
                &request,
                &[],
            ),
            Ok(())
        );
        for result in [
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::NotRequired,
                &[digest('c')],
                None,
                &allocation,
                &request,
                &[],
            ),
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::NotRequired,
                &[],
                Some(&digest('d')),
                &allocation,
                &request,
                &[],
            ),
            validate_delivery_capacity_correspondence_parts_v1(
                &delivery,
                ContractDeliveryRequirementV1::NotRequired,
                &[],
                None,
                &allocation,
                &request,
                &[digest('e')],
            ),
        ] {
            assert!(matches!(
                result,
                Err(CapacityModelError::InvalidDeliveryCorrespondence(_))
            ));
        }
    }

    #[test]
    fn cap_h08_aggregate_exact_fit_and_excess_are_distinct() {
        let semantic = semantic(0);
        let sum = checked_semantic_sum_v1(&semantic).expect("sum");
        let carriers = derive_custody_carrier_map_v1(
            &carrier_policy(),
            &semantic,
            &payloads(),
            &DeliveryCapacityPlanV1::not_required(),
        )
        .expect("carriers");
        let usage = checked_logical_carrier_usage_v1(16_384, 12_288, &[100], &[200], 300, 0)
            .expect("usage");
        assert_eq!(
            usage.logical_preallocated_carrier_bytes,
            16_384 + 12_288 + 100 + 200 + 300
        );
        assert_eq!(usage.missing_committed_bytes(), 300);
        let exact_total = usage.logical_preallocated_carrier_bytes + carriers.retained_charge_bytes;
        let exact = evaluate_capacity_v1(
            &policy(exact_total, exact_total - 1),
            &semantic,
            sum,
            sum,
            &carriers,
            &usage,
        )
        .expect("exact fit");
        assert_eq!(
            exact.disposition(),
            CapacityEvaluationDispositionV1::WithinLogicalLimits
        );
        assert_eq!(
            exact.used_after_watermark(),
            HighWatermarkClassificationV1::AtOrAbove
        );

        let one_over = evaluate_capacity_v1(
            &policy(exact_total - 1, exact_total - 2),
            &semantic,
            sum,
            sum,
            &carriers,
            &usage,
        )
        .expect("one-byte refusal");
        assert!(
            one_over
                .refusal_reasons()
                .contains(&CapacityLimitRefusalV1::LogicalPreallocatedCarrierTotalExceeded)
        );

        let usage_with_one_more_carrier = checked_logical_carrier_usage_v1(
            usage.bootstrap_carrier_bytes,
            usage.global_refusal_carrier_bytes,
            &[100, carriers.retained_charge_bytes],
            &[200],
            usage.missing_committed_bytes,
            0,
        )
        .expect("larger usage");
        let carrier_over = evaluate_capacity_v1(
            &policy(exact_total, exact_total - 1),
            &semantic,
            sum,
            sum,
            &carriers,
            &usage_with_one_more_carrier,
        )
        .expect("one-carrier refusal");
        assert!(
            carrier_over
                .refusal_reasons()
                .contains(&CapacityLimitRefusalV1::LogicalPreallocatedCarrierTotalExceeded)
        );
    }

    #[test]
    fn store_projection_matches_shared_aggregate_law_including_missing_committed() {
        let semantic = semantic(0);
        let sum = checked_semantic_sum_v1(&semantic).expect("sum");
        let carriers = derive_custody_carrier_map_v1(
            &carrier_policy(),
            &semantic,
            &payloads(),
            &DeliveryCapacityPlanV1::not_required(),
        )
        .expect("carriers");
        let usage = checked_logical_carrier_usage_v1(16_384, 12_288, &[100, 200], &[300], 400, 2)
            .expect("usage");
        let exact_total =
            usage.logical_preallocated_carrier_bytes() + carriers.retained_charge_bytes();
        let policy = policy(exact_total, exact_total - 1);

        let store = evaluate_capacity_v1(&policy, &semantic, sum, sum, &carriers, &usage)
            .expect("Store projection");
        let shared = contract_logical_preallocated_custody_carriers_v1(
            &contract_semantic_components(&semantic),
            &CapacityUsageComponentsV1 {
                bootstrap_integrity_carrier_bytes: usage.bootstrap_carrier_bytes(),
                global_prelaunch_refusal_bytes: usage.global_refusal_carrier_bytes(),
                matched_retained_bytes: usage.retained_allocation_bytes(),
                physical_orphan_bytes: usage.charged_orphan_bytes(),
                missing_committed_bytes: usage.missing_committed_bytes(),
                active_queue_entries: usage.active_queue_entries(),
            },
            &CapacityCandidateChargeV1 {
                arena_file_length_bytes: carriers.arena_file_length_bytes(),
                canonical_record_extent_length_bytes: carriers
                    .canonical_record_extent_length_bytes(),
                delivery_ledger_extent_length_bytes: carriers.delivery_ledger_extent_length_bytes(),
                final_closure_payload_bytes: carriers.arena().final_payload_bytes,
                protected_failure_payload_bytes: carriers.arena().failure_payload_bytes,
                queue_entries_reserved: carriers.queue_slots(),
            },
            &CapacityLogicalLimitsV1 {
                total_bytes: policy.total_bytes,
                high_watermark_bytes: policy.high_watermark_bytes,
                protected_failure_receipt_bytes: policy.protected_failure_receipt_bytes,
                maximum_single_execution_closure_bytes: policy
                    .maximum_single_execution_closure_bytes,
                maximum_queue_entries: policy.maximum_queue_entries,
            },
        )
        .expect("shared aggregate");

        assert_eq!(
            shared.logical_preallocated_carrier_bytes_before(),
            16_384 + 12_288 + 100 + 200 + 300 + 400
        );
        assert_eq!(store.semantic_sum_bytes(), shared.semantic_sum_bytes());
        assert_eq!(
            store.single_execution_bound_bytes(),
            shared.single_execution_bound_bytes()
        );
        assert_eq!(
            store.used_before_bytes(),
            shared.logical_preallocated_carrier_bytes_before()
        );
        assert_eq!(
            store.candidate_retained_charge_bytes(),
            shared.retained_charge_bytes()
        );
        assert_eq!(
            store.used_after_bytes(),
            shared.logical_preallocated_carrier_bytes_after()
        );
        assert_eq!(store.queue_entries_before(), shared.queue_entries_before());
        assert_eq!(
            store.queue_entries_reserved(),
            shared.queue_entries_reserved()
        );
        assert_eq!(store.queue_entries_after(), shared.queue_entries_after());
        assert_eq!(
            store.used_before_watermark(),
            contract_watermark(shared.used_before_watermark())
        );
        assert_eq!(
            store.used_after_watermark(),
            contract_watermark(shared.used_after_watermark())
        );
        assert_eq!(
            store.disposition(),
            CapacityEvaluationDispositionV1::WithinLogicalLimits
        );
        assert!(store.refusal_reasons().is_empty());
    }

    #[test]
    fn policy_derived_p_single_execution_and_high_watermark_rules_are_explicit() {
        assert_eq!(single_execution_bound_v1(10, 20), Ok(20));
        assert_eq!(single_execution_bound_v1(30, 20), Ok(30));
        assert_eq!(
            classify_high_watermark_v1(99, 100),
            Ok(HighWatermarkClassificationV1::Below)
        );
        assert_eq!(
            classify_high_watermark_v1(100, 100),
            Ok(HighWatermarkClassificationV1::AtOrAbove)
        );
        let successor = CAPACITY_IJSON_SAFE_INTEGER_MAX_V1 + 1;
        assert!(matches!(
            single_execution_bound_v1(successor, 1),
            Err(CapacityModelError::UnsafeInteger(
                "single-execution semantic sum"
            ))
        ));
        assert!(matches!(
            single_execution_bound_v1(1, successor),
            Err(CapacityModelError::UnsafeInteger(
                "single-execution final-closure payload"
            ))
        ));
        assert!(matches!(
            classify_high_watermark_v1(successor, 1),
            Err(CapacityModelError::UnsafeInteger(
                "high-watermark logical carrier usage"
            ))
        ));
        assert!(matches!(
            classify_high_watermark_v1(1, successor),
            Err(CapacityModelError::UnsafeInteger("high-watermark boundary"))
        ));

        let semantic = semantic(0);
        let sum = checked_semantic_sum_v1(&semantic).expect("sum");
        let carriers = derive_custody_carrier_map_v1(
            &carrier_policy(),
            &semantic,
            &payloads(),
            &DeliveryCapacityPlanV1::not_required(),
        )
        .expect("carriers");
        let usage = checked_logical_carrier_usage_v1(4_096, 4_096, &[], &[], 0, 0).expect("usage");
        let total = usage.logical_preallocated_carrier_bytes + carriers.retained_charge_bytes;

        assert_eq!(
            carriers.arena.failure_payload_bytes,
            carrier_policy().protected_failure_receipt_bytes
        );
        let mut substituted_policy = policy(total, total - 1);
        substituted_policy.protected_failure_receipt_bytes -= 1;
        assert!(matches!(
            evaluate_capacity_v1(&substituted_policy, &semantic, sum, sum, &carriers, &usage),
            Err(CapacityModelError::ProtectedFailurePolicyMismatch {
                carrier_bytes: 8_192,
                policy_bytes: 8_191,
            })
        ));

        let mut hostile_limit = policy(total, total - 1);
        hostile_limit.maximum_single_execution_closure_bytes =
            single_execution_bound_v1(sum, carriers.arena.final_payload_bytes)
                .expect("single-execution bound")
                - 1;
        let evaluation =
            evaluate_capacity_v1(&hostile_limit, &semantic, sum, sum, &carriers, &usage)
                .expect("limit refusal");
        assert_eq!(
            evaluation.refusal_reasons(),
            &[CapacityLimitRefusalV1::MaximumSingleExecutionClosureExceeded]
        );
    }

    #[test]
    fn retained_and_aggregate_arithmetic_refuse_overflow_and_zero_charges() {
        assert!(matches!(
            checked_retained_charge_v1(u64::MAX, 1, 0),
            Err(CapacityModelError::UnsafeInteger("arena_file"))
        ));
        assert!(matches!(
            checked_logical_carrier_usage_v1(1, 1, &[0], &[], 0, 0),
            Err(CapacityModelError::ZeroLogicalCarrierCharge {
                carrier: "retained_allocation"
            })
        ));
        assert!(matches!(
            checked_logical_carrier_usage_v1(u64::MAX, 1, &[], &[], 0, 0),
            Err(CapacityModelError::UnsafeInteger(
                "logical preallocated carrier usage"
            ))
        ));
        let usage = LogicalCarrierUsageV1 {
            bootstrap_carrier_bytes: 1,
            global_refusal_carrier_bytes: 1,
            retained_allocation_bytes: 0,
            charged_orphan_bytes: 0,
            missing_committed_bytes: 0,
            logical_preallocated_carrier_bytes: u64::MAX,
            active_queue_entries: 0,
        };
        assert!(matches!(
            checked_post_allocation_usage_v1(&usage, 1),
            Err(CapacityModelError::UnsafeInteger(
                "post-allocation logical carrier usage"
            ))
        ));
    }

    #[test]
    fn capacity_policy_relations_and_queue_overflow_fail_closed() {
        for hostile in [
            CapacityPolicyV1 {
                total_bytes: 10,
                high_watermark_bytes: 0,
                protected_failure_receipt_bytes: 1,
                maximum_single_execution_closure_bytes: 1,
                maximum_queue_entries: 1,
            },
            CapacityPolicyV1 {
                total_bytes: 10,
                high_watermark_bytes: 5,
                protected_failure_receipt_bytes: 5,
                maximum_single_execution_closure_bytes: 1,
                maximum_queue_entries: 1,
            },
            CapacityPolicyV1 {
                total_bytes: 10,
                high_watermark_bytes: 10,
                protected_failure_receipt_bytes: 1,
                maximum_single_execution_closure_bytes: 1,
                maximum_queue_entries: 1,
            },
        ] {
            assert!(matches!(
                hostile.validate(),
                Err(CapacityModelError::InvalidCapacityPolicy(_))
            ));
        }

        let semantic = semantic(8_000);
        let sum = checked_semantic_sum_v1(&semantic).expect("sum");
        let carriers = derive_custody_carrier_map_v1(
            &carrier_policy(),
            &semantic,
            &payloads(),
            &required_delivery(8_100),
        )
        .expect("carriers");
        let usage = checked_logical_carrier_usage_v1(
            4_096,
            4_096,
            &[],
            &[],
            0,
            CAPACITY_IJSON_SAFE_INTEGER_MAX_V1,
        )
        .expect("usage");
        assert!(matches!(
            evaluate_capacity_v1(
                &policy(
                    CAPACITY_IJSON_SAFE_INTEGER_MAX_V1,
                    CAPACITY_IJSON_SAFE_INTEGER_MAX_V1 - 1
                ),
                &semantic,
                sum,
                sum,
                &carriers,
                &usage
            ),
            Err(CapacityModelError::UnsafeInteger(
                "post-allocation queue entries"
            ))
        ));
    }
}
