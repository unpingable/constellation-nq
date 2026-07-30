//! Pure, authority-neutral custody-capacity arithmetic.
//!
//! This module is the single implementation of the v1 physical carrier
//! geometry shared by contract validation and Store.  It calculates logical
//! geometry only.  A successful result does not allocate bytes, establish
//! filesystem capacity, accept a request, authorize launch, or perform a
//! provider effect.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact unsigned-integer ceiling representable without loss under I-JSON/JCS.
pub const CAPACITY_IJSON_SAFE_INTEGER_MAX_V1: u64 = 9_007_199_254_740_991;

/// Alignment used by the v1 arena and append-extent formats.
pub const CUSTODY_CAPACITY_ALIGNMENT_V1: u64 = 4_096;

const ARENA_SUPERBLOCK_COUNT_V1: u64 = 2;
const ARENA_SECTION_COUNT_V1: u64 = 4;
const APPEND_SUPERBLOCK_COUNT_V1: u64 = 2;
const APPEND_HEADER_COUNT_V1: u64 = 1;

/// A bounded failure in the shared v1 capacity arithmetic.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapacityArithmeticError {
    /// An input or derived result exceeded the I-JSON/JCS safe-integer domain.
    #[error("custody-capacity integer is unsafe while calculating {0}")]
    UnsafeInteger(&'static str),
    /// A required physical carrier was assigned no payload capacity.
    #[error("{0} payload capacity must be nonzero")]
    ZeroCarrierPayload(&'static str),
    /// Installed logical limits were internally incoherent.
    #[error("custody-capacity policy is invalid: {0}")]
    InvalidPolicy(&'static str),
    /// Candidate protected-failure capacity differed from installed policy.
    #[error(
        "protected-failure carrier is {carrier_bytes} bytes but policy requires {policy_bytes} bytes"
    )]
    ProtectedFailurePolicyMismatch {
        /// Candidate carrier payload.
        carrier_bytes: u64,
        /// Installed policy payload.
        policy_bytes: u64,
    },
}

/// Exact v1 arena geometry for independent `D/R/V/P` payload capacities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyArenaGeometryV1 {
    /// Complete arena length `F`.
    pub file_length_bytes: u64,
    /// Offset of the dependency-section header.
    pub dependency_header_offset: u64,
    /// Offset of the dependency payload.
    pub dependency_payload_offset: u64,
    /// `D`.
    pub dependency_payload_bytes: u64,
    /// Offset of the raw-section header.
    pub raw_header_offset: u64,
    /// Offset of the raw payload.
    pub raw_payload_offset: u64,
    /// `R`.
    pub raw_payload_bytes: u64,
    /// Offset of the final-section header.
    pub final_header_offset: u64,
    /// Offset of the final payload.
    pub final_payload_offset: u64,
    /// `V`.
    pub final_payload_bytes: u64,
    /// Offset of the protected-failure header.
    pub failure_header_offset: u64,
    /// Offset of the protected-failure payload.
    pub failure_payload_offset: u64,
    /// `P`.
    pub failure_payload_bytes: u64,
    /// Two superblocks plus four section headers.
    pub fixed_format_bytes: u64,
    /// All alignment bytes in `F`, counted exactly once.
    pub alignment_bytes: u64,
}

/// Exact v1 append-only extent geometry for an independent payload bound.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppendExtentGeometryV1 {
    /// Offset of superblock zero.
    pub superblock_0_offset: u64,
    /// Offset of superblock one.
    pub superblock_1_offset: u64,
    /// Offset of the extent header.
    pub extent_header_offset: u64,
    /// Offset at which append frames begin.
    pub payload_offset: u64,
    /// Independently derived payload bound.
    pub payload_bytes: u64,
    /// Complete logical extent length.
    pub extent_length_bytes: u64,
    /// Two superblocks plus one extent header.
    pub fixed_format_bytes: u64,
    /// Final alignment bytes.
    pub alignment_bytes: u64,
}

/// The exact eight semantic components carried by one intended reservation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacitySemanticComponentsV1 {
    /// Request, authentication, authorization, and decision material.
    pub request_and_decision_bytes: u64,
    /// Exact raw evidence material.
    pub raw_evidence_bytes: u64,
    /// Normalized admitted facts.
    pub normalized_bytes: u64,
    /// Projected admitted facts.
    pub projected_bytes: u64,
    /// Terminal diagnostic or typed non-success artifact.
    pub diagnostic_artifact_bytes: u64,
    /// Authenticated dependency closure.
    pub dependency_closure_bytes: u64,
    /// Capacity, launch, checkpoint, and commit material.
    pub commit_checkpoint_overhead_bytes: u64,
    /// Immutable delivery-ledger material, or zero when not required.
    pub mandatory_delivery_ledger_bytes: u64,
}

/// Complete aggregate usage inputs before one candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityUsageComponentsV1 {
    /// Fixed bootstrap/integrity carrier `B`.
    pub bootstrap_integrity_carrier_bytes: u64,
    /// Fixed global prelaunch-refusal carrier `G`.
    pub global_prelaunch_refusal_bytes: u64,
    /// Sum of matched retained allocation charges.
    pub matched_retained_bytes: u64,
    /// Sum of authenticated charged orphan carrier sets.
    pub physical_orphan_bytes: u64,
    /// Canonical commitments missing a matched physical carrier.
    pub missing_committed_bytes: u64,
    /// Active delivery occurrences before this candidate.
    pub active_queue_entries: u64,
}

/// Candidate carrier and queue inputs used by the aggregate law.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityCandidateChargeV1 {
    /// Complete arena length `F`.
    pub arena_file_length_bytes: u64,
    /// Complete canonical-record extent length `M`.
    pub canonical_record_extent_length_bytes: u64,
    /// Complete delivery extent length `L`, or zero when not required.
    pub delivery_ledger_extent_length_bytes: u64,
    /// Independently derived final-closure payload bound `V`.
    pub final_closure_payload_bytes: u64,
    /// Protected-failure payload `P`.
    pub protected_failure_payload_bytes: u64,
    /// Queue occurrences reserved by this candidate.
    pub queue_entries_reserved: u64,
}

/// Installed aggregate logical limits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityLogicalLimitsV1 {
    /// Complete logical preallocated-carrier budget.
    pub total_bytes: u64,
    /// Backpressure boundary, not a second total.
    pub high_watermark_bytes: u64,
    /// Exact required protected-failure payload.
    pub protected_failure_receipt_bytes: u64,
    /// Limit on `max(S, V)`.
    pub maximum_single_execution_closure_bytes: u64,
    /// Maximum active delivery queue occurrences.
    pub maximum_queue_entries: u64,
}

/// Classification relative to the exact high-watermark boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityWatermarkClassificationV1 {
    /// Logical use is strictly below the boundary.
    Below,
    /// Logical use equals or exceeds the boundary.
    AtOrAbove,
}

/// Closed logical-limit refusal reasons in required stable order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLimitRefusalV1 {
    /// `max(S, V)` exceeded the installed single-execution limit.
    MaximumSingleExecutionClosureExceeded,
    /// Active plus candidate queue entries exceeded the installed limit.
    MaximumQueueEntriesExceeded,
    /// `U + T` exceeded the installed logical total.
    LogicalPreallocatedCarrierTotalExceeded,
}

/// Pure aggregate disposition; never a physical-allocation capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLogicalDispositionV1 {
    /// Logical arithmetic permits a separately governed physical attempt.
    WithinLogicalLimits,
    /// At least one closed logical limit refused the candidate.
    Refused,
}

/// Complete result of the shared aggregate law.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalPreallocatedCustodyEvaluationV1 {
    semantic_sum_bytes: u64,
    single_execution_bound_bytes: u64,
    logical_preallocated_carrier_bytes_before: u64,
    retained_charge_bytes: u64,
    logical_preallocated_carrier_bytes_after: u64,
    queue_entries_before: u64,
    queue_entries_reserved: u64,
    queue_entries_after: u64,
    used_before_watermark: CapacityWatermarkClassificationV1,
    used_after_watermark: CapacityWatermarkClassificationV1,
    disposition: CapacityLogicalDispositionV1,
    refusal_reasons: Vec<CapacityLimitRefusalV1>,
}

impl LogicalPreallocatedCustodyEvaluationV1 {
    /// Exact semantic sum `S`.
    #[must_use]
    pub const fn semantic_sum_bytes(&self) -> u64 {
        self.semantic_sum_bytes
    }

    /// Exact single-execution surface `max(S, V)`.
    #[must_use]
    pub const fn single_execution_bound_bytes(&self) -> u64 {
        self.single_execution_bound_bytes
    }

    /// Exact aggregate use `U`.
    #[must_use]
    pub const fn logical_preallocated_carrier_bytes_before(&self) -> u64 {
        self.logical_preallocated_carrier_bytes_before
    }

    /// Candidate retained carrier charge `T = F + M + L`.
    #[must_use]
    pub const fn retained_charge_bytes(&self) -> u64 {
        self.retained_charge_bytes
    }

    /// Exact checked `U + T`.
    #[must_use]
    pub const fn logical_preallocated_carrier_bytes_after(&self) -> u64 {
        self.logical_preallocated_carrier_bytes_after
    }

    /// Queue entries before this candidate.
    #[must_use]
    pub const fn queue_entries_before(&self) -> u64 {
        self.queue_entries_before
    }

    /// Queue entries reserved by this candidate.
    #[must_use]
    pub const fn queue_entries_reserved(&self) -> u64 {
        self.queue_entries_reserved
    }

    /// Exact checked queue cardinality after this candidate.
    #[must_use]
    pub const fn queue_entries_after(&self) -> u64 {
        self.queue_entries_after
    }

    /// Watermark classification of `U`.
    #[must_use]
    pub const fn used_before_watermark(&self) -> CapacityWatermarkClassificationV1 {
        self.used_before_watermark
    }

    /// Watermark classification of `U + T`.
    #[must_use]
    pub const fn used_after_watermark(&self) -> CapacityWatermarkClassificationV1 {
        self.used_after_watermark
    }

    /// Pure logical disposition.
    #[must_use]
    pub const fn disposition(&self) -> CapacityLogicalDispositionV1 {
        self.disposition
    }

    /// All violated limits in stable contract order.
    #[must_use]
    pub fn refusal_reasons(&self) -> &[CapacityLimitRefusalV1] {
        &self.refusal_reasons
    }
}

/// Admit one integer to the exact v1 serialized capacity domain.
///
/// This helper deliberately accepts zero.  Individual carriers impose their
/// own nonzero law after the shared representation bound is checked.
///
/// # Errors
///
/// Returns [`CapacityArithmeticError::UnsafeInteger`] outside the exact
/// I-JSON/JCS integer domain.
pub fn checked_capacity_integer_v1(
    value: u64,
    operation: &'static str,
) -> Result<u64, CapacityArithmeticError> {
    if value <= CAPACITY_IJSON_SAFE_INTEGER_MAX_V1 {
        Ok(value)
    } else {
        Err(CapacityArithmeticError::UnsafeInteger(operation))
    }
}

fn checked_add_v1(
    left: u64,
    right: u64,
    operation: &'static str,
) -> Result<u64, CapacityArithmeticError> {
    checked_capacity_integer_v1(left, operation)?;
    checked_capacity_integer_v1(right, operation)?;
    let value = left
        .checked_add(right)
        .ok_or(CapacityArithmeticError::UnsafeInteger(operation))?;
    checked_capacity_integer_v1(value, operation)
}

fn checked_mul_v1(
    left: u64,
    right: u64,
    operation: &'static str,
) -> Result<u64, CapacityArithmeticError> {
    checked_capacity_integer_v1(left, operation)?;
    checked_capacity_integer_v1(right, operation)?;
    let value = left
        .checked_mul(right)
        .ok_or(CapacityArithmeticError::UnsafeInteger(operation))?;
    checked_capacity_integer_v1(value, operation)
}

fn checked_sum_v1(
    values: impl IntoIterator<Item = u64>,
    operation: &'static str,
) -> Result<u64, CapacityArithmeticError> {
    values
        .into_iter()
        .try_fold(0_u64, |sum, value| checked_add_v1(sum, value, operation))
}

fn checked_align_up_v1(
    value: u64,
    operation: &'static str,
) -> Result<u64, CapacityArithmeticError> {
    checked_capacity_integer_v1(value, operation)?;
    let rounded = checked_add_v1(value, CUSTODY_CAPACITY_ALIGNMENT_V1 - 1, operation)?;
    checked_capacity_integer_v1(rounded & !(CUSTODY_CAPACITY_ALIGNMENT_V1 - 1), operation)
}

fn require_nonzero_carrier(
    carrier: &'static str,
    bytes: u64,
) -> Result<(), CapacityArithmeticError> {
    checked_capacity_integer_v1(bytes, carrier)?;
    if bytes == 0 {
        return Err(CapacityArithmeticError::ZeroCarrierPayload(carrier));
    }
    Ok(())
}

/// Compute the checked semantic sum `S`.
///
/// # Errors
///
/// Returns an unsafe-integer error when an input or checked sum exceeds the
/// exact I-JSON/JCS domain.
pub fn checked_capacity_semantic_sum_v1(
    semantic: &CapacitySemanticComponentsV1,
) -> Result<u64, CapacityArithmeticError> {
    checked_sum_v1(
        [
            semantic.request_and_decision_bytes,
            semantic.raw_evidence_bytes,
            semantic.normalized_bytes,
            semantic.projected_bytes,
            semantic.diagnostic_artifact_bytes,
            semantic.dependency_closure_bytes,
            semantic.commit_checkpoint_overhead_bytes,
            semantic.mandatory_delivery_ledger_bytes,
        ],
        "semantic component sum",
    )
}

/// Compute the exact retained charge `T = F + M + L`.
///
/// # Errors
///
/// Refuses zero required carriers and unsafe inputs or sums.
pub fn checked_capacity_retained_charge_v1(
    arena_file_length_bytes: u64,
    canonical_record_extent_length_bytes: u64,
    delivery_ledger_extent_length_bytes: u64,
) -> Result<u64, CapacityArithmeticError> {
    require_nonzero_carrier("arena_file", arena_file_length_bytes)?;
    require_nonzero_carrier(
        "canonical_record_extent",
        canonical_record_extent_length_bytes,
    )?;
    checked_sum_v1(
        [
            arena_file_length_bytes,
            canonical_record_extent_length_bytes,
            delivery_ledger_extent_length_bytes,
        ],
        "retained carrier charge",
    )
}

/// Compute aggregate logical usage `U`, including missing committed bytes.
///
/// # Errors
///
/// Returns an unsafe-integer error for any unrepresentable input or sum.
pub fn checked_capacity_usage_v1(
    usage: &CapacityUsageComponentsV1,
) -> Result<u64, CapacityArithmeticError> {
    checked_capacity_integer_v1(usage.active_queue_entries, "active queue entries")?;
    checked_sum_v1(
        [
            usage.bootstrap_integrity_carrier_bytes,
            usage.global_prelaunch_refusal_bytes,
            usage.matched_retained_bytes,
            usage.physical_orphan_bytes,
            usage.missing_committed_bytes,
        ],
        "logical preallocated carrier usage",
    )
}

/// Compute checked `post = U + T`.
///
/// # Errors
///
/// Returns an unsafe-integer error when either input or the sum is outside
/// the exact I-JSON/JCS domain.
pub fn checked_capacity_post_usage_v1(
    logical_preallocated_carrier_bytes: u64,
    retained_charge_bytes: u64,
) -> Result<u64, CapacityArithmeticError> {
    checked_add_v1(
        logical_preallocated_carrier_bytes,
        retained_charge_bytes,
        "post-allocation logical carrier usage",
    )
}

/// Compute active queue cardinality after the candidate.
///
/// # Errors
///
/// Returns an unsafe-integer error when either input or the sum is outside
/// the exact I-JSON/JCS domain.
pub fn checked_capacity_queue_after_v1(
    active_queue_entries: u64,
    queue_entries_reserved: u64,
) -> Result<u64, CapacityArithmeticError> {
    checked_add_v1(
        active_queue_entries,
        queue_entries_reserved,
        "post-allocation queue entries",
    )
}

/// Compute the checked single-execution surface `max(S, V)`.
///
/// # Errors
///
/// Returns an unsafe-integer error when either input is outside the exact
/// I-JSON/JCS domain.
pub fn checked_capacity_single_execution_bound_v1(
    semantic_sum_bytes: u64,
    final_closure_payload_bytes: u64,
) -> Result<u64, CapacityArithmeticError> {
    checked_capacity_integer_v1(semantic_sum_bytes, "single-execution semantic sum")?;
    checked_capacity_integer_v1(
        final_closure_payload_bytes,
        "single-execution final-closure payload",
    )?;
    Ok(semantic_sum_bytes.max(final_closure_payload_bytes))
}

/// Classify one exact aggregate use against a high-watermark boundary.
///
/// # Errors
///
/// Returns an unsafe-integer error when the use or boundary is outside the
/// exact I-JSON/JCS domain.
pub fn classify_capacity_high_watermark_v1(
    logical_preallocated_carrier_bytes: u64,
    high_watermark_bytes: u64,
) -> Result<CapacityWatermarkClassificationV1, CapacityArithmeticError> {
    checked_capacity_integer_v1(
        logical_preallocated_carrier_bytes,
        "high-watermark logical carrier usage",
    )?;
    checked_capacity_integer_v1(high_watermark_bytes, "high-watermark boundary")?;
    Ok(
        if logical_preallocated_carrier_bytes < high_watermark_bytes {
            CapacityWatermarkClassificationV1::Below
        } else {
            CapacityWatermarkClassificationV1::AtOrAbove
        },
    )
}

/// Evaluate `S`, `T`, `U`, `post`, queue cardinality, watermarks, and the
/// closed logical limits through one shared checked law.
///
/// This is the implementation identified by
/// `nq.logical_preallocated_custody_carriers` v1.  A favorable result proves
/// only that logical arithmetic permits a separately governed physical
/// allocation attempt.  It performs no filesystem effect and establishes no
/// reservation, request acceptance, launch, diagnostic result, reliance,
/// authorization, or action.
///
/// # Errors
///
/// Refuses unsafe arithmetic, invalid policy geometry, zero required
/// carriers, and protected-failure policy mismatch.
#[allow(clippy::too_many_lines)] // One closed logical law keeps every refusal in required order.
pub fn checked_logical_preallocated_custody_carriers_v1(
    semantic: &CapacitySemanticComponentsV1,
    usage: &CapacityUsageComponentsV1,
    candidate: &CapacityCandidateChargeV1,
    limits: &CapacityLogicalLimitsV1,
) -> Result<LogicalPreallocatedCustodyEvaluationV1, CapacityArithmeticError> {
    for (value, operation) in [
        (limits.total_bytes, "capacity policy total bytes"),
        (
            limits.high_watermark_bytes,
            "capacity policy high-watermark bytes",
        ),
        (
            limits.protected_failure_receipt_bytes,
            "capacity policy protected-failure bytes",
        ),
        (
            limits.maximum_single_execution_closure_bytes,
            "capacity policy single-execution bytes",
        ),
        (
            limits.maximum_queue_entries,
            "capacity policy maximum queue entries",
        ),
    ] {
        checked_capacity_integer_v1(value, operation)?;
    }
    if limits.protected_failure_receipt_bytes == 0 {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "protected failure receipt bytes are zero",
        ));
    }
    if limits.high_watermark_bytes == 0 {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "high watermark bytes are zero",
        ));
    }
    if limits.total_bytes == 0 {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "total bytes are zero",
        ));
    }
    if limits.maximum_single_execution_closure_bytes == 0 {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "maximum single-execution closure bytes are zero",
        ));
    }
    if limits.maximum_queue_entries == 0 {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "maximum queue entries are zero",
        ));
    }
    if limits.protected_failure_receipt_bytes >= limits.high_watermark_bytes {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "protected failure bytes are not below the high watermark",
        ));
    }
    if limits.high_watermark_bytes >= limits.total_bytes {
        return Err(CapacityArithmeticError::InvalidPolicy(
            "high watermark is not below total bytes",
        ));
    }
    if candidate.protected_failure_payload_bytes != limits.protected_failure_receipt_bytes {
        return Err(CapacityArithmeticError::ProtectedFailurePolicyMismatch {
            carrier_bytes: candidate.protected_failure_payload_bytes,
            policy_bytes: limits.protected_failure_receipt_bytes,
        });
    }

    let semantic_sum_bytes = checked_capacity_semantic_sum_v1(semantic)?;
    let logical_preallocated_carrier_bytes_before = checked_capacity_usage_v1(usage)?;
    let retained_charge_bytes = checked_capacity_retained_charge_v1(
        candidate.arena_file_length_bytes,
        candidate.canonical_record_extent_length_bytes,
        candidate.delivery_ledger_extent_length_bytes,
    )?;
    let logical_preallocated_carrier_bytes_after = checked_capacity_post_usage_v1(
        logical_preallocated_carrier_bytes_before,
        retained_charge_bytes,
    )?;
    let queue_entries_after = checked_capacity_queue_after_v1(
        usage.active_queue_entries,
        candidate.queue_entries_reserved,
    )?;
    let single_execution_bound_bytes = checked_capacity_single_execution_bound_v1(
        semantic_sum_bytes,
        candidate.final_closure_payload_bytes,
    )?;
    let mut refusal_reasons = Vec::new();
    if single_execution_bound_bytes > limits.maximum_single_execution_closure_bytes {
        refusal_reasons.push(CapacityLimitRefusalV1::MaximumSingleExecutionClosureExceeded);
    }
    if queue_entries_after > limits.maximum_queue_entries {
        refusal_reasons.push(CapacityLimitRefusalV1::MaximumQueueEntriesExceeded);
    }
    if logical_preallocated_carrier_bytes_after > limits.total_bytes {
        refusal_reasons.push(CapacityLimitRefusalV1::LogicalPreallocatedCarrierTotalExceeded);
    }
    let disposition = if refusal_reasons.is_empty() {
        CapacityLogicalDispositionV1::WithinLogicalLimits
    } else {
        CapacityLogicalDispositionV1::Refused
    };

    Ok(LogicalPreallocatedCustodyEvaluationV1 {
        semantic_sum_bytes,
        single_execution_bound_bytes,
        logical_preallocated_carrier_bytes_before,
        retained_charge_bytes,
        logical_preallocated_carrier_bytes_after,
        queue_entries_before: usage.active_queue_entries,
        queue_entries_reserved: candidate.queue_entries_reserved,
        queue_entries_after,
        used_before_watermark: classify_capacity_high_watermark_v1(
            logical_preallocated_carrier_bytes_before,
            limits.high_watermark_bytes,
        )?,
        used_after_watermark: classify_capacity_high_watermark_v1(
            logical_preallocated_carrier_bytes_after,
            limits.high_watermark_bytes,
        )?,
        disposition,
        refusal_reasons,
    })
}

/// Derive the exact checked arena geometry used by the v1 physical format.
///
/// The four payloads are independent bounds.  Slack in one carrier does not
/// repair another.
///
/// # Errors
///
/// Refuses zero payload carriers and every unsafe intermediate or result.
#[allow(clippy::too_many_lines)] // One closed format formula exposes every exact offset.
pub fn checked_custody_arena_geometry_v1(
    dependency_payload_bytes: u64,
    raw_payload_bytes: u64,
    final_payload_bytes: u64,
    failure_payload_bytes: u64,
) -> Result<CustodyArenaGeometryV1, CapacityArithmeticError> {
    for (carrier, bytes) in [
        ("dependency", dependency_payload_bytes),
        ("raw_acquisition", raw_payload_bytes),
        ("final_closure", final_payload_bytes),
        ("protected_failure", failure_payload_bytes),
    ] {
        require_nonzero_carrier(carrier, bytes)?;
    }

    let dependency_header_offset = checked_mul_v1(
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        ARENA_SUPERBLOCK_COUNT_V1,
        "arena dependency-header offset",
    )?;
    let dependency_payload_offset = checked_add_v1(
        dependency_header_offset,
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        "arena dependency-payload offset",
    )?;
    let raw_header_offset = checked_align_up_v1(
        checked_add_v1(
            dependency_payload_offset,
            dependency_payload_bytes,
            "arena dependency end",
        )?,
        "arena raw-header alignment",
    )?;
    let raw_payload_offset = checked_add_v1(
        raw_header_offset,
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        "arena raw-payload offset",
    )?;
    let final_header_offset = checked_align_up_v1(
        checked_add_v1(raw_payload_offset, raw_payload_bytes, "arena raw end")?,
        "arena final-header alignment",
    )?;
    let final_payload_offset = checked_add_v1(
        final_header_offset,
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        "arena final-payload offset",
    )?;
    let failure_header_offset = checked_align_up_v1(
        checked_add_v1(final_payload_offset, final_payload_bytes, "arena final end")?,
        "arena failure-header alignment",
    )?;
    let failure_payload_offset = checked_add_v1(
        failure_header_offset,
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        "arena failure-payload offset",
    )?;
    let file_length_bytes = checked_align_up_v1(
        checked_add_v1(
            failure_payload_offset,
            failure_payload_bytes,
            "arena failure end",
        )?,
        "arena file-length alignment",
    )?;
    let fixed_format_bytes = checked_mul_v1(
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        ARENA_SUPERBLOCK_COUNT_V1 + ARENA_SECTION_COUNT_V1,
        "arena fixed-format bytes",
    )?;
    let payload_bytes = checked_sum_v1(
        [
            dependency_payload_bytes,
            raw_payload_bytes,
            final_payload_bytes,
            failure_payload_bytes,
        ],
        "arena payload sum",
    )?;
    let used_without_alignment = checked_add_v1(
        fixed_format_bytes,
        payload_bytes,
        "arena format plus payload",
    )?;
    let alignment_bytes = file_length_bytes
        .checked_sub(used_without_alignment)
        .ok_or(CapacityArithmeticError::UnsafeInteger(
            "arena alignment accounting",
        ))?;
    checked_capacity_integer_v1(alignment_bytes, "arena alignment accounting")?;

    Ok(CustodyArenaGeometryV1 {
        file_length_bytes,
        dependency_header_offset,
        dependency_payload_offset,
        dependency_payload_bytes,
        raw_header_offset,
        raw_payload_offset,
        raw_payload_bytes,
        final_header_offset,
        final_payload_offset,
        final_payload_bytes,
        failure_header_offset,
        failure_payload_offset,
        failure_payload_bytes,
        fixed_format_bytes,
        alignment_bytes,
    })
}

/// Derive one exact append-only carrier extent.
///
/// `payload_bytes == 0` is not a null-delivery encoding.  Null delivery has
/// no extent at all.
///
/// # Errors
///
/// Refuses a zero payload and every unsafe intermediate or result.
pub fn checked_append_extent_geometry_v1(
    payload_bytes: u64,
) -> Result<AppendExtentGeometryV1, CapacityArithmeticError> {
    require_nonzero_carrier("append_extent", payload_bytes)?;
    let superblock_0_offset = 0;
    let superblock_1_offset = CUSTODY_CAPACITY_ALIGNMENT_V1;
    let extent_header_offset = checked_mul_v1(
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        APPEND_SUPERBLOCK_COUNT_V1,
        "append extent-header offset",
    )?;
    let payload_offset = checked_add_v1(
        extent_header_offset,
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        "append payload offset",
    )?;
    let extent_length_bytes = checked_align_up_v1(
        checked_add_v1(payload_offset, payload_bytes, "append payload end")?,
        "append extent-length alignment",
    )?;
    let fixed_format_bytes = checked_mul_v1(
        CUSTODY_CAPACITY_ALIGNMENT_V1,
        APPEND_SUPERBLOCK_COUNT_V1 + APPEND_HEADER_COUNT_V1,
        "append fixed-format bytes",
    )?;
    let used_without_alignment = checked_add_v1(
        fixed_format_bytes,
        payload_bytes,
        "append format plus payload",
    )?;
    let alignment_bytes = extent_length_bytes
        .checked_sub(used_without_alignment)
        .ok_or(CapacityArithmeticError::UnsafeInteger(
            "append alignment accounting",
        ))?;
    checked_capacity_integer_v1(alignment_bytes, "append alignment accounting")?;

    Ok(AppendExtentGeometryV1 {
        superblock_0_offset,
        superblock_1_offset,
        extent_header_offset,
        payload_offset,
        payload_bytes,
        extent_length_bytes,
        fixed_format_bytes,
        alignment_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CAPACITY_IJSON_SAFE_INTEGER_MAX_V1, CapacityArithmeticError,
        checked_append_extent_geometry_v1, checked_capacity_integer_v1,
        checked_custody_arena_geometry_v1,
    };

    #[test]
    fn exact_i_json_safe_integer_boundary_is_closed() {
        assert_eq!(
            checked_capacity_integer_v1(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1, "safe maximum"),
            Ok(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1)
        );
        assert_eq!(
            checked_capacity_integer_v1(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1 + 1, "unsafe successor"),
            Err(CapacityArithmeticError::UnsafeInteger("unsafe successor"))
        );
    }

    #[test]
    fn derived_geometry_refuses_safe_integer_overrun() {
        assert!(matches!(
            checked_append_extent_geometry_v1(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1),
            Err(CapacityArithmeticError::UnsafeInteger(_))
        ));
        assert!(matches!(
            checked_custody_arena_geometry_v1(1, 1, 1, CAPACITY_IJSON_SAFE_INTEGER_MAX_V1),
            Err(CapacityArithmeticError::UnsafeInteger(_))
        ));
    }
}
