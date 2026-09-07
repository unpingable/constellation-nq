//! Versioned compiled detectors over admitted evidence.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    ProfileDigest, ProfileKey, ProfileRefusal, ProfileRefusalCode, RefusalBoundary, ValidatedReport,
};

/// Schema identifier for canonical detector descriptors.
pub const DETECTOR_DESCRIPTOR_SCHEMA: &str = "nq.detector_descriptor.v1";

/// Typed, canonically hashed rule parameters carried inside a detector
/// descriptor so the detector's semantic identity covers its executable law.
///
/// Thresholds are fixed-point integers, never floats: a float has no single
/// canonical byte form, and behavior-bearing law must hash deterministically.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorRuleParameters {
    /// One-minute load-pressure law. The condition is `Present` when
    /// `load_1m / cpu_count >= normalized_load_threshold_millis / 1000`.
    LoadPressure {
        /// Threshold on normalized one-minute load, in thousandths of a logical
        /// CPU (e.g. `2000` = load at least twice the logical CPU count).
        normalized_load_threshold_millis: u32,
    },
    /// Generic exact systemd-unit comparison under an admitted external policy.
    SystemdUnitPostcondition {
        /// Only this immutable policy schema may provide expected values.
        threshold_policy_schema: String,
    },
    /// Generic bounded HTTP status/body comparison under an admitted policy.
    HttpEndpointPostcondition {
        /// Only this immutable policy schema may provide expected values.
        threshold_policy_schema: String,
    },
}

/// Canonical identity and operator metadata for one detector revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorDescriptor {
    /// Descriptor schema.
    pub schema: String,
    /// Stable detector identifier.
    pub id: String,
    /// Compiled detector revision.
    pub version: u32,
    /// Exact profile contract consumed by this detector.
    pub profile: ProfileKey,
    /// Digest of that profile descriptor.
    pub profile_digest: ProfileDigest,
    /// Short operator-facing title.
    pub title: String,
    /// Stable condition name emitted by this detector.
    pub condition: String,
    /// Typed rule parameters interpreted by this detector revision. Part of the
    /// hashed identity, so a behavior-changing threshold rotates the digest.
    pub parameters: DetectorRuleParameters,
}

impl DetectorDescriptor {
    /// Computes a digest over the canonical descriptor.
    ///
    /// # Errors
    ///
    /// Returns the canonicalization failure text if serialization fails.
    pub fn digest(&self) -> Result<String, String> {
        nq_protocol::semantic_digest(self)
            .map(|digest| digest.to_string())
            .map_err(|error| error.to_string())
    }
}

/// Consistent storage position used by an evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EvidenceWatermark(pub u64);

/// Input to a compiled detector.
#[derive(Clone, Debug)]
pub struct DetectorInput<'a> {
    /// Instance whose admitted evidence is being evaluated.
    pub instance_id: &'a str,
    /// Evaluation wall-clock time.
    pub evaluated_at: DateTime<Utc>,
    /// Consistent database watermark selected by the evaluation engine.
    pub watermark: EvidenceWatermark,
    /// Exact immutable external verdict policy, when the compiled detector
    /// declares that policy surface.
    pub threshold_policy: Option<&'a ThresholdPolicyInput>,
    /// Admitted report occurrences visible at the watermark.
    ///
    /// Slice order and report timestamps carry no ordering authority. Detectors
    /// select recency only through [`DetectorReport::report_sequence`].
    pub reports: &'a [DetectorReport],
}

/// Exact immutable external policy presented to a compiled detector.
///
/// The compiled profile remains the semantic owner: it validates the closed
/// policy schema, recomputes `digest` over `value`, and binds the policy to the
/// exact subject and request scope before using any verdict-changing value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdPolicyInput {
    /// Stable policy family.
    pub id: String,
    /// Exact policy generation.
    pub version: String,
    /// SHA-256 of the canonical policy value.
    pub digest: nq_protocol::Sha256Digest,
    /// Closed profile-owned policy document.
    pub value: serde_json::Value,
}

impl ThresholdPolicyInput {
    /// Verifies that the retained identity commits to the exact policy value.
    ///
    /// # Errors
    ///
    /// Returns canonicalization or mismatch detail without interpreting policy.
    pub fn verify_digest(&self) -> Result<(), String> {
        let actual =
            nq_protocol::semantic_digest(&self.value).map_err(|error| error.to_string())?;
        if actual == self.digest {
            Ok(())
        } else {
            Err(format!(
                "threshold policy digest mismatch: expected {}, observed {}",
                self.digest, actual
            ))
        }
    }
}

/// One exact admitted report occurrence presented to compiled detectors.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectorReport {
    /// Opaque NQ-owned report identity.
    pub report_id: String,
    /// Durable database order assigned when the report was committed.
    pub report_sequence: u64,
    /// Profile-validated semantic testimony for this exact occurrence.
    pub report: ValidatedReport,
}

/// A precise source report/observation used by an evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorEvidence {
    /// Opaque NQ-owned identity of the exact report occurrence.
    pub report_id: String,
    /// Durable database order of the exact report occurrence.
    pub report_sequence: u64,
    /// Canonical semantic report identity.
    pub report_digest: String,
    /// Observation ordinal, when the evidence is an observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_ordinal: Option<u32>,
    /// Time the evidence was observed.
    pub observed_at: DateTime<Utc>,
}

/// Detector result plane. Only `ExplicitlyAbsent` may resolve a finding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorState {
    /// Current admitted evidence supports the bounded condition.
    Present,
    /// Sufficient current coverage explicitly supports absence.
    ExplicitlyAbsent,
    /// Evidence is missing, stale, partial, refused, or otherwise insufficient.
    CannotEvaluate,
}

/// Result returned by a compiled detector revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorResult {
    /// Exact detector state.
    pub state: DetectorState,
    /// Condition identifier from the detector descriptor.
    pub condition: String,
    /// Concise bounded diagnosis.
    pub summary: String,
    /// Exact evidence references.
    pub evidence: Vec<DetectorEvidence>,
    /// Material limits on this evaluation.
    pub limitations: Vec<String>,
    /// Required typed refusal when the detector cannot evaluate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<ProfileRefusal>,
    /// Database watermark used by the evaluation.
    pub watermark: EvidenceWatermark,
}

impl DetectorResult {
    /// Creates a `cannot_evaluate` result with an exact responsible instance.
    #[must_use]
    pub fn cannot_evaluate(
        input: &DetectorInput<'_>,
        descriptor: &DetectorDescriptor,
        summary: impl Into<String>,
        limitations: Vec<String>,
    ) -> Self {
        Self::cannot_evaluate_with_details(input, descriptor, summary, limitations, BTreeMap::new())
    }

    /// Creates a `cannot_evaluate` result with bounded dependent facts while
    /// retaining the typed detector boundary and refusal code as its semantic
    /// identity.
    #[must_use]
    pub fn cannot_evaluate_with_details(
        input: &DetectorInput<'_>,
        descriptor: &DetectorDescriptor,
        summary: impl Into<String>,
        limitations: Vec<String>,
        details: BTreeMap<String, String>,
    ) -> Self {
        let summary = summary.into();
        let refusal = ProfileRefusal {
            instance_id: input.instance_id.to_owned(),
            profile: descriptor.profile.clone(),
            boundary: RefusalBoundary::Detector,
            code: ProfileRefusalCode::CannotEvaluate,
            message: summary.clone(),
            details,
        };
        Self {
            state: DetectorState::CannotEvaluate,
            condition: descriptor.condition.clone(),
            summary,
            evidence: Vec::new(),
            limitations,
            refusal: Some(refusal),
            watermark: input.watermark,
        }
    }
}

/// Narrow object-safe interface for one separately versioned compiled detector.
pub trait Detector: Send + Sync {
    /// Canonical detector descriptor.
    fn descriptor(&self) -> &'static DetectorDescriptor;

    /// Evaluates admitted evidence at the supplied consistent watermark.
    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult;
}
