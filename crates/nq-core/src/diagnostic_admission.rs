//! Portable provenance for one locally produced diagnostic artifact.
//!
//! This carrier records that the configured NQ store reopened the artifact's
//! complete local semantic history. It establishes evidence eligibility only:
//! it is not freshness, reliance, authorization, or permission to act.

use chrono::DateTime;
use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};

use crate::continuity::ProviderAcquisitionIntentV1;
use crate::diagnostic_execution_v2::DIAGNOSTIC_EXECUTION_V2_SCHEMA;
use crate::substrate_origin::SubstrateOriginAcquisitionIntentV1;

/// Exact admission-provenance schema emitted by NQ-NG.
pub const DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA: &str = "nq.diagnostic_admission_provenance.v1";
/// Admission provenance carrying an exact pre-invocation continuity chain.
pub const DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA_V2: &str = "nq.diagnostic_admission_provenance.v2";
/// Admission provenance carrying a pre-invocation substrate-origin proof and,
/// for a transition, its exact continuity-authority carrier.
pub const DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA_V3: &str = "nq.diagnostic_admission_provenance.v3";

const NONCLAIMS: [&str; 3] = [
    "admission establishes evidence eligibility only",
    "this provenance does not establish freshness, reliance, authorization, or action",
    "source and resolver honesty remain environmental",
];

/// The exact NQ source disposition represented by the diagnostic artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSourceDispositionV1 {
    /// A provider report passed NQ profile admission and its judgment is bound.
    AdmittedReport,
    /// Exact provider bytes were retained with a governed refusal.
    GovernedRefusal,
    /// No qualifying provider response entered evidence custody.
    AcquisitionFailure,
}

/// Stable identity of the configured NQ store that owns the local history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionSourceV1 {
    /// Current source kind. Imported custody can never use this carrier.
    pub kind: String,
    /// Store-genesis identity also carried by the locally emitted artifact.
    pub source_id: String,
}

/// Exact committed artifact bytes qualified by the source store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionArtifactV1 {
    /// Contract-owned semantic identity of the diagnostic artifact.
    pub artifact_id: Sha256Digest,
    /// Exact diagnostic contract schema.
    pub contract_schema: String,
    /// Digest of the complete retained canonical artifact bytes.
    pub canonical_bytes_sha256: Sha256Digest,
    /// Length of the complete retained canonical artifact bytes.
    pub canonical_bytes_length: u64,
}

/// Exact local execution occurrence from which the artifact was committed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionOriginV1 {
    /// Local collection-run identity.
    pub run_id: String,
    /// Local evaluation identity when a report was admitted and evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_id: Option<String>,
    /// Diagnostic completion time bound into the artifact.
    pub completed_at: String,
    /// Store commitment time.
    pub committed_at: String,
}

/// Provider admission and exact raw-intake identities behind the artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionProviderV1 {
    /// Identity of the exact retained provider intake.
    pub provider_intake_id: String,
    /// Digest of the exact provider response bytes, including empty custody.
    pub raw_sha256: Sha256Digest,
    /// Provider-bound admission identity derived at intake.
    pub provider_admission_id: Sha256Digest,
    /// Source admission identity evaluated by NQ.
    pub source_admission_id: String,
    /// Exact admission-context digest evaluated by NQ.
    pub admission_context_digest: Sha256Digest,
    /// Exact compiled-profile semantic identity evaluated by NQ.
    pub profile_semantic_id: Sha256Digest,
}

/// Persisted NQ judgment for an admitted provider report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionJudgmentV1 {
    /// Admitted report identity.
    pub report_id: String,
    /// Frozen judgment schema.
    pub judgment_schema: String,
    /// Digest authenticating the retained judgment body.
    pub judgment_digest: Sha256Digest,
}

/// Content-identified proof that one artifact is a locally produced NQ result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionProvenanceV1 {
    /// Exact carrier schema.
    pub schema: String,
    /// Content identity of this carrier with this field omitted.
    pub provenance_id: Sha256Digest,
    /// Stable local NQ store identity.
    pub source: DiagnosticAdmissionSourceV1,
    /// Exact committed diagnostic artifact binding.
    pub artifact: DiagnosticAdmissionArtifactV1,
    /// Exact local diagnostic occurrence.
    pub origin: DiagnosticAdmissionOriginV1,
    /// Exact provider and admission-rule provenance.
    pub provider: DiagnosticAdmissionProviderV1,
    /// NQ's source-input disposition represented by the artifact.
    pub disposition: DiagnosticSourceDispositionV1,
    /// Exact report judgment when and only when a report was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judgment: Option<DiagnosticAdmissionJudgmentV1>,
    /// Closed non-authority boundary statements.
    pub nonclaims: Vec<String>,
}

impl DiagnosticAdmissionProvenanceV1 {
    /// Seal the exact provenance body after the source history has verified.
    pub(crate) fn seal(mut self) -> Result<Self, String> {
        DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA.clone_into(&mut self.schema);
        self.provenance_id = nq_protocol::sha256_bytes(b"pending provenance identity");
        self.nonclaims = NONCLAIMS.into_iter().map(str::to_owned).collect();
        self.provenance_id = self.computed_provenance_id()?;
        self.validate()?;
        Ok(self)
    }

    /// Recompute the content identity with `provenance_id` omitted.
    ///
    /// # Errors
    ///
    /// Returns when the typed carrier cannot be represented as canonical JSON.
    pub fn computed_provenance_id(&self) -> Result<Sha256Digest, String> {
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "diagnostic admission provenance is not an object".to_owned())?
            .remove("provenance_id");
        semantic_digest(&value).map_err(|error| error.to_string())
    }

    /// Validate the closed carrier without treating its self-hash as source
    /// authentication. Consumers must acquire it from their configured NQ
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns when any closed field, identity, timestamp, disposition, or
    /// nonclaim differs from the carrier contract.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA {
            return Err("unsupported diagnostic admission provenance schema".into());
        }
        if self.source.kind != "local_nq_store"
            || self.source.source_id.trim().is_empty()
            || self.source.source_id.chars().any(char::is_whitespace)
        {
            return Err("diagnostic admission source identity is invalid".into());
        }
        if self.artifact.contract_schema != DIAGNOSTIC_EXECUTION_V2_SCHEMA
            || self.artifact.canonical_bytes_length == 0
        {
            return Err("diagnostic admission artifact binding is invalid".into());
        }
        if self.origin.run_id.is_empty()
            || self
                .origin
                .evaluation_id
                .as_ref()
                .is_some_and(String::is_empty)
            || DateTime::parse_from_rfc3339(&self.origin.completed_at).is_err()
            || DateTime::parse_from_rfc3339(&self.origin.committed_at).is_err()
        {
            return Err("diagnostic admission local origin is invalid".into());
        }
        if self.provider.provider_intake_id.is_empty()
            || self.provider.source_admission_id.is_empty()
        {
            return Err("diagnostic admission provider binding is invalid".into());
        }
        match (self.disposition, &self.judgment) {
            (DiagnosticSourceDispositionV1::AdmittedReport, Some(judgment))
                if !judgment.report_id.is_empty()
                    && judgment.judgment_schema == nq_store::JUDGMENT_SCHEMA_VERSION => {}
            (DiagnosticSourceDispositionV1::AdmittedReport, _) => {
                return Err("admitted report provenance requires its exact judgment".into());
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(
                    "non-admitted source disposition cannot carry a report judgment".into(),
                );
            }
        }
        if self.nonclaims != NONCLAIMS.into_iter().map(str::to_owned).collect::<Vec<_>>() {
            return Err("diagnostic admission nonclaims differ from the closed contract".into());
        }
        if self.provenance_id != self.computed_provenance_id()? {
            return Err("diagnostic admission provenance identity mismatch".into());
        }
        Ok(())
    }
}

/// Exact prerequisite and lifecycle projection for one continuity-bound intake.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionContinuityV2 {
    /// Exact intent durably committed before provider invocation.
    pub intent: ProviderAcquisitionIntentV1,
    /// Digest of the exact stored intent bytes.
    pub intent_digest: Sha256Digest,
    /// Closed append-only phases proving dispatch and durable intake completion.
    pub phases: Vec<String>,
}

/// Content-identified NQ admission carrier with continuity prerequisites.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdmissionProvenanceV2 {
    /// Exact carrier schema.
    pub schema: String,
    /// Content identity with this field omitted.
    pub provenance_id: Sha256Digest,
    /// Stable local NQ store identity.
    pub source: DiagnosticAdmissionSourceV1,
    /// Exact committed diagnostic artifact binding.
    pub artifact: DiagnosticAdmissionArtifactV1,
    /// Exact local diagnostic occurrence.
    pub origin: DiagnosticAdmissionOriginV1,
    /// Exact provider and admission-rule provenance.
    pub provider: DiagnosticAdmissionProviderV1,
    /// Proof-bearing pre-invocation continuity chain.
    pub continuity: DiagnosticAdmissionContinuityV2,
    /// NQ's source-input disposition.
    pub disposition: DiagnosticSourceDispositionV1,
    /// Exact report judgment when and only when a report was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judgment: Option<DiagnosticAdmissionJudgmentV1>,
    /// Closed non-authority boundary statements.
    pub nonclaims: Vec<String>,
}

impl DiagnosticAdmissionProvenanceV2 {
    pub(crate) fn seal(mut self) -> Result<Self, String> {
        self.schema = DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA_V2.into();
        self.provenance_id = nq_protocol::sha256_bytes(b"pending v2 provenance identity");
        self.nonclaims = NONCLAIMS.into_iter().map(str::to_owned).collect();
        self.provenance_id = self.computed_provenance_id()?;
        self.validate()?;
        Ok(self)
    }

    /// Recompute the exact content identity with the identity field omitted.
    ///
    /// # Errors
    ///
    /// Returns when the closed provenance cannot be represented canonically.
    pub fn computed_provenance_id(&self) -> Result<Sha256Digest, String> {
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "diagnostic admission provenance v2 is not an object".to_owned())?
            .remove("provenance_id");
        semantic_digest(&value).map_err(|error| error.to_string())
    }

    /// Validate exact local provenance and immutable pre-invocation causality.
    ///
    /// # Errors
    ///
    /// Returns when any schema, identity, acquisition phase, provider binding,
    /// disposition, or closed nonclaim differs from the V2 contract.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA_V2 {
            return Err("unsupported diagnostic admission provenance v2 schema".into());
        }
        self.continuity
            .intent
            .validate()
            .map_err(|error| error.to_string())?;
        if self.source.kind != "local_nq_store"
            || self.source.source_id.trim().is_empty()
            || self.source.source_id.chars().any(char::is_whitespace)
        {
            return Err("diagnostic admission source identity is invalid".into());
        }
        if self.artifact.contract_schema != DIAGNOSTIC_EXECUTION_V2_SCHEMA
            || self.artifact.canonical_bytes_length == 0
        {
            return Err("diagnostic admission artifact binding is invalid".into());
        }
        if self.origin.run_id.is_empty()
            || self
                .origin
                .evaluation_id
                .as_ref()
                .is_some_and(String::is_empty)
            || DateTime::parse_from_rfc3339(&self.origin.completed_at).is_err()
            || DateTime::parse_from_rfc3339(&self.origin.committed_at).is_err()
        {
            return Err("diagnostic admission local origin is invalid".into());
        }
        if self.provider.provider_intake_id.is_empty()
            || self.provider.source_admission_id.is_empty()
        {
            return Err("diagnostic admission provider binding is invalid".into());
        }
        if self.continuity.intent.intake_id != self.provider.provider_intake_id
            || self.continuity.intent.run_id != self.origin.run_id
            || self
                .continuity
                .intent
                .canonical_digest()
                .map_err(|error| error.to_string())?
                != self.continuity.intent_digest.as_str()
            || self.continuity.phases
                != ["provider_invocation_started", "provider_intake_completed"]
        {
            return Err(
                "diagnostic admission continuity does not bind exact intent/intake lifecycle"
                    .into(),
            );
        }
        if self.nonclaims != NONCLAIMS.into_iter().map(str::to_owned).collect::<Vec<_>>() {
            return Err("diagnostic admission v2 nonclaims differ from closed contract".into());
        }
        match (self.disposition, &self.judgment) {
            (DiagnosticSourceDispositionV1::AdmittedReport, Some(judgment))
                if !judgment.report_id.is_empty()
                    && judgment.judgment_schema == nq_store::JUDGMENT_SCHEMA_VERSION => {}
            (DiagnosticSourceDispositionV1::AdmittedReport, _) => {
                return Err("admitted report provenance requires its exact judgment".into());
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(
                    "non-admitted source disposition cannot carry a report judgment".into(),
                );
            }
        }
        if self.provenance_id != self.computed_provenance_id()? {
            return Err("diagnostic admission provenance v2 identity mismatch".into());
        }
        Ok(())
    }
}

/// Exact origin-attested prerequisite and lifecycle projection for one intake.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct DiagnosticAdmissionSubstrateOriginV3 {
    pub intent: SubstrateOriginAcquisitionIntentV1,
    pub intent_digest: Sha256Digest,
    pub phases: Vec<String>,
}

/// Content-identified NQ admission carrier with an origin proof acquired
/// before the observed provider was dispatched.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct DiagnosticAdmissionProvenanceV3 {
    pub schema: String,
    pub provenance_id: Sha256Digest,
    pub source: DiagnosticAdmissionSourceV1,
    pub artifact: DiagnosticAdmissionArtifactV1,
    pub origin: DiagnosticAdmissionOriginV1,
    pub provider: DiagnosticAdmissionProviderV1,
    pub substrate_origin: DiagnosticAdmissionSubstrateOriginV3,
    pub disposition: DiagnosticSourceDispositionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judgment: Option<DiagnosticAdmissionJudgmentV1>,
    pub nonclaims: Vec<String>,
}

#[allow(missing_docs)]
#[allow(clippy::missing_errors_doc)]
impl DiagnosticAdmissionProvenanceV3 {
    pub(crate) fn seal(mut self) -> Result<Self, String> {
        self.schema = DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA_V3.into();
        self.provenance_id = nq_protocol::sha256_bytes(b"pending v3 provenance identity");
        self.nonclaims = NONCLAIMS.into_iter().map(str::to_owned).collect();
        self.provenance_id = self.computed_provenance_id()?;
        self.validate()?;
        Ok(self)
    }

    pub fn computed_provenance_id(&self) -> Result<Sha256Digest, String> {
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "diagnostic admission provenance v3 is not an object".to_owned())?
            .remove("provenance_id");
        semantic_digest(&value).map_err(|error| error.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != DIAGNOSTIC_ADMISSION_PROVENANCE_SCHEMA_V3 {
            return Err("unsupported diagnostic admission provenance v3 schema".into());
        }
        self.substrate_origin
            .intent
            .validate()
            .map_err(|error| error.to_string())?;
        if self.source.kind != "local_nq_store"
            || self.source.source_id.trim().is_empty()
            || self.source.source_id.chars().any(char::is_whitespace)
        {
            return Err("diagnostic admission source identity is invalid".into());
        }
        if self.artifact.contract_schema != DIAGNOSTIC_EXECUTION_V2_SCHEMA
            || self.artifact.canonical_bytes_length == 0
        {
            return Err("diagnostic admission artifact binding is invalid".into());
        }
        if self.origin.run_id.is_empty()
            || self
                .origin
                .evaluation_id
                .as_ref()
                .is_some_and(String::is_empty)
            || DateTime::parse_from_rfc3339(&self.origin.completed_at).is_err()
            || DateTime::parse_from_rfc3339(&self.origin.committed_at).is_err()
        {
            return Err("diagnostic admission local origin is invalid".into());
        }
        if self.provider.provider_intake_id.is_empty()
            || self.provider.source_admission_id.is_empty()
        {
            return Err("diagnostic admission provider binding is invalid".into());
        }
        if self.substrate_origin.intent.intake_id != self.provider.provider_intake_id
            || self.substrate_origin.intent.run_id != self.origin.run_id
            || self
                .substrate_origin
                .intent
                .canonical_digest()
                .map_err(|error| error.to_string())?
                != self.substrate_origin.intent_digest.as_str()
            || self.substrate_origin.phases
                != ["provider_invocation_started", "provider_intake_completed"]
        {
            return Err(
                "diagnostic admission substrate origin does not bind exact intent/intake lifecycle"
                    .into(),
            );
        }
        if self.nonclaims != NONCLAIMS.into_iter().map(str::to_owned).collect::<Vec<_>>() {
            return Err("diagnostic admission v3 nonclaims differ from the closed contract".into());
        }
        match (self.disposition, &self.judgment) {
            (DiagnosticSourceDispositionV1::AdmittedReport, Some(judgment))
                if !judgment.report_id.is_empty()
                    && judgment.judgment_schema == nq_store::JUDGMENT_SCHEMA_VERSION => {}
            (DiagnosticSourceDispositionV1::AdmittedReport, _) => {
                return Err("admitted report provenance requires its exact judgment".into());
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(
                    "non-admitted source disposition cannot carry a report judgment".into(),
                );
            }
        }
        if self.provenance_id != self.computed_provenance_id()? {
            return Err("diagnostic admission provenance v3 identity mismatch".into());
        }
        Ok(())
    }
}

/// Closed production export family. V1 history is never upgraded into V2 proof.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SupportedDiagnosticAdmissionProvenance {
    /// Historical local admission without continuity prerequisite.
    V1(Box<DiagnosticAdmissionProvenanceV1>),
    /// Admission whose acquisition durably committed Standing authority first.
    V2(Box<DiagnosticAdmissionProvenanceV2>),
    /// Admission whose acquisition bound independently signed substrate-origin
    /// evidence before provider invocation.
    V3(Box<DiagnosticAdmissionProvenanceV3>),
}
