//! Query-only exact admitted-observation custody. This does not collect,
//! reevaluate, refresh evidence, or grant present reliance or effect authority.
use crate::engine::EngineError;
use chrono::{DateTime, Utc};
use nq_profiles::{DetectorEvidence, ValidatedReport};
use nq_protocol::{EvidenceReport, Observation};
use nq_store::{CanonicalDocument, Store};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "nq.admitted-observation-export/v1";
pub const MAX_BYTES: usize = 1_048_576;

/// Exact existing detector evidence fields, with unknown additions refused.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReferenceV1 {
    pub report_id: String,
    pub report_sequence: u64,
    pub report_digest: String,
    pub observation_ordinal: u32,
    pub observed_at: DateTime<Utc>,
}
impl From<ObservationReferenceV1> for DetectorEvidence {
    fn from(value: ObservationReferenceV1) -> Self {
        Self {
            report_id: value.report_id,
            report_sequence: value.report_sequence,
            report_digest: value.report_digest,
            observation_ordinal: Some(value.observation_ordinal),
            observed_at: value.observed_at,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedObservationExportV1 {
    pub schema: String,
    pub evidence: DetectorEvidence,
    pub instance_id: String,
    pub received_at: DateTime<Utc>,
    pub profile: nq_protocol::ProfileBinding,
    pub binding: nq_protocol::SubjectBinding,
    pub report_observed_at: DateTime<Utc>,
    pub report_status: nq_protocol::ReportStatus,
    pub backend: nq_protocol::BackendProvenance,
    pub used_capabilities: Vec<nq_protocol::Capability>,
    pub observation: Observation,
    pub standing: String,
}

/// Resolve all five existing detector-evidence fields against verified custody.
/// # Errors
/// Refuses absent, altered, oversized, noncanonical or unbound evidence. Reads
/// only the named committed observation; it does not invoke any helper.
pub fn export_admitted_observation(
    store: &Store,
    evidence: &DetectorEvidence,
) -> Result<AdmittedObservationExportV1, EngineError> {
    nq_protocol::Sha256Digest::parse(evidence.report_digest.clone())
        .map_err(|error| invalid(&error.to_string()))?;
    let ordinal = evidence
        .observation_ordinal
        .ok_or_else(|| invalid("observation ordinal is required"))?;
    if evidence.report_id.len() > 256 || evidence.report_id.is_empty() {
        return Err(invalid("invalid report identity bound"));
    }
    let row = store
        .admitted_evidence_reference(&evidence.report_id, &evidence.report_digest, Some(ordinal))?
        .ok_or_else(|| invalid("exact admitted evidence reference unavailable"))?;
    if !row.observation_exists
        || u64::try_from(row.report_sequence).ok() != Some(evidence.report_sequence)
        || row.canonical_json.len() > MAX_BYTES
    {
        return Err(invalid(
            "report sequence, observation or byte bound mismatch",
        ));
    }
    let snapshot = store
        .verify_admitted_snapshot(&evidence.report_id)
        .map_err(|error| invalid(&error.to_string()))?;
    let document = CanonicalDocument::from_canonical_bytes(row.canonical_json)?;
    let report: EvidenceReport =
        serde_json::from_slice(document.as_bytes()).map_err(|error| invalid(&error.to_string()))?;
    nq_protocol::validate_report(&report)
        .map_err(|error| invalid(&format!("report invalid: {error}")))?;
    if nq_protocol::semantic_digest(&report)
        .map_err(|error| invalid(&error.to_string()))?
        .as_str()
        != evidence.report_digest
    {
        return Err(invalid("canonical report digest mismatch"));
    }
    let admitted: ValidatedReport = serde_json::from_slice(&snapshot.validated_report_json)
        .map_err(|error| invalid(&error.to_string()))?;
    if admitted.instance_id != row.instance_id
        || admitted.report_digest != evidence.report_digest
        || admitted.profile.id != report.profile.id.as_str()
        || admitted.profile.version.to_string() != report.profile.version.as_str()
        || admitted.profile_digest != report.profile.digest.as_str()
    {
        return Err(invalid("admitted profile provenance mismatch"));
    }
    let observation = report
        .observations
        .iter()
        .find(|observation| observation.ordinal == ordinal)
        .ok_or_else(|| invalid("observation unavailable"))?
        .clone();
    if observation.observed_at != evidence.observed_at
        || row
            .observation_observed_at
            .as_deref()
            .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.with_timezone(&Utc))
            != Some(evidence.observed_at)
    {
        return Err(invalid("observation time mismatch"));
    }
    let received_at = DateTime::parse_from_rfc3339(&row.received_at)
        .map_err(|error| invalid(&error.to_string()))?
        .with_timezone(&Utc);
    let exported = AdmittedObservationExportV1 {
        schema: SCHEMA.into(),
        evidence: evidence.clone(),
        instance_id: row.instance_id,
        received_at,
        profile: report.profile,
        binding: report.binding,
        report_observed_at: report.observed_at,
        report_status: report.status,
        backend: report.backend,
        used_capabilities: report.used_capabilities,
        observation,
        standing: "historical_custody_only".into(),
    };
    if serde_json::to_vec(&exported)
        .map_err(|error| invalid(&error.to_string()))?
        .len()
        > MAX_BYTES
    {
        return Err(invalid("export exceeds byte bound"));
    }
    Ok(exported)
}
fn invalid(message: &str) -> EngineError {
    EngineError::Invariant(format!("admitted observation export: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_wire_vector_names_the_native_report_and_exact_reference() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json"
        )).unwrap();
        let export: AdmittedObservationExportV1 =
            serde_json::from_value(vectors["export"].clone()).unwrap();
        let reference: ObservationReferenceV1 =
            serde_json::from_value(vectors["cases"][0]["reference"].clone()).unwrap();
        let evidence: DetectorEvidence = reference.into();
        assert_eq!(
            serde_json::to_value(evidence).unwrap(),
            serde_json::to_value(&export.evidence).unwrap()
        );
        let report: EvidenceReport = serde_json::from_value(vectors["report"].clone()).unwrap();
        assert_eq!(
            nq_protocol::semantic_digest(&report).unwrap().as_str(),
            export.evidence.report_digest
        );
        assert_eq!(
            serde_json::to_value(&export.observation).unwrap(),
            serde_json::to_value(&report.observations[0]).unwrap()
        );
        assert_eq!(export.schema, SCHEMA);
        assert_eq!(export.standing, "historical_custody_only");
        assert_eq!(export.profile.version.as_str(), "3");
        let mut extra = vectors["cases"][0]["reference"].clone();
        extra["current"] = true.into();
        assert!(serde_json::from_value::<ObservationReferenceV1>(extra).is_err());
    }
}
