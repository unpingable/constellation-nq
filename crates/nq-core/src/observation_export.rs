//! Query-only exact admitted-observation custody. This does not collect,
//! reevaluate, refresh evidence, or grant present reliance or effect authority.
use crate::engine::EngineError;
use chrono::{DateTime, SecondsFormat, Utc};
use nq_profiles::{DetectorEvidence, ValidatedReport};
use nq_protocol::{EvidenceReport, Observation};
use nq_store::{CanonicalDocument, Store};
use serde::{Deserialize, Serialize};

/// Exact query-only export schema identity.
pub const SCHEMA: &str = "nq.admitted-observation-export/v1";
/// Source report and serialized export byte ceiling.
pub const MAX_BYTES: usize = 1_048_576;

/// Exact existing detector evidence fields, with unknown additions refused.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReferenceV1 {
    /// Exact admitted report identity.
    pub report_id: String,
    /// Exact monotonic admitted report sequence.
    pub report_sequence: u64,
    /// Exact canonical semantic source report digest.
    pub report_digest: String,
    /// Required native observation ordinal within the report.
    pub observation_ordinal: u32,
    /// Exact native observation timestamp.
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

/// Named exact timestamp form used by an observation reference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceTimeBasis {
    /// Exact native protocol observation timestamp.
    NativeObservationTime,
    /// Exact millisecond projection sealed by the existing evaluation carrier.
    EvaluationMillisecondProjection,
}

fn reference_time_basis(
    native: DateTime<Utc>,
    reference: DateTime<Utc>,
) -> Option<ReferenceTimeBasis> {
    if native == reference {
        Some(ReferenceTimeBasis::NativeObservationTime)
    } else if DateTime::parse_from_rfc3339(&native.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok()
        .map(|at| at.with_timezone(&Utc))
        == Some(reference)
    {
        Some(ReferenceTimeBasis::EvaluationMillisecondProjection)
    } else {
        None
    }
}

/// Authenticated historical custody of one exact native observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedObservationExportV1 {
    /// Exact export schema.
    pub schema: String,
    /// Joined detector evidence coordinates.
    pub evidence: DetectorEvidence,
    /// Named exact relation between supplied reference and native observation time.
    pub reference_time_basis: ReferenceTimeBasis,
    /// Original admitted watcher instance identity.
    pub instance_id: String,
    /// Historical admission receipt time, never export time.
    pub received_at: DateTime<Utc>,
    /// Native bound profile identity and descriptor digest.
    pub profile: nq_protocol::ProfileBinding,
    /// Native exact logical subject, scope and vantage.
    pub binding: nq_protocol::SubjectBinding,
    /// Native containing report observation timestamp.
    pub report_observed_at: DateTime<Utc>,
    /// Native containing report status.
    pub report_status: nq_protocol::ReportStatus,
    /// Original report producer implementation and tool provenance.
    pub backend: nq_protocol::BackendProvenance,
    /// Capabilities recorded as exercised by the source report.
    pub used_capabilities: Vec<nq_protocol::Capability>,
    /// Exact native admitted observation, including raw profile payload.
    pub observation: Observation,
    /// Always historical custody only; no currentness or effects grant.
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
        || admitted.profile_digest.as_str() != report.profile.digest.as_str()
    {
        return Err(invalid("admitted profile provenance mismatch"));
    }
    let observation = report
        .observations
        .iter()
        .find(|observation| observation.ordinal == ordinal)
        .ok_or_else(|| invalid("observation unavailable"))?
        .clone();
    let reference_time_basis = reference_time_basis(observation.observed_at, evidence.observed_at)
        .ok_or_else(|| {
            invalid(
                "observation reference time is neither native nor its exact evaluation projection",
            )
        })?;
    // The existing admission index deliberately stores the engine's canonical
    // millisecond projection. Native bytes and the supplied reference remain
    // unrounded in this export; arbitrary within-millisecond changes refuse.
    if row.observation_observed_at.as_deref()
        != Some(
            observation
                .observed_at
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_str(),
        )
    {
        return Err(invalid("observation index time projection mismatch"));
    }
    let received_at = DateTime::parse_from_rfc3339(&row.received_at)
        .map_err(|error| invalid(&error.to_string()))?
        .with_timezone(&Utc);
    let exported = AdmittedObservationExportV1 {
        schema: SCHEMA.into(),
        evidence: evidence.clone(),
        reference_time_basis,
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

#[cfg(test)]
mod precision_tests {
    use super::*;
    #[test]
    fn shared_fractional_vectors_preserve_exact_native_or_declared_projection_only() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json"
        )).unwrap();
        for case in vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["name"].as_str().unwrap().starts_with("nanos_"))
        {
            let response: AdmittedObservationExportV1 =
                serde_json::from_value(case["response"].clone()).unwrap();
            let report: EvidenceReport =
                serde_json::from_value(case["source_report"].clone()).unwrap();
            assert_eq!(
                nq_protocol::semantic_digest(&report).unwrap().as_str(),
                response.evidence.report_digest
            );
            let actual = reference_time_basis(
                response.observation.observed_at,
                response.evidence.observed_at,
            );
            let valid = actual == Some(response.reference_time_basis);
            assert_eq!(
                valid,
                case["expected_reliance"] == "current",
                "{}",
                case["name"]
            );
            assert_eq!(
                response.observation.observed_at,
                report.observations[0].observed_at
            );
        }
    }
}
