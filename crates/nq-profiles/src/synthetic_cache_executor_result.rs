//! Admission contract for one past, Docket-bound synthetic-cache result.

use crate::{
    CardinalityLimits, Detector, DetectorDescriptor, DetectorEvidence, DetectorInput,
    DetectorResult, DetectorRuleParameters, DetectorState, EvidenceBasis, FreshnessPolicy,
    ProfileDescriptor, ProfileModule, ProfileProjection, ProfileRefusal, ProfileRefusalCode,
    ProjectionResult, RefusalBoundary, SemanticCoverageState, SemanticReportStatus, SubjectRules,
    ValidatedReport, ValidationContext, ValidationResult, VocabularyTerm,
    descriptor::PROFILE_DESCRIPTOR_SCHEMA,
    detector::DETECTOR_DESCRIPTOR_SCHEMA,
    validation::{ReportInput, validate_basis, validate_common},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{any::Any, collections::BTreeMap, sync::LazyLock};

/// Stable profile identifier.
pub const PROFILE_ID: &str = "nq.synthetic_cache_executor_result";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;
/// Stateless compiled module.
#[derive(Debug)]
pub struct SyntheticCacheExecutorResultProfile;
/// Singleton module.
pub static MODULE: SyntheticCacheExecutorResultProfile = SyntheticCacheExecutorResultProfile;

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "synthetic_cache_executor_result".into(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Past Docket-bound synthetic-cache executor result".into(),
    observation_kinds: vec![VocabularyTerm::new(
        "settled_executor_result",
        "One exact past settled executor result",
    )],
    coverage: vec![VocabularyTerm::new(
        "synthetic_cache_result",
        "Fixed health, cache sequence, failover, and restoration observations",
    )],
    subjects: SubjectRules {
        namespace: "sha256:".into(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new(
        "synthetic_cache_executor_attempt",
        "One exact Docket attempt and executor plan",
    )],
    vantages: vec![VocabularyTerm::new(
        "retained_docket_state",
        "Read-only retained Docket and executor records",
    )],
    access_paths: vec![VocabularyTerm::new(
        "docket_sqlite_and_executor_record",
        "Read-only SQLite and fixed-file acquisition",
    )],
    bases: vec![VocabularyTerm::new(
        "docket_settlement_and_executor_receipt",
        "Exact settlement joined to the executor-record receipt",
    )],
    regimes: vec![VocabularyTerm::new(
        "past_attempt",
        "Past execution testimony, not current service health",
    )],
    capabilities: vec![VocabularyTerm::new(
        "read_settled_cache_result",
        "Read retained records without replaying effects",
    )],
    freshness: FreshnessPolicy {
        reliance_seconds: 60,
        alignment_seconds: 0,
    },
    limits: CardinalityLimits {
        max_observations: 1,
        max_payload_bytes: 65_536,
        max_subject_bytes: 71,
        max_coverage_declarations: 1,
    },
    disturbance_assumptions: vec![
        "Reading retained records does not repeat cache requests or lifecycle effects".into(),
        "A matching record establishes only what the exact past attempt reported".into(),
    ],
});
/// Detector proving the fixed past attempt result is current enough for reliance.
#[derive(Debug)]
pub struct SyntheticCacheResultDetector;
/// Singleton detector.
pub static SYNTHETIC_CACHE_RESULT_DETECTOR: SyntheticCacheResultDetector =
    SyntheticCacheResultDetector;
static DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| DetectorDescriptor {
    schema: DETECTOR_DESCRIPTOR_SCHEMA.into(),
    id: "nq.synthetic_cache_executor_result.fixed_result".into(),
    version: 1,
    profile: DESCRIPTOR.profile.clone(),
    profile_digest: DESCRIPTOR
        .digest()
        .expect("compiled descriptor canonicalizes"),
    title: "Expected past synthetic-cache executor result".into(),
    condition: "expected_synthetic_cache_result_missing".into(),
    parameters: DetectorRuleParameters::SyntheticCacheExecutorResult,
});
static DETECTORS: [&'static dyn Detector; 1] = [&SYNTHETIC_CACHE_RESULT_DETECTOR];

impl Detector for SyntheticCacheResultDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &DETECTOR_DESCRIPTOR
    }
    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        let Some(occurrence) = input
            .reports
            .iter()
            .filter(|v| v.report.instance_id == input.instance_id)
            .max_by_key(|v| v.report_sequence)
        else {
            return cannot_evaluate(
                input,
                "no admitted cache-result testimony",
                "missing_testimony",
            );
        };
        let report = &occurrence.report;
        let Some(observation) = report.observations.first() else {
            return cannot_evaluate(
                input,
                "cache-result testimony lacks its observation",
                "missing_observation",
            );
        };
        let Ok(payload) = serde_json::from_value::<ResultPayload>(observation.payload.clone())
        else {
            return cannot_evaluate(
                input,
                "cache-result testimony payload cannot be reopened",
                "projection_failure",
            );
        };
        let Some(executor_observed_at) =
            chrono::DateTime::from_timestamp_millis(payload.executor_observed_at_unix_ms)
        else {
            return cannot_evaluate(
                input,
                "executor observation time is invalid",
                "invalid_executor_observation_time",
            );
        };
        let age = input
            .evaluated_at
            .signed_duration_since(executor_observed_at);
        if report.profile != DESCRIPTOR.profile
            || report.profile_digest != DETECTOR_DESCRIPTOR.profile_digest
            || report.status != SemanticReportStatus::Complete
            || report.coverage.get("synthetic_cache_result")
                != Some(&SemanticCoverageState::Complete)
            || age < chrono::Duration::zero()
            || age > chrono::Duration::seconds(DESCRIPTOR.freshness.reliance_seconds as i64)
        {
            return cannot_evaluate(
                input,
                "cache-result testimony is missing, stale, or incomplete",
                "missing_or_stale_testimony",
            );
        }
        DetectorResult { state:DetectorState::ExplicitlyAbsent, condition:DETECTOR_DESCRIPTOR.condition.clone(), summary:"the exact past synthetic-cache attempt reported the fixed expected result".into(), evidence:vec![DetectorEvidence{report_id:occurrence.report_id.clone(),report_sequence:occurrence.report_sequence,report_digest:report.report_digest.clone(),observation_ordinal:Some(observation.ordinal),observed_at:observation.observed_at}], limitations:vec!["This conclusion describes one past attempt and does not establish current cache health".into()], refusal:None, watermark:input.watermark }
    }
}

fn cannot_evaluate(input: &DetectorInput<'_>, summary: &str, reason: &str) -> DetectorResult {
    DetectorResult::cannot_evaluate_with_details(
        input,
        &DETECTOR_DESCRIPTOR,
        summary,
        vec!["Missing or stale retained testimony cannot establish the past result".into()],
        BTreeMap::from([("reason".into(), reason.into())]),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AttemptScope {
    attempt: String,
    marker: String,
    subject: String,
    scope: String,
    work: String,
    work_schema: String,
    executor_plan: String,
    executor_program_digest: String,
    docket_database: String,
    executor_record: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheRow {
    cache: String,
    cache_node: String,
    origin_count: String,
    status: u16,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultPayload {
    evidence_basis: EvidenceBasis,
    attempt: String,
    marker: String,
    subject: String,
    scope: String,
    work: String,
    work_schema: String,
    executor_plan: String,
    executor_program_digest: String,
    settlement: String,
    receipt: String,
    outcome: String,
    executor_observed_at_unix_ms: i64,
    health_status: u16,
    cache_sequence: Vec<CacheRow>,
    failure_cache_nodes: Vec<String>,
    restored_nodes: Vec<String>,
}

/// Minimal rebuildable projection of one admitted past result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultProjection {
    profile: crate::ProfileKey,
    /// Observation ordinal.
    pub ordinal: u32,
    /// Attempt digest.
    pub attempt: String,
    /// Settlement digest.
    pub settlement: String,
    /// Executor receipt.
    pub receipt: String,
}
impl ProfileProjection for ResultProjection {
    fn profile(&self) -> &crate::ProfileKey {
        &self.profile
    }
    fn ordinal(&self) -> u32 {
        self.ordinal
    }
    fn canonical_json(&self) -> Value {
        json!({"profile":self.profile,"ordinal":self.ordinal,"attempt":self.attempt,"settlement":self.settlement,"receipt":self.receipt})
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ProfileModule for SyntheticCacheExecutorResultProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &DESCRIPTOR
    }
    fn validate_binding(&self, c: &ValidationContext) -> Result<(), ProfileRefusal> {
        binding(c, self.descriptor()).map(|_| ())
    }
    fn validate(&self, c: &ValidationContext, r: &ReportInput) -> ValidationResult {
        let s = binding(c, self.descriptor())?;
        let a = validate_common(self.descriptor(), c, r)?;
        if a.status == SemanticReportStatus::Failed {
            return Ok(a);
        }
        match a.coverage.get("synthetic_cache_result") {
            Some(SemanticCoverageState::Complete) if a.observations.len() == 1 => {}
            Some(SemanticCoverageState::Unavailable) if a.observations.is_empty() => return Ok(a),
            _ => {
                return Err(inconsistent(
                    c,
                    self.descriptor(),
                    "coverage and observation cardinality disagree",
                ));
            }
        }
        let o = &a.observations[0];
        let p: ResultPayload = serde_json::from_value(o.payload.clone())
            .map_err(|e| invalid(c, self.descriptor(), e.to_string()))?;
        validate_basis(self.descriptor(), c, &p.evidence_basis)?;
        if p.evidence_basis.capabilities_used != a.used_capabilities
            || o.observed_at != a.observed_at
        {
            return Err(inconsistent(
                c,
                self.descriptor(),
                "basis or original observation time differs",
            ));
        }
        if p.attempt != s.attempt
            || p.marker != s.marker
            || p.subject != s.subject
            || p.scope != s.scope
            || p.work != s.work
            || p.work_schema != s.work_schema
            || p.executor_plan != s.executor_plan
            || p.executor_program_digest != s.executor_program_digest
        {
            return Err(inconsistent(
                c,
                self.descriptor(),
                "payload differs from exact attempt scope",
            ));
        }
        let expected = [
            ("MISS", "cache-a", "1"),
            ("MISS", "cache-b", "2"),
            ("HIT", "cache-a", "1"),
            ("HIT", "cache-b", "2"),
        ];
        let sequence_ok = p.cache_sequence.len() == 4
            && p.cache_sequence.iter().zip(expected).all(|(v, e)| {
                (
                    v.cache.as_str(),
                    v.cache_node.as_str(),
                    v.origin_count.as_str(),
                    v.status,
                ) == (e.0, e.1, e.2, 200)
            });
        if p.outcome != "success"
            || !digest(&p.settlement)
            || !digest(&p.receipt)
            || p.health_status != 200
            || !sequence_ok
            || p.failure_cache_nodes.len() != 4
            || p.failure_cache_nodes.iter().any(|v| v != "cache-b")
            || p.restored_nodes != ["cache-a", "cache-b"]
        {
            return Err(inconsistent(
                c,
                self.descriptor(),
                "result lacks the fixed successful observations",
            ));
        }
        Ok(a)
    }
    fn project(&self, r: &ValidatedReport) -> ProjectionResult {
        r.observations
            .iter()
            .map(|o| {
                let p: ResultPayload = serde_json::from_value(o.payload.clone())
                    .map_err(|e| projection_failure(r, e.to_string()))?;
                Ok(Box::new(ResultProjection {
                    profile: r.profile.clone(),
                    ordinal: o.ordinal,
                    attempt: p.attempt,
                    settlement: p.settlement,
                    receipt: p.receipt,
                }) as Box<dyn ProfileProjection>)
            })
            .collect()
    }
    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &DETECTORS
    }
}
fn binding(c: &ValidationContext, d: &ProfileDescriptor) -> Result<AttemptScope, ProfileRefusal> {
    if c.scope.kind != "synthetic_cache_executor_attempt" {
        return Err(scope_error(c, d, "scope kind differs"));
    }
    let s: AttemptScope = serde_json::from_value(c.scope.value.clone())
        .map_err(|e| scope_error(c, d, &e.to_string()))?;
    if c.request_subject != s.subject
        || s.work_schema != "maude.local-compose-workflow/v1"
        || c.vantage.kind != "retained_docket_state"
        || c.vantage.value != json!({})
        || [
            &s.attempt,
            &s.marker,
            &s.subject,
            &s.scope,
            &s.work,
            &s.executor_plan,
            &s.executor_program_digest,
        ]
        .iter()
        .any(|v| !digest(v))
        || ![&s.docket_database, &s.executor_record]
            .iter()
            .all(|v| v.starts_with('/'))
    {
        return Err(scope_error(c, d, "attempt binding is not exact"));
    }
    Ok(s)
}
fn digest(v: &str) -> bool {
    v.len() == 71
        && v.starts_with("sha256:")
        && v[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn scope_error(c: &ValidationContext, d: &ProfileDescriptor, m: &str) -> ProfileRefusal {
    ProfileRefusal::new(
        c,
        d,
        RefusalBoundary::Profile,
        ProfileRefusalCode::ScopeEscape,
        m,
    )
}
fn inconsistent(c: &ValidationContext, d: &ProfileDescriptor, m: &str) -> ProfileRefusal {
    ProfileRefusal::new(
        c,
        d,
        RefusalBoundary::Report,
        ProfileRefusalCode::InconsistentReport,
        m,
    )
}
fn invalid(c: &ValidationContext, d: &ProfileDescriptor, e: String) -> ProfileRefusal {
    ProfileRefusal::new(
        c,
        d,
        RefusalBoundary::Observation,
        ProfileRefusalCode::InvalidPayload,
        "payload does not match retained cache result",
    )
    .with_detail("error", e)
}
fn projection_failure(r: &ValidatedReport, e: String) -> ProfileRefusal {
    ProfileRefusal {
        instance_id: r.instance_id.clone(),
        profile: r.profile.clone(),
        boundary: RefusalBoundary::Observation,
        code: ProfileRefusalCode::InvalidPayload,
        message: "admitted cache result could not be projected".into(),
        details: BTreeMap::from([("error".into(), e)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone as _, Utc};
    use std::collections::BTreeSet;

    const D: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn context() -> ValidationContext {
        ValidationContext {
            instance_id: "cache-result-qualification".into(),
            request_subject: D.into(),
            scope: crate::ScopeGrant {
                kind: "synthetic_cache_executor_attempt".into(),
                value: json!({"attempt":D,"marker":D,"subject":D,"scope":D,"work":D,"work_schema":"maude.local-compose-workflow/v1","executor_plan":D,"executor_program_digest":D,"docket_database":"/tmp/docket.sqlite3","executor_record":"/tmp/result.json"}),
            },
            vantage: crate::VantageGrant {
                kind: "retained_docket_state".into(),
                value: json!({}),
            },
            granted_capabilities: BTreeSet::from(["read_settled_cache_result".into()]),
            received_at: Utc
                .with_ymd_and_hms(2026, 9, 11, 12, 0, 30)
                .single()
                .unwrap(),
            max_observations: 1,
            max_future_skew: Duration::seconds(5),
        }
    }

    fn report(observed_at: chrono::DateTime<Utc>) -> ReportInput {
        let c = context();
        let basis = json!({"scope":c.scope,"vantage":c.vantage,"access_path":"docket_sqlite_and_executor_record","basis":"docket_settlement_and_executor_receipt","regime":"past_attempt","capabilities_used":["read_settled_cache_result"]});
        ReportInput {
            report_digest: format!("sha256:{}", "b".repeat(64)),
            profile: DESCRIPTOR.profile.clone(),
            profile_digest: DESCRIPTOR.digest().unwrap().as_str().into(),
            status: SemanticReportStatus::Complete,
            observed_at,
            coverage: vec![crate::CoverageInput {
                name: "synthetic_cache_result".into(),
                subject: None,
                state: SemanticCoverageState::Complete,
                detail: None,
            }],
            observations: vec![crate::ObservationInput {
                kind: "settled_executor_result".into(),
                subject: D.into(),
                ordinal: 0,
                observed_at,
                payload: json!({"evidence_basis":basis,"attempt":D,"marker":D,"subject":D,"scope":D,"work":D,"work_schema":"maude.local-compose-workflow/v1","executor_plan":D,"executor_program_digest":D,"settlement":D,"receipt":D,"outcome":"success","executor_observed_at_unix_ms":observed_at.timestamp_millis(),"health_status":200,"cache_sequence":[{"cache":"MISS","cache_node":"cache-a","origin_count":"1","status":200},{"cache":"MISS","cache_node":"cache-b","origin_count":"2","status":200},{"cache":"HIT","cache_node":"cache-a","origin_count":"1","status":200},{"cache":"HIT","cache_node":"cache-b","origin_count":"2","status":200}],"failure_cache_nodes":["cache-b","cache-b","cache-b","cache-b"],"restored_nodes":["cache-a","cache-b"]}),
            }],
            error_count: 0,
            failure_error_count: 0,
            used_capabilities: BTreeSet::from(["read_settled_cache_result".into()]),
        }
    }

    #[test]
    fn validates_exact_past_result() {
        let c = context();
        assert!(
            MODULE
                .validate(&c, &report(c.received_at - Duration::seconds(30)))
                .is_ok()
        );
    }

    #[test]
    fn validation_preserves_past_time_for_detector_currentness() {
        let c = context();
        assert!(
            MODULE
                .validate(&c, &report(c.received_at - Duration::seconds(61)))
                .is_ok()
        );
    }

    #[test]
    fn detector_refuses_stale_original_observation() {
        let c = context();
        let admitted = MODULE
            .validate(&c, &report(c.received_at - Duration::seconds(30)))
            .unwrap();
        let row = crate::DetectorReport {
            report_id: "report:cache".into(),
            report_sequence: 1,
            report: admitted,
        };
        let input = crate::DetectorInput {
            instance_id: &c.instance_id,
            evaluated_at: c.received_at + Duration::seconds(31),
            watermark: crate::EvidenceWatermark(1),
            reports: std::slice::from_ref(&row),
            threshold_policy: None,
        };
        let result = SYNTHETIC_CACHE_RESULT_DETECTOR.evaluate(&input);
        assert_eq!(result.state, crate::DetectorState::CannotEvaluate);
        assert_eq!(
            result
                .refusal
                .unwrap()
                .details
                .get("reason")
                .map(String::as_str),
            Some("missing_or_stale_testimony")
        );
    }

    #[test]
    fn changed_cache_sequence_is_refused() {
        let c = context();
        let mut r = report(c.received_at - Duration::seconds(30));
        r.observations[0].payload["cache_sequence"][2]["origin_count"] = json!("3");
        assert_eq!(
            MODULE.validate(&c, &r).unwrap_err().code,
            ProfileRefusalCode::InconsistentReport
        );
    }
}
