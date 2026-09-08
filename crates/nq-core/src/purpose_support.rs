//! Purpose-bound read-only consideration of locally qualified diagnostics.
//! Source-world currentness is separate from artifact-age policy. This surface
//! cannot authorize effects, repair a missing premise, or make imports local.
use crate::diagnostic_execution::{
    DiagnosticClaimStatusV1, DiagnosticCoherenceV1, DiagnosticDerivationV1,
};
use crate::diagnostic_execution_supported::SupportedDiagnosticExecution;
use crate::diagnostic_execution_v2::{ClockQualificationV2, DiagnosticExecutionV2};
use chrono::{DateTime, Utc};
use nq_protocol::{Sha256Digest, semantic_digest};
use nq_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SCHEMA: &str = "nq.diagnostic-purpose-support/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeRequest {
    pub artifact_id: Sha256Digest,
    pub consumer: String,
    pub purpose: String,
    pub subject_digest: Sha256Digest,
    pub claim: String,
    pub evaluated_at: DateTime<Utc>,
    pub maximum_artifact_age_seconds: u64,
    pub require_source_currentness: bool,
    pub supporting_artifact_ids: Vec<Sha256Digest>,
    #[serde(default)]
    pub continuity_support: Option<crate::continuity_support::ContinuitySupport>,
}

fn reopen(store: &Store, id: &Sha256Digest) -> Result<DiagnosticExecutionV2, String> {
    crate::qualify_diagnostic_admission(store, id).map_err(|e| e.to_string())?;
    match crate::engine::reopen_diagnostic_artifact(store, id).map_err(|e| e.to_string())? {
        SupportedDiagnosticExecution::V2(a) => Ok(a),
        _ => Err("purpose support requires locally admitted v2 diagnostic".into()),
    }
}

/// Reopens complete local provenance before producing any purpose testimony.
pub fn qualify(store: &Store, r: &PurposeRequest) -> Result<Value, String> {
    if r.maximum_artifact_age_seconds == 0
        || r.maximum_artifact_age_seconds > 900
        || r.supporting_artifact_ids.len() > 16
    {
        return Err("bounded request limits".into());
    }
    let a = reopen(store, &r.artifact_id)?;
    let provenance =
        crate::qualify_diagnostic_admission(store, &r.artifact_id).map_err(|e| e.to_string())?;
    let subject = semantic_digest(&a.subject).map_err(|e| e.to_string())?;
    let expires = a
        .completed_at
        .checked_add_signed(chrono::Duration::seconds(
            r.maximum_artifact_age_seconds as i64,
        ))
        .ok_or("expiry overflow")?;
    let claim = a.claims.iter().find(|c| c.claim_id == r.claim);
    let mut decision = "supported_readonly";
    let mut reasons = Vec::new();
    if !matches!(
        r.consumer.as_str(),
        "nightshift-readonly" | "nightshift-readonly-continuity"
    ) {
        decision = "consumer_unknown";
    } else if !matches!(
        r.purpose.as_str(),
        "historical_readonly" | "continue_observing"
    ) {
        decision = "purpose_not_authorized";
    } else if subject != r.subject_digest || r.evaluated_at < a.completed_at {
        decision = "malformed_request";
    } else if r.evaluated_at >= expires {
        decision = "stale_evidence";
    } else if a.outcome.coherence == DiagnosticCoherenceV1::Contradictory {
        decision = "contradiction_retained";
    } else if a.outcome.derivation == DiagnosticDerivationV1::Refused {
        decision = "cannot_testify";
    } else if a.outcome.derivation == DiagnosticDerivationV1::Unsupported {
        decision = "cannot_testify";
    } else if let Some(c) = claim {
        decision = match c.status {
            DiagnosticClaimStatusV1::Established => "supported_readonly",
            DiagnosticClaimStatusV1::Contradictory => "contradiction_retained",
            DiagnosticClaimStatusV1::Refuted | DiagnosticClaimStatusV1::Unknown => {
                "claim_not_verified"
            }
        };
        if !c.dependency_refusal_ids.is_empty() || !c.dependency_failure_ids.is_empty() {
            decision = "cannot_testify";
        }
    } else {
        decision = "claim_not_authorized_for_consumer";
    }
    // This family deliberately does not establish clock comparability. A
    // bounded source clock alone also needs a consumer-owned comparison law.
    if decision == "supported_readonly"
        && (r.require_source_currentness || r.purpose == "continue_observing")
    {
        decision = "cannot_testify";
        reasons.push("source-currentness requires a separately qualified clock-comparison contract; this family qualifies artifact-age only".to_owned());
    }
    let mut supporting = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut continuity = false;
    if let Some(s) = &r.continuity_support {
        crate::continuity_support::replay(s)?;
        if s.snapshot_context.is_none() {
            return Err("continuity support lacks scoped source-history qualification".into());
        }
        if s.binding.subject_digest != subject
            || s.binding.principal != r.consumer
            || s.binding.purpose != "continue_observing"
            || s.receipt_id == r.artifact_id
        {
            return Err(
                "continuity exact subject/principal/purpose or independence mismatch".into(),
            );
        }
        let source_time = DateTime::parse_from_rfc3339(&s.evaluation_time)
            .map_err(|e| e.to_string())?
            .with_timezone(&Utc);
        continuity = s.disposition == "eligible"
            && source_time <= r.evaluated_at
            && source_time
                .checked_add_signed(chrono::Duration::seconds(900))
                .is_some_and(|t| r.evaluated_at < t);
        supporting.push(json!({"claim":s.claim,"content_hash":s.receipt_id,"status":s.disposition,"subject":s.binding.subject_digest}));
        reasons.extend(s.limitations.clone());
    }
    for id in &r.supporting_artifact_ids {
        if id == &r.artifact_id || !seen.insert(id.clone()) {
            return Err("duplicate or primary-as-support artifact".into());
        }
        let s = reopen(store, id)?;
        let same_subject = semantic_digest(&s.subject).map_err(|e| e.to_string())? == subject;
        for c in &s.claims {
            supporting.push(json!({"claim":c.claim_id,"content_hash":id,"status":c.status,"subject":s.subject.id}));
            if c.claim_id == "continuity_rely_eligible"
                && c.status == DiagnosticClaimStatusV1::Established
                && same_subject
                && s.completed_at <= r.evaluated_at
                && s.completed_at
                    .checked_add_signed(chrono::Duration::seconds(900))
                    .is_some_and(|t| r.evaluated_at < t)
                && s.outcome.derivation == DiagnosticDerivationV1::Completed
                && s.outcome.coherence == DiagnosticCoherenceV1::JointlyEstablished
                && matches!(
                    s.attempt_interval.qualification,
                    ClockQualificationV2::Bounded { .. }
                )
            {
                // Matching names and a bounded producer clock still do not
                // establish the missing consumer clock-comparison contract.
                reasons.push("named continuity support present; consumer clock comparison remains unqualified".into());
            }
        }
    }
    if r.consumer == "nightshift-readonly-continuity"
        && !continuity
        && decision == "supported_readonly"
    {
        decision = "residual_obligation_blocks";
        reasons.push("required independently named current continuity_rely_eligible support is not established".to_owned());
    }
    let request_digest = semantic_digest(r).map_err(|e| e.to_string())?;
    let coverage_limits = vec![
        serde_json::to_string(&a.outcome.coverage).map_err(|e| e.to_string())?,
        serde_json::to_string(&a.limitations).map_err(|e| e.to_string())?,
        serde_json::to_string(&a.nonclaims).map_err(|e| e.to_string())?,
        serde_json::to_string(&claim.map(|c| (&c.limitations, &c.nonclaims)))
            .map_err(|e| e.to_string())?,
        serde_json::to_string(&a.outcome.refusals).map_err(|e| e.to_string())?,
        serde_json::to_string(&a.outcome.unsupported).map_err(|e| e.to_string())?,
    ];
    let mut out = json!({"schema":SCHEMA,"request":r,"decision_id":"","request_digest":request_digest,
        "evidence_context_digest":provenance.provenance_id,"consumer_profile_id":r.consumer,
        "caller_binding":"configured_local_store","caller_binding_disclosure":"configured consumer selection, not authenticated caller identity; local store provenance reopened",
        "purpose":r.purpose,"claim":r.claim,"subject_digest":subject,"receipt_content_hash":a.artifact_id,
        "underlying_status":claim.map(|c|json!(c.status)).unwrap_or(json!("unknown")),"decision":decision,
        "premises":[],"coverage_limits":coverage_limits,
        "unresolved_residuals":if continuity || r.consumer!="nightshift-readonly-continuity" {json!([])} else {json!(["continuity_rely_eligible required"])},
        "retained_contradictions":if a.outcome.coherence==DiagnosticCoherenceV1::Contradictory {json!(["source diagnostic contradictory"])} else {json!([])},
        "refusal_reasons":reasons,"establishes":if decision=="supported_readonly" {json!(["bounded read-only consideration of exact retained claim"])} else {json!([])},
        "does_not_establish":["no action authority","source-world currentness not established","source and resolver honesty remain environmental"],
        "supporting_receipts":supporting,"policy_version":"nq.readonly-artifact-consideration/v1","generated_at":r.evaluated_at,"expires_at":expires,
        "source_artifact":a,"admission_provenance":provenance});
    out.as_object_mut().unwrap().remove("decision_id");
    out["decision_id"] = json!(semantic_digest(&out).map_err(|e| e.to_string())?);
    Ok(out)
}
