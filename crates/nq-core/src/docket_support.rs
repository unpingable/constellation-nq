//! Closed factual Docket dossier profile; no settlement or authorization authority.
//! DTO wire shapes follow supported Docket c49ad8d services/dossier.rs.
//! Historical NQ DTOs supplied field inventory only, not runtime or interpretation.
#![allow(dead_code)]
use chrono::{DateTime, Utc};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dossier {
    dossier_format: String,
    attempt: String,
    state: String,
    version: u64,
    settlement: String,
    identity: Identity,
    authority: Authority,
    timeline: Vec<TimelineEntry>,
    execution: Execution,
    observation: ObservationSection,
    qualification: Option<Qualification>,
    /// Present only on v2 sources. Upstream *authorization* facts, kept
    /// distinct from the source's own settlement facts throughout.
    #[serde(default)]
    authorization: Option<Authorization>,
}

/// The source's authorization provenance, as v2 records it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    source: String,
    issuance: Option<Issuance>,
}

/// One upstream issuance the source verified and recorded.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Issuance {
    issuance_id: String,
    decision_id: String,
    issuer_principal: String,
    issuer_key_id: String,
    target_id: String,
    request_raw_sha256: String,
    request_upstream_digest: String,
    prepared_attempt_digest: String,
    requested_actor: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    accepted_at_ms: u64,
    upstream_premises: Vec<UpstreamPremise>,
    upstream_premises_meaning: String,
    upstream_residual_status: String,
    upstream_residuals: Vec<UpstreamResidual>,
    consumption_ledger: String,
    consumption_use_digest: String,
    establishes: String,
    does_not_establish: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamPremise {
    kind: String,
    statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamResidual {
    source_system: String,
    obligation_id: String,
    subject: String,
    kind: String,
    statement: String,
    discharged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    work_request: String,
    goal: String,
    /// v1/v2 operational path. It remains unchanged on legacy projections.
    #[serde(default)]
    repository: Option<String>,
    /// v3 Docket-owned logical repository identity.
    #[serde(default)]
    repository_id: Option<String>,
    /// v3 operational alias. This is never used as logical identity.
    #[serde(default)]
    repository_locator: Option<RepositoryLocator>,
    /// v3 primary logical subject. Null before a result commitment exists.
    #[serde(default)]
    ref_continuity_subject: Option<String>,
    target_ref: String,
    basis: String,
    effect_class: String,
    settlement_premises: Vec<String>,
    allowed_paths: Vec<String>,
    candidate: String,
    candidate_digest: String,
    patch_digest: String,
    preparation_run: String,
    candidate_ingested_at_ms: u64,
    prepared_attempt_digest: String,
    observation_plan: ObservationPlan,
    request_created_at_ms: u64,
    admitted_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryLocator {
    kind: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationPlan {
    argv: Vec<String>,
    environment: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    ratification: Option<Ratification>,
    ratifying_grant: Option<Grant>,
    reservation: Option<Reservation>,
    dispatch: Option<Dispatch>,
    recovery_grant: Option<Grant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ratification {
    ratification: String,
    actor: String,
    standing_use: String,
    at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    grant: String,
    actor: String,
    act: String,
    attempt_digest_binding: String,
    expires_at_ms: u64,
    consumed_by: Option<String>,
    used_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    reservation: String,
    basis: String,
    expires_at_ms: u64,
    consumed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dispatch {
    dispatch: String,
    created_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimelineEntry {
    seq: u64,
    kind: String,
    at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    settlement: String,
    commitment: Option<Commitment>,
    dispatch_refusal: Option<DispatchRefusal>,
    indeterminate: Option<Indeterminate>,
    recovery_facts: Vec<RecoveryFact>,
    resolution: Option<Resolution>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commitment {
    result_commit: String,
    previous_value: String,
    target_ref: String,
    journal_digest: String,
    committed_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchRefusal {
    ground: String,
    journal_digest: String,
    refused_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Indeterminate {
    last_journal_digest: Option<String>,
    recorded_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryFact {
    fact: String,
    source: String,
    source_detail: Option<String>,
    observed_ref: String,
    expected_result_commit: Option<String>,
    journal_digest: String,
    recorded_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    resolution: String,
    fact: String,
    verdict: String,
    recovery_standing_use: String,
    resolved_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationSection {
    observations: Vec<ObservationRecord>,
    reliance_admissions: Vec<RelianceAdmission>,
    reliance_refusals: Vec<RelianceRefusal>,
    residual_obligations: Vec<ResidualObligation>,
    reconciliation: Option<Reconciliation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationRecord {
    observation: String,
    argv: Vec<String>,
    working_directory: String,
    result_commit: String,
    environment: String,
    exit_status: i64,
    stdout_digest: String,
    stderr_digest: String,
    observed_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelianceAdmission {
    observation: String,
    result_commit: String,
    at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelianceRefusal {
    kind: String,
    detail: Option<String>,
    subject: Option<RelianceSubject>,
    at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelianceSubject {
    observation: String,
    consumer: String,
    claim: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidualObligation {
    obligation: String,
    kind: String,
    recorded_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconciliation {
    retained_obligations: Vec<String>,
    reconciled_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    verdict: String,
    proof_basis: String,
    fact: String,
    fact_source: String,
    #[serde(default)]
    custody_premise: Option<String>,
    #[serde(default)]
    custody_premise_asserted_not_verified: Option<bool>,
    observed_ref: String,
    expected_result_commit: Option<String>,
    observed_ref_owner: Option<String>,
    journal_digest: String,
    evidence_concordance: String,
    evidence_agrees: bool,
    establishes: String,
    does_not_establish: String,
}

pub const SCHEMA: &str = "nq.docket-purpose-support/v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub attempt: String,
    pub subject: String,
    pub consumer: String,
    pub purpose: String,
    pub claim: String,
    pub evaluated_at: DateTime<Utc>,
    pub continuity_support: Option<crate::continuity_support::ContinuitySupport>,
}

/// Observed by the bounded producer, never a file-import custody upgrade.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acquisition {
    pub executable_digest: Sha256Digest,
    pub state_locator: String,
    pub attempt: String,
    pub observed_at: DateTime<Utc>,
    pub raw_digest: Sha256Digest,
}

/// Replays the factual projection, not source authentication or present truth.
pub fn qualify(
    raw: &[u8],
    r: &Request,
    acquisition: Option<&Acquisition>,
) -> Result<Value, String> {
    let d: Dossier =
        nq_protocol::decode_json_document(raw, 4 * 1024 * 1024).map_err(|e| e.to_string())?;
    if d.dossier_format != "gwr:attempt-dossier:v3" || d.attempt != r.attempt {
        return Err("wrong Docket schema/attempt".into());
    }
    let repository = d
        .identity
        .repository_id
        .as_deref()
        .ok_or("missing Docket repository identity")?;
    let locator = d
        .identity
        .repository_locator
        .as_ref()
        .ok_or("missing locator")?;
    if repository.is_empty()
        || locator.kind != "path"
        || locator.value.is_empty()
        || d.identity.repository.is_some()
    {
        return Err("invalid v3 repository identity/locator".into());
    }
    let subject = if let Some(c) = &d.execution.commitment {
        if c.target_ref != d.identity.target_ref || c.result_commit.is_empty() {
            return Err("commitment/ref mismatch".into());
        }
        let exact = format!(
            "gwr:ref-continuity:v0:{repository}#{}@{}",
            c.target_ref, c.result_commit
        );
        if d.identity.ref_continuity_subject.as_deref() != Some(&exact) {
            return Err("Docket logical subject components mismatch".into());
        }
        exact
    } else {
        if d.identity.ref_continuity_subject.is_some() || d.state == "committed" {
            return Err("commitment absent for claimed committed subject".into());
        }
        format!("docket:attempt:{}", d.attempt)
    };
    if subject != r.subject {
        return Err("request subject mismatch".into());
    }
    let raw_digest = sha256_bytes(raw);
    let custody = if let Some(a) = acquisition {
        if a.attempt != r.attempt
            || a.raw_digest != raw_digest
            || a.state_locator.is_empty()
            || a.observed_at > r.evaluated_at
        {
            return Err("acquisition binding mismatch".into());
        }
        "native_observation"
    } else {
        "external_projection"
    };
    let mut premises = Vec::new();
    for p in &d.identity.settlement_premises {
        if p.trim().is_empty() {
            return Err("unenforceable settlement premise".into());
        }
        premises.push(format!(
            "Docket settlement premise: {p}; asserted, not verified"
        ));
    }
    if premises.is_empty() {
        return Err("required settlement premises absent".into());
    }
    let mut residuals = Vec::new();
    for ob in &d.observation.residual_obligations {
        residuals.push(format!(
            "Docket {}: {} (not discharged)",
            ob.obligation, ob.kind
        ));
    }
    if let Some(reconciliation) = &d.observation.reconciliation {
        for ob in &reconciliation.retained_obligations {
            residuals.push(format!("Docket retained obligation {ob}"));
        }
    }
    let auth = d
        .authorization
        .as_ref()
        .ok_or("v3 authorization block absent")?;
    match (auth.source.as_str(), &auth.issuance) {
        ("upstream", Some(i)) => {
            for p in &i.upstream_premises {
                if p.kind.trim().is_empty() || p.statement.trim().is_empty() {
                    return Err("unenforceable upstream premise".into());
                }
                premises.push(format!(
                    "Upstream authorization premise {}: {}; asserted, not verified",
                    p.kind, p.statement
                ));
            }
            if i.upstream_residual_status != "none_recorded" || !i.upstream_residuals.is_empty() {
                residuals.push(format!(
                    "upstream residual status {}",
                    i.upstream_residual_status
                ));
            }
            for residual in &i.upstream_residuals {
                if residual.discharged {
                    return Err("source cannot discharge upstream obligations".into());
                }
                residuals.push(format!(
                    "upstream {}: {}",
                    residual.obligation_id, residual.statement
                ));
            }
        }
        ("local" | "unrecorded", None) => {}
        _ => return Err("inconsistent authorization provenance".into()),
    }
    let mut contradictions = Vec::new();
    if d.state == "committed"
        && (d.settlement != "normal"
            || d.execution.dispatch_refusal.is_some()
            || d.execution.indeterminate.is_some()
            || d.execution.resolution.is_some())
    {
        contradictions
            .push("normal committed claim conflicts with retained execution history".into());
    }
    if d.settlement != d.execution.settlement {
        contradictions.push("Docket settlement fields disagree".to_owned());
    }
    if let Some(q) = &d.qualification {
        if q.custody_premise.as_deref().is_none_or(|p| p.is_empty())
            || q.custody_premise_asserted_not_verified != Some(true)
        {
            return Err("recovery qualification missing asserted custody premise".into());
        }
        premises.push(format!(
            "Recovery premise {}; asserted, not verified",
            q.custody_premise.as_deref().unwrap()
        ));
        if !q.evidence_agrees {
            contradictions.push("Docket retained evidence disagrees".to_owned());
        }
    }
    let allowed_purpose = [
        "continue_observing",
        "wait",
        "request_evidence",
        "stop",
        "human_escalation",
    ]
    .contains(&r.purpose.as_str());
    let mut decision = if !["nightshift-readonly", "nightshift-readonly-continuity"]
        .contains(&r.consumer.as_str())
    {
        "consumer_unknown"
    } else if !allowed_purpose {
        "purpose_not_authorized"
    } else if r.claim != "docket_attempt_settled" {
        "claim_not_authorized_for_consumer"
    } else if custody == "external_projection" && r.consumer == "nightshift-readonly" {
        "custody_basis_not_accepted"
    } else if !contradictions.is_empty() {
        "contradiction_retained"
    } else if !residuals.is_empty() {
        "residual_obligations_unresolved"
    } else if d.state != "committed" {
        "claim_not_verified"
    } else {
        "supported_readonly"
    };
    if let Some(a) = acquisition {
        if r.evaluated_at
            .signed_duration_since(a.observed_at)
            .num_seconds()
            >= 900
        {
            decision = "stale_evidence";
        }
    }
    let subject_digest = semantic_digest(&subject).map_err(|e| e.to_string())?;
    let mut supporting = Vec::new();
    if r.consumer == "nightshift-readonly-continuity" {
        if let Some(s) = &r.continuity_support {
            crate::continuity_support::replay(s)?;
            if s.binding.subject_digest != subject_digest
                || s.binding.principal != r.consumer
                || s.binding.purpose != "continue_observing"
                || s.receipt_id == raw_digest
            {
                return Err("continuity support subject/principal/purpose mismatch".into());
            }
            let at = DateTime::parse_from_rfc3339(&s.evaluation_time)
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc);
            if decision == "supported_readonly"
                && (s.disposition != "eligible"
                    || at > r.evaluated_at
                    || r.evaluated_at.signed_duration_since(at).num_seconds() >= 900)
            {
                decision = "supporting_evidence_not_current_or_verified";
            }
            supporting.push(json!({"claim":s.claim,"content_hash":s.receipt_id,"status":s.disposition,"subject":subject}));
        } else if decision == "supported_readonly" {
            decision = "supporting_evidence_missing";
        }
    }
    let mut receipt = json!({"schema":SCHEMA,"request":r,"request_digest":semantic_digest(r).map_err(|e|e.to_string())?,
        "subject":subject,"subject_digest":subject_digest,"claim":r.claim,"decision":decision,
        "source_record_utf8":std::str::from_utf8(raw).map_err(|e|e.to_string())?,"source_digest":raw_digest,
        "acquisition":acquisition,"custody_basis":custody,"generated_at":r.evaluated_at,
        "expires_at":r.evaluated_at.checked_add_signed(chrono::Duration::seconds(900)).ok_or("time overflow")?,
        "premises":premises,"unresolved_residuals":residuals,"retained_contradictions":contradictions,
        "supporting_receipts":supporting,"does_not_establish":[
            "Docket reports normal committed state; NQ does not independently establish settlement",
            "native observation names direct bounded acquisition, not truth of Docket assertions",
            "premises remain asserted; no upstream obligations discharged",
            "currentness requires independent exact PresentEvidencePort evidence",
            "no action authority, retry, effect success, or authorization granted"]});
    receipt["receipt_id"] = json!(semantic_digest(&receipt).map_err(|e| e.to_string())?);
    Ok(receipt)
}

pub fn replay(receipt: &Value) -> Result<(), String> {
    let request: Request =
        serde_json::from_value(receipt["request"].clone()).map_err(|e| e.to_string())?;
    let acquisition: Option<Acquisition> =
        serde_json::from_value(receipt["acquisition"].clone()).map_err(|e| e.to_string())?;
    if qualify(
        receipt["source_record_utf8"]
            .as_str()
            .ok_or("source bytes missing")?
            .as_bytes(),
        &request,
        acquisition.as_ref(),
    )? != *receipt
    {
        return Err("Docket purpose replay mismatch".into());
    }
    Ok(())
}
