//! Compiled factual projection of Continuity memory rely exports.
//! Not Standing substrate succession, action authority, or source authentication.
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA: &str = "nq.continuity-memory-support/v1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContinuityBinding {
    pub store_id: String,
    pub memory_id: String,
    pub scope: String,
    pub subject_digest: Sha256Digest,
    pub principal: String,
    pub purpose: String,
    pub raw_source_digest: Sha256Digest,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContinuitySupport {
    pub schema: String,
    pub receipt_id: Sha256Digest,
    pub binding: ContinuityBinding,
    pub claim: String,
    pub disposition: String,
    pub evaluation_time: String,
    pub source_code: String,
    pub source_record_utf8: String,
    pub limitations: Vec<String>,
}

fn fields(v: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = v.as_object().ok_or("expected object")?;
    if object.keys().any(|k| !allowed.contains(&k.as_str()))
        || allowed.iter().any(|k| !object.contains_key(*k))
    {
        return Err("missing or unknown field in complete source export".into());
    }
    Ok(())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("missing source string {k}"))
}

/// Exact source-byte qualification under an externally owned source binding.
/// The binding is configuration, not authentication inferred from a self-hash.
pub fn qualify(raw: &[u8], binding: &ContinuityBinding) -> Result<ContinuitySupport, String> {
    if raw.len() > 2 * 1024 * 1024 || sha256_bytes(raw) != binding.raw_source_digest {
        return Err("source custody digest/size mismatch".into());
    }
    for s in [
        &binding.store_id,
        &binding.memory_id,
        &binding.scope,
        &binding.principal,
        &binding.purpose,
    ] {
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            return Err("binding token invalid".into());
        }
    }
    if binding.principal != "nightshift-readonly-continuity"
        || binding.purpose != "continue_observing"
    {
        return Err("unsupported continuity consumer/purpose".into());
    }
    let v: Value =
        nq_protocol::decode_json_document(raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    fields(
        &v,
        &[
            "schema",
            "export_id",
            "exported_at",
            "source",
            "subject",
            "content_hash",
            "status",
            "supersedes",
            "revoked_by",
            "authoring_tier",
            "reliance_class",
            "effective_reliance",
            "lifecycle",
            "times",
            "evaluation_time",
            "rely",
            "premises",
            "history",
            "establishes",
            "does_not_establish",
        ],
    )?;
    if v["schema"] != "continuity.rely_export.v0" {
        return Err("not a Continuity source export (recursive NQ substitution refused)".into());
    }
    fields(
        &v["source"],
        &[
            "system",
            "store_id",
            "scope_kind",
            "schema_version",
            "exporter",
        ],
    )?;
    fields(
        &v["source"]["exporter"],
        &["tool", "version", "repo", "commit"],
    )?;
    fields(&v["subject"], &["memory_id", "scope", "kind", "basis"])?;
    fields(&v["rely"], &["rely_ok", "code", "message", "details"])?;
    fields(
        &v["lifecycle"],
        &[
            "observe_event_id",
            "observe_receipt_hash",
            "latest_commit_event_id",
            "latest_commit_receipt_hash",
        ],
    )?;
    fields(
        &v["times"],
        &[
            "created_at",
            "updated_at",
            "source_observed_at",
            "expires_at",
        ],
    )?;
    fields(&v["history"], &["event_count", "receipt_count"])?;
    // This compiled profile accepts the complete emitted v0 wire form, not
    // partially populated source model inputs. Nullable source facts remain null.
    for (object, keys) in [
        (&v, &["supersedes", "revoked_by"][..]),
        (&v["source"], &["scope_kind"][..]),
        (&v["source"]["exporter"], &["repo", "commit"][..]),
        (
            &v["lifecycle"],
            &[
                "observe_event_id",
                "observe_receipt_hash",
                "latest_commit_event_id",
                "latest_commit_receipt_hash",
            ][..],
        ),
    ] {
        for key in keys {
            if !object[key].is_null() {
                text(object, key)?;
            }
        }
    }
    if !v["source"]["schema_version"].is_null() && v["source"]["schema_version"].as_u64().is_none()
    {
        return Err("invalid source schema version".into());
    }
    for key in ["tool", "version"] {
        text(&v["source"]["exporter"], key)?;
    }
    for key in ["memory_id", "scope", "kind", "basis"] {
        text(&v["subject"], key)?;
    }
    text(&v["rely"], "message")?;
    for key in ["event_count", "receipt_count"] {
        v["history"][key].as_u64().ok_or("invalid history count")?;
    }
    for key in ["exported_at", "evaluation_time"] {
        chrono::DateTime::parse_from_rfc3339(text(&v, key)?).map_err(|e| e.to_string())?;
    }
    for key in [
        "created_at",
        "updated_at",
        "source_observed_at",
        "expires_at",
    ] {
        if ["created_at", "updated_at"].contains(&key) || !v["times"][key].is_null() {
            chrono::DateTime::parse_from_rfc3339(text(&v["times"], key)?)
                .map_err(|e| e.to_string())?;
        }
    }
    for key in ["establishes", "does_not_establish"] {
        let lines = v[key]
            .as_array()
            .ok_or("source claims must be string arrays")?;
        if lines.is_empty()
            || lines
                .iter()
                .any(|line| line.as_str().is_none_or(|s| s.trim().is_empty()))
        {
            return Err("source claim/limitation missing".into());
        }
    }
    if !["observed", "committed", "revoked"].contains(&text(&v, "status")?) {
        return Err("unknown source lifecycle status".into());
    }
    let classes = ["none", "retrieve_only", "advisory", "actionable"];
    let declared = classes
        .iter()
        .position(|s| Some(*s) == v["reliance_class"].as_str())
        .ok_or("unknown reliance class")?;
    let effective = classes
        .iter()
        .position(|s| Some(*s) == v["effective_reliance"].as_str())
        .ok_or("unknown effective reliance")?;
    // Source-owned tier ceiling, pinned to Continuity aed09d3 api/models.py.
    let cap = match text(&v, "authoring_tier")? {
        "revoked" => 0,
        "provenance_unknown" => 1,
        "agent_authored" | "runtime_authored" => 2,
        "custodian_signed" => 3,
        _ => return Err("unknown authoring tier".into()),
    };
    if effective != declared.min(cap) {
        return Err("source effective reliance contradicts declared tier ceiling".into());
    }
    if !v["rely"]["details"].is_object() {
        return Err("source detail must be object".into());
    }
    if v["source"]["system"] != "continuity"
        || v["source"]["store_id"] != binding.store_id
        || v["subject"]["memory_id"] != binding.memory_id
        || v["subject"]["scope"] != binding.scope
    {
        return Err("source store/memory/scope mismatch".into());
    }
    for field in ["export_id", "content_hash"] {
        Sha256Digest::parse(text(&v, field)?).map_err(|e| e.to_string())?;
    }
    let at = text(&v, "evaluation_time")?;
    chrono::DateTime::parse_from_rfc3339(at).map_err(|e| e.to_string())?;
    let ok = v["rely"]["rely_ok"]
        .as_bool()
        .ok_or("source rely_ok missing")?;
    let code = text(&v["rely"], "code")?;
    if ![
        "eligible",
        "status_not_committed",
        "expired",
        "reliance_none",
        "authoring_tier_capped",
        "kind_basis_policy",
        "hard_premise_unavailable",
    ]
    .contains(&code)
    {
        return Err("unknown source rely code".into());
    }
    if ok != (code == "eligible") {
        return Err("contradictory source rely verdict/code".into());
    }
    if ok
        && (v["status"] != "committed"
            || !v["revoked_by"].is_null()
            || v["effective_reliance"] == "none")
    {
        return Err("eligible source contradicts lifecycle/ceiling".into());
    }
    let mut limitations = vec![
        "external Continuity projection; source consistency is not authenticated custody".into(),
        "reports source rely gate at evaluation time, not world truth or currentness".into(),
        "no action authority, premise discharge, or tier promotion".into(),
    ];
    for p in v["premises"].as_array().ok_or("premises array required")? {
        fields(p, &["src", "relation", "strength", "status"])?;
        for k in ["src", "relation", "strength", "status"] {
            text(p, k)?;
        }
        limitations.push(format!("source premise: {p}"));
    }
    for line in v["does_not_establish"]
        .as_array()
        .ok_or("source nonclaims required")?
    {
        limitations.push(
            line.as_str()
                .filter(|s| !s.is_empty())
                .ok_or("source nonclaim invalid")?
                .into(),
        );
    }
    for k in ["authoring_tier", "reliance_class", "effective_reliance"] {
        limitations.push(format!("source {k}: {}", text(&v, k)?));
    }
    let missing = code == "hard_premise_unavailable"
        && serde_json::to_string(&v["rely"]["details"])
            .map_err(|e| e.to_string())?
            .contains(":missing");
    let disposition = if ok {
        "eligible"
    } else if missing || (code == "status_not_committed" && v["status"] != "revoked") {
        "indeterminate"
    } else {
        "not_eligible"
    };
    let mut receipt = ContinuitySupport {
        schema: SCHEMA.into(),
        receipt_id: sha256_bytes(b"pending"),
        binding: binding.clone(),
        claim: "continuity_rely_eligible".into(),
        disposition: disposition.into(),
        evaluation_time: at.into(),
        source_code: code.into(),
        source_record_utf8: String::from_utf8(raw.to_vec()).map_err(|e| e.to_string())?,
        limitations,
    };
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;
    value.as_object_mut().unwrap().remove("receipt_id");
    receipt.receipt_id = semantic_digest(&value).map_err(|e| e.to_string())?;
    Ok(receipt)
}

pub fn replay(receipt: &ContinuitySupport) -> Result<(), String> {
    if qualify(receipt.source_record_utf8.as_bytes(), &receipt.binding)? != *receipt {
        return Err("continuity receipt replay mismatch".into());
    }
    Ok(())
}
