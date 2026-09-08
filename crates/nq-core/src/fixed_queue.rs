//! Closed factual predicates with exact, immutable consumer bindings.
//! Catalogs carry identities, never executable expressions: only the finite
//! compiled forms below are admitted. This is factual testimony, not authority.
use chrono::DateTime;
use nq_protocol::{Sha256Digest, semantic_digest};
use serde::Deserialize;
use serde_json::{Value, json};

// The existing Monitor inventory wire remains a closed typed input. These DTOs
// validate all rows, including unselected ones; they do not interpret facts.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryShape {
    schema: String,
    project: String,
    repository: String,
    acquisition: AcquisitionShape,
    validation_issues: Vec<String>,
    concerns: Vec<ConcernShape>,
}
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionShape {
    disposition: String,
    acquired_at_unix_ms: u128,
    producer: String,
    binding_schema: String,
    manifest_digest: String,
    status_digest: Option<String>,
    exit_code: Option<i32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    repository_revision_context: Option<String>,
    repository_revision_is_deployment_provenance: bool,
}
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcernShape {
    declaration: DeclarationShape,
    monitor_state: String,
    observation: Option<ObservationShape>,
}
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclarationShape {
    id: String,
    question: String,
    profile: String,
    required: bool,
    description: String,
}
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationShape {
    observation_present: bool,
    local_state: String,
    domain_state: Option<String>,
    observed_at: Option<String>,
    valid_for_seconds: Option<u64>,
    reason: String,
    facts: Value,
}

pub fn digest(value: &Value) -> Result<String, String> {
    semantic_digest(value)
        .map(|v| v.to_string())
        .map_err(|e| e.to_string())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing string {field}"))
}

fn evaluate(profile: &Value, facts: &Value) -> Result<bool, String> {
    fn compare(fact: &str, kind: &str, value: Value, comparator: &str) -> Value {
        json!({"operator":"compare","fact":fact,"comparator":comparator,"value":{"type":kind,"value":value}})
    }
    let access_schema = json!([{"path":"exists","type":"bool"},{"path":"readable","type":"bool"},{"path":"write_transaction_available","type":"bool"}]);
    let access = json!({"operator":"all","clauses":[compare("exists","bool",json!(true),"eq"),compare("readable","bool",json!(true),"eq"),compare("write_transaction_available","bool",json!(true),"eq")]});
    if profile["input_schema"] == access_schema && profile["predicate"] == access {
        let a = facts["exists"].as_bool().ok_or("indeterminate: exists")?;
        let b = facts["readable"]
            .as_bool()
            .ok_or("indeterminate: readable")?;
        let c = facts["write_transaction_available"]
            .as_bool()
            .ok_or("indeterminate: transaction")?;
        return Ok(a && b && c);
    }
    let continuity_schema = json!([{"path":"quick_check","type":"string"},{"path":"write_transaction_acquired","type":"bool"}]);
    let continuity = json!({"operator":"all","clauses":[compare("quick_check","string",json!("ok"),"eq"),compare("write_transaction_acquired","bool",json!(true),"eq")]});
    if profile["input_schema"] == continuity_schema && profile["predicate"] == continuity {
        let a = facts["quick_check"]
            .as_str()
            .ok_or("indeterminate: quick_check")?;
        let b = facts["write_transaction_acquired"]
            .as_bool()
            .ok_or("indeterminate: transaction")?;
        return Ok(a == "ok" && b);
    }
    for (field, floor) in [
        ("free_bytes", 15032385536_u64),
        ("freelist_count", 5000000_u64),
    ] {
        if profile["input_schema"] == json!([{"path":field,"type":"u64"}])
            && profile["predicate"] == compare(field, "u64", json!(floor), "ge")
        {
            return facts[field]
                .as_u64()
                .map(|v| v >= floor)
                .ok_or_else(|| format!("indeterminate: {field}"));
        }
    }
    if profile["input_schema"] != json!([{"path":"queue.depth","type":"u64"}]) {
        return Err("unsupported compiled input schema".into());
    }
    let depth = facts
        .pointer("/queue/depth")
        .and_then(Value::as_u64)
        .ok_or("indeterminate: queue.depth is not an observed u64")?;
    let low = json!({"operator":"compare","fact":"queue.depth","comparator":"le","value":{"type":"u64","value":17}});
    let high = json!({"operator":"compare","fact":"queue.depth","comparator":"ge","value":{"type":"u64","value":18}});
    if profile["predicate"] == low {
        Ok(depth <= 17)
    } else if profile["predicate"] == high {
        Ok(depth >= 18)
    } else {
        Err("unsupported compiled predicate; no runtime interpreter".into())
    }
}

fn profile<'a>(catalog: &'a Value, project: &str, concern: &str) -> Result<&'a Value, String> {
    if catalog["schema"] != "nq.project-predicate-profile-catalog/v1" {
        return Err("catalog schema".into());
    }
    let matches: Vec<_> = catalog["profiles"]
        .as_array()
        .ok_or("profiles array")?
        .iter()
        .filter(|p| p["subject"]["project"] == project && p["subject"]["concern"] == concern)
        .collect();
    if matches.len() != 1 {
        return Err("profile binding missing or ambiguous".into());
    }
    let p = matches[0];
    if p["schema"] != "nq.project-predicate-profile/v1" {
        return Err("profile schema".into());
    }
    Ok(p)
}

pub fn admit(
    inventory: &Value,
    catalog: &Value,
    catalog_digest: &str,
    concern: &str,
    at: &str,
) -> Result<Value, String> {
    let _: InventoryShape = serde_json::from_value(inventory.clone())
        .map_err(|error| format!("malformed Monitor inventory: {error}"))?;
    if digest(catalog)? != catalog_digest {
        return Err("catalog digest mismatch".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut bindings = std::collections::BTreeSet::new();
    for p in catalog["profiles"].as_array().ok_or("profiles array")? {
        if !ids.insert(text(p, "id")?) || !bindings.insert(digest(&p["subject"])?) {
            return Err("duplicate profile identity or subject binding".into());
        }
    }
    if inventory["schema"] != "monitor.project-observation.inventory/v1"
        || inventory["acquisition"]["disposition"] != "ACQUIRED_AND_VALIDATED"
        || inventory["acquisition"]["exit_code"] != 0
        || inventory["validation_issues"] != json!([])
    {
        return Err("inventory not acquired and validated".into());
    }
    let project = text(inventory, "project")?;
    text(inventory, "repository")?;
    // A malformed unselected row must not be laundered by a favorable selection.
    let mut concern_ids = std::collections::BTreeSet::new();
    for item in inventory["concerns"].as_array().ok_or("concerns array")? {
        let id = text(&item["declaration"], "id")?;
        let state = text(item, "monitor_state")?;
        let observed = item.get("observation").is_some_and(|v| !v.is_null());
        if !concern_ids.insert(id)
            || !matches!(
                state,
                "OBSERVED" | "MISSING_REQUIRED_OBSERVATION" | "MISSING_OPTIONAL_OBSERVATION"
            )
            || (state == "OBSERVED") != observed
        {
            return Err("duplicate concern or inconsistent inventory observation state".into());
        }
    }
    let p = profile(catalog, project, concern)?;
    let acquisition = &inventory["acquisition"];
    if acquisition["binding_schema"] != "project.observation-binding/v1"
        || acquisition["repository_revision_is_deployment_provenance"] != false
        || acquisition["stdout_bytes"].as_u64().unwrap_or(0) == 0
    {
        return Err("acquisition custody or provenance mismatch".into());
    }
    for field in ["manifest_digest", "status_digest"] {
        Sha256Digest::parse(text(acquisition, field)?).map_err(|e| e.to_string())?;
    }
    let producer = text(acquisition, "producer")?;
    if !p["accepted_producers"]
        .as_array()
        .ok_or("producer bindings")?
        .contains(&json!(producer))
        || !p["accepted_manifest_digests"]
            .as_array()
            .ok_or("manifest bindings")?
            .contains(&acquisition["manifest_digest"])
    {
        return Err("producer or manifest mismatch".into());
    }
    let rows: Vec<_> = inventory["concerns"]
        .as_array()
        .ok_or("concerns array")?
        .iter()
        .filter(|c| c["declaration"]["id"] == concern)
        .collect();
    if rows.len() != 1 {
        return Err("concern missing or ambiguous".into());
    }
    let row = rows[0];
    if row["monitor_state"] != "OBSERVED"
        || row["observation"]["observation_present"] != true
        || row["declaration"]["question"] != p["question"]
        || row["declaration"]["profile"] != p["declaration_profile"]
    {
        return Err("observation absent or declaration mismatch".into());
    }
    let observation = &row["observation"];
    let observed_at = text(observation, "observed_at")?;
    let observed = DateTime::parse_from_rfc3339(observed_at).map_err(|e| e.to_string())?;
    let evaluated = DateTime::parse_from_rfc3339(at).map_err(|e| e.to_string())?;
    // Legacy specimen bindings omitted this optional bound. The compiled
    // maximum is 300 seconds; an explicit smaller policy only narrows it.
    let maximum = match p.get("max_observation_age_seconds") {
        None => 300,
        Some(v) => v.as_u64().ok_or("profile age bound")?.min(300),
    };
    let validity = match observation.get("valid_for_seconds") {
        None | Some(Value::Null) => maximum,
        Some(value) => value.as_u64().ok_or("observation validity")?.min(maximum),
    };
    let age = evaluated.signed_duration_since(observed);
    let seconds = i64::try_from(validity).map_err(|_| "age overflow")?;
    if age < chrono::Duration::zero()
        || age >= chrono::Duration::try_seconds(seconds).ok_or("age overflow")?
    {
        return Err("observation future or stale at exclusive boundary".into());
    }
    let conclusion = evaluate(p, &observation["facts"])?;
    let mut receipt = json!({"schema":"nq.bounded-predicate-admission/v1", "compiled_semantics":"nq.bounded-predicate-compiled/v1", "inventory_digest":digest(inventory)?, "catalog_digest":catalog_digest,"evaluated_at":at,"concern":concern,"semantic_conclusion":conclusion,
        "witness":{"project":project,"concern":concern,"question":text(p,"question")?,"declaration_profile":text(p,"declaration_profile")?,"predicate_profile":text(p,"id")?,"profile_digest":digest(p)?,"input_schema_digest":digest(&p["input_schema"])?,"producer":producer,"observed_at":observed_at,"valid_for_seconds":validity}});
    receipt["receipt_digest"] = json!(digest(&receipt)?);
    Ok(receipt)
}

pub fn replay(receipt: &Value, inventory: &Value, catalog: &Value) -> Result<bool, String> {
    Ok(admit(
        inventory,
        catalog,
        text(receipt, "catalog_digest")?,
        text(receipt, "concern")?,
        text(receipt, "evaluated_at")?,
    )? == *receipt)
}

pub fn support(
    receipt: &Value,
    inventory: &Value,
    catalog: &Value,
    facts: &Value,
) -> Result<Value, String> {
    if !replay(receipt, inventory, catalog)? {
        return Err("admission replay mismatch".into());
    }
    if receipt["semantic_conclusion"] != true {
        return Err("primary predicate not established".into());
    }
    let witness = &receipt["witness"];
    let p = profile(
        catalog,
        text(witness, "project")?,
        text(witness, "concern")?,
    )?;
    Ok(
        json!({"schema":"nq.bounded-predicate-support-evaluation/v1","admission_replay_matches":true,"admission_receipt_digest":receipt["receipt_digest"],"catalog_digest":receipt["catalog_digest"],"predicate_profile":witness["predicate_profile"],"profile_digest":witness["profile_digest"],"input_schema_digest":witness["input_schema_digest"],"semantic_conclusion":evaluate(p,facts)?,"trace":{"compiled_semantics":"nq.bounded-predicate-compiled/v1","facts_digest":digest(facts)?}}),
    )
}
