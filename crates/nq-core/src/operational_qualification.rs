//! NQ-owned qualification of exact Monitor operational testimony.
//!
//! This additive contract consumes, but does not replace, diagnostic execution
//! v2. It retains acquisition failure, refusal, cannot-testify, claim support,
//! contradiction, and later temporal applicability as distinct facts.
#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const OPERATIONAL_QUALIFICATION_SCHEMA_V1: &str = "nq.operational-observation-qualification/v1";
pub const MONITOR_OPERATIONAL_SCHEMA_V1: &str = "monitor.operational-acquisition/v1";
pub const MONITOR_SIGNATURE_DOMAIN_V1: &str = "monitor.operational-observation.v1";
pub const MONITOR_CONTENT_DIGEST_DOMAIN_V1: &str = "operational.content.v1";
pub const FIELD_CLOCK_MONITOR_RESULT_HEAD: &str = "b2d52fe34f146774cbf5601819982c267c7fb082";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalClaimRuleV1 {
    pub claim_id: String,
    pub coverage_dimension: String,
    pub payload_json_pointer: String,
    pub proposition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedProducerIdentityV1 {
    pub principal_id: String,
    pub producer_identity_digest: String,
    pub public_key_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalQualificationProfileV1 {
    pub profile_id: String,
    pub monitor_contract_head: String,
    pub accepted_subject_identity_digests: Vec<String>,
    pub accepted_producer_identities: Vec<AcceptedProducerIdentityV1>,
    pub accepted_payload_schemas: Vec<String>,
    pub claims: Vec<OperationalClaimRuleV1>,
}

impl OperationalQualificationProfileV1 {
    /// Validate the closed profile and exact Monitor contract pin.
    ///
    /// # Errors
    /// Returns an error for an unknown contract head, malformed identity,
    /// noncanonical set, or invalid claim rule.
    pub fn validate(&self) -> Result<(), OperationalQualificationError> {
        token("profile_id", &self.profile_id)?;
        if self.monitor_contract_head != FIELD_CLOCK_MONITOR_RESULT_HEAD {
            return Err(error(
                "monitor_contract_mismatch",
                "profile does not pin the qualified FIELD-CLOCK Monitor result head",
            ));
        }
        sorted(
            "subject identities",
            &self.accepted_subject_identity_digests,
            true,
        )?;
        if self.accepted_producer_identities.is_empty()
            || self.accepted_producer_identities.len() > 64
        {
            return Err(error(
                "invalid_producer_identities",
                "producer identity set is empty or oversized",
            ));
        }
        let mut producer_keys = BTreeSet::new();
        for producer in &self.accepted_producer_identities {
            token("producer principal", &producer.principal_id)?;
            monitor_sha256_digest(
                "producer identity digest",
                &producer.producer_identity_digest,
            )?;
            monitor_sha256_digest("producer public-key digest", &producer.public_key_digest)?;
            if !producer_keys.insert((
                producer.principal_id.as_str(),
                producer.producer_identity_digest.as_str(),
                producer.public_key_digest.as_str(),
            )) {
                return Err(error(
                    "invalid_producer_identities",
                    "producer identity is duplicated",
                ));
            }
        }
        if self.accepted_producer_identities.windows(2).any(|pair| {
            (
                &pair[0].principal_id,
                &pair[0].producer_identity_digest,
                &pair[0].public_key_digest,
            ) >= (
                &pair[1].principal_id,
                &pair[1].producer_identity_digest,
                &pair[1].public_key_digest,
            )
        }) {
            return Err(error(
                "invalid_producer_identities",
                "producer identities must be sorted and unique",
            ));
        }
        sorted("payload schemas", &self.accepted_payload_schemas, true)?;
        if self.claims.is_empty() || self.claims.len() > 64 {
            return Err(error(
                "invalid_claim_profile",
                "claim rules are empty or oversized",
            ));
        }
        let mut ids = BTreeSet::new();
        for claim in &self.claims {
            token("claim_id", &claim.claim_id)?;
            token("coverage_dimension", &claim.coverage_dimension)?;
            text("payload_json_pointer", &claim.payload_json_pointer)?;
            text("proposition", &claim.proposition)?;
            if !claim.payload_json_pointer.starts_with('/') || !ids.insert(&claim.claim_id) {
                return Err(error(
                    "invalid_claim_profile",
                    "claim IDs must be unique and pointers absolute",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OperationalEvidenceInputV1 {
    pub input_id: String,
    pub signed_monitor_record: Vec<u8>,
    pub payload_bytes: Option<Vec<u8>>,
    pub receiver_custody_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalRefusalV1 {
    pub code: String,
    pub exact_basis_digest: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalClaimSupportV1 {
    pub claim_id: String,
    pub proposition: String,
    pub value_digest: Sha256Digest,
    pub monitor_record_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CannotTestifyV1 {
    pub claim_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedOperationalInputV1 {
    pub input_id: String,
    pub raw_record_digest: Sha256Digest,
    pub monitor_record_digest: Option<String>,
    pub subject_identity_digest: Option<String>,
    pub producer_identity_digest: Option<String>,
    pub producer_principal_id: Option<String>,
    pub producer_class: Option<String>,
    pub acquisition_outcome: Option<String>,
    pub producer_observed_at: Option<DateTime<Utc>>,
    pub receiver_custody_at: DateTime<Utc>,
    pub payload_schema: Option<String>,
    pub claim_support: Vec<OperationalClaimSupportV1>,
    pub cannot_testify: Vec<CannotTestifyV1>,
    pub refusals: Vec<OperationalRefusalV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalContradictionV1 {
    pub subject_identity_digest: String,
    pub claim_id: String,
    pub first_input_id: String,
    pub first_value_digest: Sha256Digest,
    pub second_input_id: String,
    pub second_value_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalQualificationArtifactV1 {
    pub schema: String,
    pub profile_id: String,
    pub monitor_contract_head: String,
    pub evaluated_at: DateTime<Utc>,
    pub inputs: Vec<QualifiedOperationalInputV1>,
    pub contradictions: Vec<OperationalContradictionV1>,
    pub nonclaims: Vec<String>,
}

impl OperationalQualificationArtifactV1 {
    /// Compute the deterministic JCS identity of this NQ artifact.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub fn artifact_digest(&self) -> Result<Sha256Digest, OperationalQualificationError> {
        semantic_digest(self).map_err(|e| error("canonicalization_failed", e.to_string()))
    }

    /// Freeze the exact NQ-supported claim set for a temporal consumer.
    ///
    /// # Errors
    /// Returns an error if the qualification cannot be identified.
    pub fn temporal_claim_boundary(
        &self,
    ) -> Result<TemporalClaimBoundaryV1, OperationalQualificationError> {
        let claim_ids = self
            .inputs
            .iter()
            .flat_map(|input| {
                input
                    .claim_support
                    .iter()
                    .map(|claim| claim.claim_id.clone())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(TemporalClaimBoundaryV1 {
            qualification_digest: self.artifact_digest()?,
            exact_supported_claim_ids: claim_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalClaimBoundaryV1 {
    pub qualification_digest: Sha256Digest,
    pub exact_supported_claim_ids: Vec<String>,
}

impl TemporalClaimBoundaryV1 {
    /// Refuse a temporal projection that adds a claim NQ did not support.
    ///
    /// # Errors
    /// Returns an error for noncanonical input or claim widening.
    pub fn validate_nightshift_projection(
        &self,
        projected_claim_ids: &[String],
    ) -> Result<(), OperationalQualificationError> {
        sorted("projected claim IDs", projected_claim_ids, false)?;
        if projected_claim_ids
            .iter()
            .any(|claim| !self.exact_supported_claim_ids.contains(claim))
        {
            return Err(error(
                "nightshift_claim_widening",
                "temporal projection contains a claim NQ did not support",
            ));
        }
        Ok(())
    }
}

/// Qualify exact Monitor records under one closed NQ profile.
///
/// # Errors
/// Returns an error when the profile or input set is malformed. Record-level
/// refusals remain in the returned artifact.
pub fn qualify_operational_observations(
    profile: &OperationalQualificationProfileV1,
    inputs: &[OperationalEvidenceInputV1],
    evaluated_at: DateTime<Utc>,
) -> Result<OperationalQualificationArtifactV1, OperationalQualificationError> {
    profile.validate()?;
    if inputs.is_empty() || inputs.len() > 64 {
        return Err(error(
            "invalid_input_count",
            "operational input set is empty or oversized",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut qualified = Vec::with_capacity(inputs.len());
    for input in inputs {
        token("input_id", &input.input_id)?;
        if !seen.insert(input.input_id.clone()) {
            return Err(error("duplicate_input", "input identity is duplicated"));
        }
        qualified.push(qualify_one(profile, input, evaluated_at));
    }
    let contradictions = contradictions(&qualified);
    Ok(OperationalQualificationArtifactV1 {
        schema: OPERATIONAL_QUALIFICATION_SCHEMA_V1.to_owned(),
        profile_id: profile.profile_id.clone(),
        monitor_contract_head: profile.monitor_contract_head.clone(),
        evaluated_at,
        inputs: qualified,
        contradictions,
        nonclaims: vec![
            "NQ qualification grants no authorization or remediation".to_owned(),
            "NQ qualification does not establish Nightshift temporal currentness".to_owned(),
            "producer class alone grants no evidentiary precedence".to_owned(),
        ],
    })
}

#[allow(clippy::too_many_lines)]
fn qualify_one(
    profile: &OperationalQualificationProfileV1,
    input: &OperationalEvidenceInputV1,
    evaluated_at: DateTime<Utc>,
) -> QualifiedOperationalInputV1 {
    let raw_digest = sha256_bytes(&input.signed_monitor_record);
    let mut result = QualifiedOperationalInputV1 {
        input_id: input.input_id.clone(),
        raw_record_digest: raw_digest.clone(),
        monitor_record_digest: None,
        subject_identity_digest: None,
        producer_identity_digest: None,
        producer_principal_id: None,
        producer_class: None,
        acquisition_outcome: None,
        producer_observed_at: None,
        receiver_custody_at: input.receiver_custody_at,
        payload_schema: None,
        claim_support: vec![],
        cannot_testify: vec![],
        refusals: vec![],
    };
    let refusal = |code: &str, detail: String| OperationalRefusalV1 {
        code: code.to_owned(),
        exact_basis_digest: raw_digest.to_string(),
        detail,
    };
    let reopened = match reopen_monitor(input) {
        Ok(value) => value,
        Err(failure) => {
            result.refusals.push(refusal(failure.code, failure.detail));
            return result;
        }
    };
    result.monitor_record_digest = Some(reopened.record_digest.clone());
    result.subject_identity_digest = Some(reopened.subject_digest.clone());
    result.producer_identity_digest = Some(reopened.producer_digest.clone());
    result.producer_principal_id = Some(reopened.principal_id.clone());
    result.producer_class = Some(reopened.producer_class.clone());
    result.acquisition_outcome = Some(reopened.outcome.clone());
    result.producer_observed_at = reopened.producer_observed_at;
    result.payload_schema.clone_from(&reopened.payload_schema);

    if input.receiver_custody_at < reopened.acquisition_ended_at {
        result.refusals.push(refusal(
            "receiver_custody_inversion",
            "receiver custody precedes completion of the signed acquisition".to_owned(),
        ));
        return result;
    }
    if evaluated_at < input.receiver_custody_at {
        result.refusals.push(refusal(
            "evaluation_time_inversion",
            "NQ evaluation precedes receiver custody".to_owned(),
        ));
        return result;
    }
    if !profile
        .accepted_subject_identity_digests
        .contains(&reopened.subject_digest)
    {
        result.refusals.push(refusal(
            "subject_identity_mismatch",
            "subject is outside the exact qualification profile".to_owned(),
        ));
        return result;
    }
    if !profile.accepted_producer_identities.iter().any(|accepted| {
        accepted.principal_id == reopened.principal_id
            && accepted.producer_identity_digest == reopened.producer_digest
            && accepted.public_key_digest == reopened.public_key_digest
    }) {
        result.refusals.push(refusal(
            "producer_identity_mismatch",
            "producer is outside the exact qualification profile".to_owned(),
        ));
        return result;
    }
    if reopened.outcome != "observation_produced" {
        result.cannot_testify = profile
            .claims
            .iter()
            .map(|claim| CannotTestifyV1 {
                claim_id: claim.claim_id.clone(),
                reason: format!(
                    "Monitor acquisition outcome {} produced no world testimony",
                    reopened.outcome
                ),
            })
            .collect();
        return result;
    }
    let Some(schema) = &reopened.payload_schema else {
        return result;
    };
    if !profile.accepted_payload_schemas.contains(schema) {
        result.cannot_testify = profile
            .claims
            .iter()
            .map(|claim| CannotTestifyV1 {
                claim_id: claim.claim_id.clone(),
                reason: "payload schema is unknown and remains raw-only".to_owned(),
            })
            .collect();
        return result;
    }
    let Some(payload) = reopened.payload else {
        result.refusals.push(refusal(
            "payload_custody_missing",
            "produced observation lacks reopened payload bytes".to_owned(),
        ));
        return result;
    };
    for claim in &profile.claims {
        if !reopened
            .observed_dimensions
            .contains(&claim.coverage_dimension)
        {
            result.cannot_testify.push(CannotTestifyV1 {
                claim_id: claim.claim_id.clone(),
                reason: format!(
                    "required coverage dimension {} was not observed",
                    claim.coverage_dimension
                ),
            });
            continue;
        }
        match payload.pointer(&claim.payload_json_pointer) {
            Some(value) => result.claim_support.push(OperationalClaimSupportV1 {
                claim_id: claim.claim_id.clone(),
                proposition: claim.proposition.clone(),
                value_digest: semantic_digest(value).expect("JSON value canonicalizes"),
                monitor_record_digest: reopened.record_digest.clone(),
            }),
            None => result.cannot_testify.push(CannotTestifyV1 {
                claim_id: claim.claim_id.clone(),
                reason: "profile claim pointer is absent from exact payload".to_owned(),
            }),
        }
    }
    result
}

struct ReopenedMonitor {
    record_digest: String,
    subject_digest: String,
    producer_digest: String,
    public_key_digest: String,
    principal_id: String,
    producer_class: String,
    outcome: String,
    producer_observed_at: Option<DateTime<Utc>>,
    acquisition_ended_at: DateTime<Utc>,
    payload_schema: Option<String>,
    observed_dimensions: Vec<String>,
    payload: Option<Value>,
}

#[allow(clippy::too_many_lines)]
fn reopen_monitor(
    input: &OperationalEvidenceInputV1,
) -> Result<ReopenedMonitor, OperationalQualificationError> {
    if input.signed_monitor_record.len() > 1024 * 1024 {
        return Err(error(
            "record_oversized",
            "signed Monitor record exceeds one MiB",
        ));
    }
    let root: Value = serde_json::from_slice(&input.signed_monitor_record)
        .map_err(|e| error("record_malformed", e.to_string()))?;
    exact_keys(
        &root,
        &[
            "body",
            "signature_domain",
            "signer_key_identity_digest",
            "signature_hex",
        ],
    )?;
    let body_bytes = extract_object_field(&input.signed_monitor_record, "body")?;
    let body: Value =
        serde_json::from_slice(body_bytes).map_err(|e| error("body_malformed", e.to_string()))?;
    exact_keys(
        &body,
        &[
            "schema",
            "producer",
            "subject",
            "locators",
            "acquisition",
            "lineage",
            "producer_observed_at",
            "payload_schema",
            "payload",
            "attachments",
            "coverage",
            "grants_authority",
        ],
    )?;
    if string(&body, "schema")? != MONITOR_OPERATIONAL_SCHEMA_V1 {
        return Err(error(
            "schema_unknown",
            "Monitor operational schema is unsupported",
        ));
    }
    if body.get("grants_authority").and_then(Value::as_bool) != Some(false) {
        return Err(error(
            "authority_present",
            "Monitor testimony cannot grant authority",
        ));
    }
    let semantics = validate_monitor_body(&body)?;
    let producer_bytes = extract_object_field(body_bytes, "producer")?;
    let producer = object(&body, "producer")?;
    exact_keys(
        producer,
        &[
            "principal_id",
            "collector_id",
            "key_algorithm",
            "public_key_hex",
            "public_key_digest",
            "producer_class",
        ],
    )?;
    if string(producer, "key_algorithm")? != "ed25519" {
        return Err(error(
            "key_algorithm_unknown",
            "producer key algorithm is unsupported",
        ));
    }
    token("producer principal", string(producer, "principal_id")?)?;
    token("collector identity", string(producer, "collector_id")?)?;
    token("producer class", string(producer, "producer_class")?)?;
    let public_hex = string(producer, "public_key_hex")?;
    if public_hex.len() != 64
        || !public_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            "public_key_malformed",
            "producer public key is not exact lowercase hex",
        ));
    }
    let public =
        hex::decode(public_hex).map_err(|e| error("public_key_malformed", e.to_string()))?;
    let public_key_digest = monitor_digest("operational.ed25519.public-key.v1", &[&public]);
    if string(producer, "public_key_digest")? != public_key_digest {
        return Err(error(
            "producer_key_mismatch",
            "producer public key identity is invalid",
        ));
    }
    let producer_digest = monitor_digest("operational.producer-principal.v1", &[producer_bytes]);
    if string(&root, "signer_key_identity_digest")? != producer_digest {
        return Err(error(
            "signer_identity_mismatch",
            "signature does not bind exact producer principal",
        ));
    }
    if string(&root, "signature_domain")? != MONITOR_SIGNATURE_DOMAIN_V1 {
        return Err(error(
            "signature_domain_mismatch",
            "signature domain is unsupported",
        ));
    }
    let verifying = VerifyingKey::from_bytes(
        &public
            .try_into()
            .map_err(|_| error("public_key_malformed", "public key length is invalid"))?,
    )
    .map_err(|e| error("public_key_malformed", e.to_string()))?;
    let signature_hex = string(&root, "signature_hex")?;
    if signature_hex.len() != 128
        || !signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            "signature_malformed",
            "signature is not exact lowercase hex",
        ));
    }
    let signature =
        hex::decode(signature_hex).map_err(|e| error("signature_malformed", e.to_string()))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| error("signature_malformed", "signature length is invalid"))?;
    verifying
        .verify_strict(
            &signature_transcript(body_bytes),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| error("signature_invalid", "strict Ed25519 verification failed"))?;

    let subject_bytes = extract_object_field(body_bytes, "subject")?;
    let subject_digest = monitor_digest("operational.subject.v1", &[subject_bytes]);
    let outcome = semantics.outcome;
    let producer_observed_at = semantics.producer_observed_at;
    let payload_schema = body
        .get("payload_schema")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let observed_dimensions = semantics.observed_dimensions;
    let payload = if outcome == "observation_produced" {
        let reference = object(&body, "payload")?;
        exact_keys(
            reference,
            &["media_type", "digest_domain", "digest", "byte_length"],
        )?;
        if string(reference, "digest_domain")? != MONITOR_CONTENT_DIGEST_DOMAIN_V1 {
            return Err(error(
                "payload_digest_law_unknown",
                "payload digest domain is unsupported",
            ));
        }
        let bytes = input
            .payload_bytes
            .as_deref()
            .ok_or_else(|| error("payload_missing", "exact payload bytes were not supplied"))?;
        if reference.get("byte_length").and_then(Value::as_u64) != Some(bytes.len() as u64)
            || string(reference, "digest")?
                != monitor_digest(MONITOR_CONTENT_DIGEST_DOMAIN_V1, &[bytes])
        {
            return Err(error(
                "payload_substitution",
                "payload bytes do not match exact Monitor custody",
            ));
        }
        Some(serde_json::from_slice(bytes).map_err(|e| error("payload_malformed", e.to_string()))?)
    } else {
        if body.get("payload").is_some_and(|v| !v.is_null()) || input.payload_bytes.is_some() {
            return Err(error(
                "failure_as_world_claim",
                "failed acquisition carries payload testimony",
            ));
        }
        None
    };
    Ok(ReopenedMonitor {
        record_digest: monitor_digest("operational.acquisition-record.v1", &[body_bytes]),
        subject_digest,
        producer_digest,
        public_key_digest,
        principal_id: string(producer, "principal_id")?.to_owned(),
        producer_class: string(producer, "producer_class")?.to_owned(),
        outcome,
        producer_observed_at,
        acquisition_ended_at: semantics.acquisition_ended_at,
        payload_schema,
        observed_dimensions,
        payload,
    })
}

#[derive(Debug)]
struct MonitorBodySemantics {
    outcome: String,
    producer_observed_at: Option<DateTime<Utc>>,
    acquisition_ended_at: DateTime<Utc>,
    observed_dimensions: Vec<String>,
}

#[allow(clippy::too_many_lines)]
fn validate_monitor_body(
    body: &Value,
) -> Result<MonitorBodySemantics, OperationalQualificationError> {
    let subject = object(body, "subject")?;
    exact_keys(
        subject,
        &["kind", "namespace", "basis_contract", "stable_basis"],
    )?;
    token("subject namespace", string(subject, "namespace")?)?;
    validate_subject_basis(subject)?;

    let locators = body
        .get("locators")
        .and_then(Value::as_array)
        .ok_or_else(|| error("field_type", "locators is not an array"))?;
    if locators.len() > 32 {
        return Err(error("invalid_collection", "locators is oversized"));
    }
    for locator in locators {
        exact_keys(locator, &["kind", "value", "observed_at"])?;
        if ![
            "local_path",
            "host_label",
            "dns_name",
            "ip_address",
            "url",
            "socket",
            "scheduler_display_name",
            "repository_checkout",
        ]
        .contains(&string(locator, "kind")?)
        {
            return Err(error("locator_kind_unknown", "locator kind is unsupported"));
        }
        text("locator value", string(locator, "value")?)?;
        monitor_time("locator observation time", string(locator, "observed_at")?)?;
    }

    let acquisition = object(body, "acquisition")?;
    exact_keys(
        acquisition,
        &[
            "attempt_id",
            "started_at",
            "ended_at",
            "outcome",
            "diagnostic_code",
            "raw_basis_digest",
        ],
    )?;
    token("acquisition attempt", string(acquisition, "attempt_id")?)?;
    token(
        "acquisition diagnostic",
        string(acquisition, "diagnostic_code")?,
    )?;
    if let Some(raw_basis) = acquisition
        .get("raw_basis_digest")
        .filter(|value| !value.is_null())
    {
        monitor_sha256_digest(
            "raw acquisition basis",
            raw_basis
                .as_str()
                .ok_or_else(|| error("field_type", "raw basis digest is not a string"))?,
        )?;
    }
    let started_at = monitor_time("acquisition start", string(acquisition, "started_at")?)?;
    let ended_at = monitor_time("acquisition end", string(acquisition, "ended_at")?)?;
    if started_at > ended_at {
        return Err(error(
            "timestamp_inversion",
            "acquisition end precedes start",
        ));
    }
    let outcome = string(acquisition, "outcome")?.to_owned();
    if ![
        "observation_produced",
        "no_response",
        "command_failed",
        "producer_unavailable",
        "receiver_unavailable",
        "malformed_input",
        "refused",
    ]
    .contains(&outcome.as_str())
    {
        return Err(error(
            "acquisition_outcome_unknown",
            "Monitor acquisition outcome is outside the closed contract",
        ));
    }

    let lineage = object(body, "lineage")?;
    exact_keys(
        lineage,
        &["epoch", "sequence", "predecessor_observation_digest"],
    )?;
    token("observation epoch", string(lineage, "epoch")?)?;
    let sequence = lineage
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| error("lineage_invalid", "observation sequence is not unsigned"))?;
    let predecessor = lineage
        .get("predecessor_observation_digest")
        .filter(|value| !value.is_null())
        .and_then(Value::as_str);
    if (sequence == 0) != predecessor.is_none() {
        return Err(error(
            "lineage_invalid",
            "sequence and predecessor observation are inconsistent",
        ));
    }
    if let Some(predecessor) = predecessor {
        monitor_sha256_digest("predecessor observation", predecessor)?;
    }

    let coverage = object(body, "coverage")?;
    exact_keys(
        coverage,
        &[
            "expected_dimensions",
            "observed_dimensions",
            "omitted_dimensions",
        ],
    )?;
    let expected = string_array(coverage, "expected_dimensions")?;
    let observed = string_array(coverage, "observed_dimensions")?;
    let omitted = string_array(coverage, "omitted_dimensions")?;
    sorted("expected coverage", &expected, true)?;
    sorted("observed coverage", &observed, false)?;
    sorted("omitted coverage", &omitted, false)?;
    if observed
        .iter()
        .chain(&omitted)
        .any(|dimension| !expected.contains(dimension))
        || observed.iter().any(|dimension| omitted.contains(dimension))
    {
        return Err(error(
            "coverage_invalid",
            "coverage is inconsistent with its exact denominator",
        ));
    }
    let covered = observed.iter().chain(&omitted).collect::<BTreeSet<_>>();
    if expected
        .iter()
        .any(|dimension| !covered.contains(dimension))
    {
        return Err(error(
            "coverage_incomplete",
            "every expected dimension must be observed or explicitly omitted",
        ));
    }
    let attachments = body
        .get("attachments")
        .and_then(Value::as_array)
        .ok_or_else(|| error("field_type", "attachments is not an array"))?;
    if attachments.len() > 32 {
        return Err(error("invalid_collection", "attachments is oversized"));
    }
    for attachment in attachments {
        validate_content_reference(attachment)?;
    }
    let producer_observed_at = body
        .get("producer_observed_at")
        .and_then(Value::as_str)
        .map(|value| monitor_time("producer observation time", value))
        .transpose()?;
    if outcome == "observation_produced" {
        let observed_at = producer_observed_at.ok_or_else(|| {
            error(
                "observation_time_missing",
                "produced observation lacks producer time",
            )
        })?;
        if observed_at < started_at || observed_at > ended_at {
            return Err(error(
                "observation_time_inversion",
                "producer observation time falls outside acquisition",
            ));
        }
        if body.get("payload_schema").and_then(Value::as_str).is_none()
            || !body.get("payload").is_some_and(Value::is_object)
        {
            return Err(error(
                "payload_missing",
                "produced observation lacks payload custody",
            ));
        }
        token("payload schema", string(body, "payload_schema")?)?;
        validate_content_reference(object(body, "payload")?)?;
    } else if producer_observed_at.is_some()
        || body
            .get("payload_schema")
            .is_some_and(|value| !value.is_null())
        || body.get("payload").is_some_and(|value| !value.is_null())
        || !observed.is_empty()
    {
        return Err(error(
            "failure_as_world_claim",
            "failed acquisition carries world testimony or observed coverage",
        ));
    }
    Ok(MonitorBodySemantics {
        outcome,
        producer_observed_at,
        acquisition_ended_at: ended_at,
        observed_dimensions: observed,
    })
}

fn validate_subject_basis(subject: &Value) -> Result<(), OperationalQualificationError> {
    let kind = string(subject, "kind")?;
    let basis = object(subject, "stable_basis")?;
    let (contract, fields): (&str, &[&str]) = match kind {
        "host" => (
            "monitor.subject-basis.host-machine/v1",
            &["basis_type", "machine_identity"],
        ),
        "service_instance" => (
            "monitor.subject-basis.service-instance-registry/v1",
            &["basis_type", "service_identity", "instance_identity"],
        ),
        "deployment_release" => (
            "monitor.subject-basis.deployment-release-content/v1",
            &["basis_type", "deployment_identity", "release_identity"],
        ),
        "repository_revision" => (
            "monitor.subject-basis.repository-revision-content/v1",
            &["basis_type", "repository_identity", "revision_identity"],
        ),
        "scheduler_job" => (
            "monitor.subject-basis.scheduler-job-occurrence/v1",
            &["basis_type", "scheduler_identity", "job_identity"],
        ),
        "ecad_design_revision" => (
            "monitor.subject-basis.ecad-design-revision-content/v1",
            &["basis_type", "design_identity", "revision_identity"],
        ),
        "toolchain" => (
            "monitor.subject-basis.toolchain-content/v1",
            &["basis_type", "toolchain_identity"],
        ),
        "pdk" => (
            "monitor.subject-basis.pdk-content/v1",
            &["basis_type", "pdk_identity"],
        ),
        "license_entitlement" => (
            "monitor.subject-basis.license-entitlement-registry/v1",
            &["basis_type", "entitlement_identity"],
        ),
        "worker" => (
            "monitor.subject-basis.worker-registry/v1",
            &["basis_type", "worker_identity"],
        ),
        "artifact_set" => (
            "monitor.subject-basis.artifact-set-content/v1",
            &["basis_type", "artifact_set_identity"],
        ),
        "stage_occurrence" => (
            "monitor.subject-basis.stage-occurrence/v1",
            &["basis_type", "run_identity", "stage_occurrence_identity"],
        ),
        _ => {
            return Err(error(
                "subject_kind_unknown",
                "Monitor subject kind is outside the closed contract",
            ));
        }
    };
    if string(subject, "basis_contract")? != contract {
        return Err(error(
            "unsupported_subject_basis_contract",
            "subject stable-basis contract is not the family-owned v1 contract",
        ));
    }
    exact_keys(basis, fields)?;
    if string(basis, "basis_type")? != kind {
        return Err(error(
            "subject_basis_kind_mismatch",
            "subject kind and stable-basis contract differ",
        ));
    }
    for field in fields
        .iter()
        .copied()
        .filter(|field| *field != "basis_type")
    {
        monitor_sha256_digest("stable subject basis", string(basis, field)?)?;
    }
    Ok(())
}

fn validate_content_reference(value: &Value) -> Result<(), OperationalQualificationError> {
    exact_keys(
        value,
        &["media_type", "digest_domain", "digest", "byte_length"],
    )?;
    token("content media type", string(value, "media_type")?)?;
    if string(value, "digest_domain")? != MONITOR_CONTENT_DIGEST_DOMAIN_V1 {
        return Err(error(
            "payload_digest_law_unknown",
            "content digest domain is unsupported",
        ));
    }
    monitor_sha256_digest("content digest", string(value, "digest")?)?;
    if value.get("byte_length").and_then(Value::as_u64) == Some(0)
        || value.get("byte_length").and_then(Value::as_u64).is_none()
    {
        return Err(error(
            "content_length_invalid",
            "content byte length is absent or zero",
        ));
    }
    Ok(())
}

fn monitor_time(field: &str, value: &str) -> Result<DateTime<Utc>, OperationalQualificationError> {
    text(field, value)?;
    if !value.ends_with('Z') {
        return Err(error(
            "timestamp_noncanonical",
            format!("{field} is not canonical UTC RFC3339"),
        ));
    }
    value
        .parse()
        .map_err(|parse_error| error("timestamp_invalid", format!("{field}: {parse_error}")))
}

fn monitor_sha256_digest(field: &str, value: &str) -> Result<(), OperationalQualificationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(error(
            "digest_invalid",
            format!("{field} lacks sha256 prefix"),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex.bytes().all(|byte| byte == b'0')
    {
        return Err(error(
            "digest_invalid",
            format!("{field} is not a canonical nonzero sha256 digest"),
        ));
    }
    Ok(())
}

fn contradictions(inputs: &[QualifiedOperationalInputV1]) -> Vec<OperationalContradictionV1> {
    let mut seen: BTreeMap<(&str, &str), (&str, &Sha256Digest)> = BTreeMap::new();
    let mut output = vec![];
    for input in inputs {
        let Some(subject) = input.subject_identity_digest.as_deref() else {
            continue;
        };
        for claim in &input.claim_support {
            let key = (subject, claim.claim_id.as_str());
            if let Some((prior_input, prior_value)) = seen.get(&key) {
                if *prior_value != &claim.value_digest {
                    output.push(OperationalContradictionV1 {
                        subject_identity_digest: subject.to_owned(),
                        claim_id: claim.claim_id.clone(),
                        first_input_id: (*prior_input).to_owned(),
                        first_value_digest: (*prior_value).clone(),
                        second_input_id: input.input_id.clone(),
                        second_value_digest: claim.value_digest.clone(),
                    });
                }
            } else {
                seen.insert(key, (&input.input_id, &claim.value_digest));
            }
        }
    }
    output
}

fn monitor_digest(domain: &str, parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"monitor-skunkworks.digest.v1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
fn signature_transcript(body: &[u8]) -> Vec<u8> {
    let domain = MONITOR_SIGNATURE_DOMAIN_V1.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(
        &u16::try_from(domain.len())
            .expect("fixed signature domain fits u16")
            .to_be_bytes(),
    );
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn extract_object_field<'a>(
    bytes: &'a [u8],
    key: &str,
) -> Result<&'a [u8], OperationalQualificationError> {
    let needle = format!("\"{key}\":");
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())
        .ok_or_else(|| error("field_missing", format!("missing exact field {key}")))?
        + needle.len();
    if bytes.get(start) != Some(&b'{') {
        return Err(error("field_type", format!("field {key} is not an object")));
    }
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'\"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'\"' => quoted = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&bytes[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    Err(error(
        "field_malformed",
        format!("field {key} object is unterminated"),
    ))
}
fn exact_keys(value: &Value, expected: &[&str]) -> Result<(), OperationalQualificationError> {
    let map = value
        .as_object()
        .ok_or_else(|| error("object_expected", "JSON value is not an object"))?;
    let actual = map.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(error(
            "closed_schema_violation",
            "JSON object keys differ from closed contract",
        ))
    }
}
fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Value, OperationalQualificationError> {
    value
        .get(key)
        .filter(|v| v.is_object())
        .ok_or_else(|| error("field_type", format!("{key} is not an object")))
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, OperationalQualificationError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("field_type", format!("{key} is not a string")))
}
fn string_array(value: &Value, key: &str) -> Result<Vec<String>, OperationalQualificationError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| error("field_type", format!("{key} is not an array")))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| error("field_type", format!("{key} contains a non-string")))
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalQualificationError {
    pub code: &'static str,
    pub detail: String,
}
impl std::fmt::Display for OperationalQualificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}
impl std::error::Error for OperationalQualificationError {}
fn error(code: &'static str, detail: impl Into<String>) -> OperationalQualificationError {
    OperationalQualificationError {
        code,
        detail: detail.into(),
    }
}
fn text(field: &str, value: &str) -> Result<(), OperationalQualificationError> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(error("invalid_text", format!("{field} is invalid")))
    } else {
        Ok(())
    }
}
fn token(field: &str, value: &str) -> Result<(), OperationalQualificationError> {
    text(field, value)?;
    if value.chars().any(char::is_whitespace) {
        Err(error(
            "invalid_token",
            format!("{field} contains whitespace"),
        ))
    } else {
        Ok(())
    }
}
fn sorted(
    field: &str,
    values: &[String],
    required: bool,
) -> Result<(), OperationalQualificationError> {
    if (required && values.is_empty()) || values.len() > 64 {
        return Err(error(
            "invalid_collection",
            format!("{field} is empty or oversized"),
        ));
    }
    for value in values {
        token(field, value)?;
    }
    if values.windows(2).any(|p| p[0] >= p[1]) {
        Err(error(
            "noncanonical_collection",
            format!("{field} must be sorted and unique"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    #[allow(clippy::similar_names)]
    fn signed_record(
        key_byte: u8,
        principal: &str,
        outcome: &str,
        subject_id: &str,
        payload: Option<&[u8]>,
        producer_class: &str,
    ) -> Vec<u8> {
        let signing = SigningKey::from_bytes(&[key_byte; 32]);
        let public = signing.verifying_key().to_bytes();
        let producer = json!({"principal_id":principal,"collector_id":"collector:fixture","key_algorithm":"ed25519","public_key_hex":hex::encode(public),"public_key_digest":monitor_digest("operational.ed25519.public-key.v1", &[&public]),"producer_class":producer_class});
        let subject = json!({
            "kind":"service_instance",
            "namespace":"inventory:fixture",
            "basis_contract":"monitor.subject-basis.service-instance-registry/v1",
            "stable_basis":{
                "basis_type":"service_instance",
                "service_identity":monitor_digest("fixture.subject.service", &[b"service"]),
                "instance_identity":monitor_digest("fixture.subject.instance", &[subject_id.as_bytes()])
            }
        });
        let payload_ref=payload.map(|bytes|json!({"media_type":"application/json","digest_domain":MONITOR_CONTENT_DIGEST_DOMAIN_V1,"digest":monitor_digest(MONITOR_CONTENT_DIGEST_DOMAIN_V1,&[bytes]),"byte_length":bytes.len()}));
        let produced = outcome == "observation_produced";
        let body = json!({"schema":MONITOR_OPERATIONAL_SCHEMA_V1,"producer":producer,"subject":subject,"locators":[],"acquisition":{"attempt_id":"attempt:1","started_at":"2026-08-30T01:00:00Z","ended_at":"2026-08-30T01:00:01Z","outcome":outcome,"diagnostic_code":outcome,"raw_basis_digest":monitor_digest("fixture",&[b"raw"])},"lineage":{"epoch":"epoch:1","sequence":0,"predecessor_observation_digest":null},"producer_observed_at":if produced{Some("2026-08-30T01:00:00Z")}else{None},"payload_schema":if produced{Some("fixture.service-fact/v1")}else{None},"payload":payload_ref,"attachments":[],"coverage":{"expected_dimensions":["availability"],"observed_dimensions":if produced{vec!["availability"]}else{vec![]},"omitted_dimensions":if produced{vec![]}else{vec!["availability"]}},"grants_authority":false});
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let signature = signing.sign(&signature_transcript(&body_bytes));
        let producer_bytes = extract_object_field(&body_bytes, "producer").unwrap();
        serde_json::to_vec(&json!({"body":body,"signature_domain":MONITOR_SIGNATURE_DOMAIN_V1,"signer_key_identity_digest":monitor_digest("operational.producer-principal.v1",&[producer_bytes]),"signature_hex":hex::encode(signature.to_bytes())})).unwrap()
    }
    fn profile(record: &[u8]) -> OperationalQualificationProfileV1 {
        let body_bytes = extract_object_field(record, "body").unwrap();
        let subject = extract_object_field(body_bytes, "subject").unwrap();
        OperationalQualificationProfileV1 {
            profile_id: "profile:fixture".into(),
            monitor_contract_head: FIELD_CLOCK_MONITOR_RESULT_HEAD.into(),
            accepted_subject_identity_digests: vec![monitor_digest(
                "operational.subject.v1",
                &[subject],
            )],
            accepted_producer_identities: vec![accepted_producer(record)],
            accepted_payload_schemas: vec!["fixture.service-fact/v1".into()],
            claims: vec![OperationalClaimRuleV1 {
                claim_id: "claim:availability".into(),
                coverage_dimension: "availability".into(),
                payload_json_pointer: "/facts/available".into(),
                proposition: "service availability testimony".into(),
            }],
        }
    }
    fn accepted_producer(record: &[u8]) -> AcceptedProducerIdentityV1 {
        let body_bytes = extract_object_field(record, "body").unwrap();
        let producer = extract_object_field(body_bytes, "producer").unwrap();
        let producer_value: Value = serde_json::from_slice(producer).unwrap();
        AcceptedProducerIdentityV1 {
            principal_id: string(&producer_value, "principal_id").unwrap().to_owned(),
            producer_identity_digest: monitor_digest(
                "operational.producer-principal.v1",
                &[producer],
            ),
            public_key_digest: string(&producer_value, "public_key_digest")
                .unwrap()
                .to_owned(),
        }
    }
    fn input(id: &str, record: Vec<u8>, payload: Option<&[u8]>) -> OperationalEvidenceInputV1 {
        OperationalEvidenceInputV1 {
            input_id: id.into(),
            signed_monitor_record: record,
            payload_bytes: payload.map(ToOwned::to_owned),
            receiver_custody_at: "2026-08-30T01:00:02Z".parse().unwrap(),
        }
    }
    #[test]
    fn supports_exact_claim_and_refuses_payload_subject_and_exact_key_substitution() {
        let payload = br#"{"facts":{"available":true}}"#;
        let record = signed_record(
            7,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(payload),
            "instrumented_monitor",
        );
        let profile = profile(&record);
        let artifact = qualify_operational_observations(
            &profile,
            &[input("one", record.clone(), Some(payload))],
            "2026-08-30T01:00:03Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(artifact.inputs[0].claim_support.len(), 1);
        let mut wrong = payload.to_vec();
        wrong.push(b' ');
        let refused = qualify_operational_observations(
            &profile,
            &[input("one", record.clone(), Some(&wrong))],
            artifact.evaluated_at,
        )
        .unwrap();
        assert_eq!(refused.inputs[0].refusals[0].code, "payload_substitution");
        let substituted = signed_record(
            7,
            "producer:fixture",
            "observation_produced",
            "service-instance:other",
            Some(payload),
            "instrumented_monitor",
        );
        let refused = qualify_operational_observations(
            &profile,
            &[input("one", substituted, Some(payload))],
            artifact.evaluated_at,
        )
        .unwrap();
        assert_eq!(
            refused.inputs[0].refusals[0].code,
            "subject_identity_mismatch"
        );
        let substituted = signed_record(
            8,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(payload),
            "instrumented_monitor",
        );
        let refused = qualify_operational_observations(
            &profile,
            &[input("one", substituted, Some(payload))],
            artifact.evaluated_at,
        )
        .unwrap();
        assert_eq!(
            refused.inputs[0].refusals[0].code,
            "producer_identity_mismatch"
        );
        let substituted = signed_record(
            8,
            "producer:other",
            "observation_produced",
            "service-instance:98ab",
            Some(payload),
            "instrumented_monitor",
        );
        let refused = qualify_operational_observations(
            &profile,
            &[input("one", substituted, Some(payload))],
            artifact.evaluated_at,
        )
        .unwrap();
        assert_eq!(
            refused.inputs[0].refusals[0].code,
            "producer_identity_mismatch"
        );
    }
    #[test]
    fn acquisition_failure_cannot_testify_and_unknown_schema_stays_raw() {
        let failure = signed_record(
            7,
            "producer:fixture",
            "no_response",
            "service-instance:98ab",
            None,
            "instrumented_monitor",
        );
        let failure_profile = profile(&failure);
        let artifact = qualify_operational_observations(
            &failure_profile,
            &[input("failed", failure, None)],
            "2026-08-30T01:00:03Z".parse().unwrap(),
        )
        .unwrap();
        assert!(artifact.inputs[0].claim_support.is_empty());
        assert_eq!(artifact.inputs[0].cannot_testify.len(), 1);

        let payload = br#"{"facts":{"available":true}}"#;
        let observed = signed_record(
            7,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(payload),
            "instrumented_monitor",
        );
        let mut unknown_profile = profile(&observed);
        unknown_profile.accepted_payload_schemas = vec!["fixture.unknown/v1".to_owned()];
        let raw_only = qualify_operational_observations(
            &unknown_profile,
            &[input("unknown", observed, Some(payload))],
            "2026-08-30T01:00:03Z".parse().unwrap(),
        )
        .unwrap();
        assert!(raw_only.inputs[0].claim_support.is_empty());
        assert_eq!(
            raw_only.inputs[0].cannot_testify[0].reason,
            "payload schema is unknown and remains raw-only"
        );
    }
    #[test]
    fn contradiction_is_preserved_and_temporal_layer_cannot_widen() {
        let yes = br#"{"facts":{"available":true}}"#;
        let no = br#"{"facts":{"available":false}}"#;
        let first = signed_record(
            7,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(yes),
            "instrumented_monitor",
        );
        let mut profile = profile(&first);
        let second = signed_record(
            8,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(no),
            "agent_authored",
        );
        profile
            .accepted_producer_identities
            .push(accepted_producer(&second));
        profile.accepted_producer_identities.sort_by(|left, right| {
            (
                &left.principal_id,
                &left.producer_identity_digest,
                &left.public_key_digest,
            )
                .cmp(&(
                    &right.principal_id,
                    &right.producer_identity_digest,
                    &right.public_key_digest,
                ))
        });
        let artifact = qualify_operational_observations(
            &profile,
            &[input("a", first, Some(yes)), input("b", second, Some(no))],
            "2026-08-30T01:00:03Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(artifact.contradictions.len(), 1);
        let boundary = artifact.temporal_claim_boundary().unwrap();
        boundary
            .validate_nightshift_projection(&["claim:availability".into()])
            .unwrap();
        assert_eq!(
            boundary
                .validate_nightshift_projection(&["claim:invented".into()])
                .unwrap_err()
                .code,
            "nightshift_claim_widening"
        );
    }

    #[test]
    fn monitor_identity_coverage_and_time_laws_are_reopened() {
        let payload = br#"{"facts":{"available":true}}"#;
        let record = signed_record(
            7,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(payload),
            "instrumented_monitor",
        );
        let root: Value = serde_json::from_slice(&record).unwrap();
        let mut body = root.get("body").unwrap().clone();
        body["subject"] = json!({
            "kind":"host",
            "namespace":"inventory:fixture",
            "basis_contract":"monitor.subject-basis.host-machine/v1",
            "stable_basis":{"basis_type":"host","machine_identity":"service.example"}
        });
        assert_eq!(
            validate_monitor_body(&body).unwrap_err().code,
            "digest_invalid"
        );

        let mut body = root.get("body").unwrap().clone();
        body["subject"]["basis_contract"] = json!("monitor.subject-basis.hostname-hash/v1");
        assert_eq!(
            validate_monitor_body(&body).unwrap_err().code,
            "unsupported_subject_basis_contract"
        );

        let mut body = root.get("body").unwrap().clone();
        body["coverage"]["expected_dimensions"] = json!(["availability", "revision"]);
        assert_eq!(
            validate_monitor_body(&body).unwrap_err().code,
            "coverage_incomplete"
        );

        let mut body = root.get("body").unwrap().clone();
        body["acquisition"]["started_at"] = json!("not-a-timeTstillZ");
        assert_eq!(
            validate_monitor_body(&body).unwrap_err().code,
            "timestamp_invalid"
        );

        let mut body = root.get("body").unwrap().clone();
        body["producer_observed_at"] = json!("2026-08-30T01:00:02Z");
        assert_eq!(
            validate_monitor_body(&body).unwrap_err().code,
            "observation_time_inversion"
        );
    }

    #[test]
    fn receiver_custody_and_evaluation_are_ordered() {
        let payload = br#"{"facts":{"available":true}}"#;
        let record = signed_record(
            7,
            "producer:fixture",
            "observation_produced",
            "service-instance:98ab",
            Some(payload),
            "instrumented_monitor",
        );
        let profile = profile(&record);
        let mut before_acquisition = input("early", record.clone(), Some(payload));
        before_acquisition.receiver_custody_at = "2026-08-30T00:59:59Z".parse().unwrap();
        let artifact = qualify_operational_observations(
            &profile,
            &[before_acquisition],
            "2026-08-30T01:00:03Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            artifact.inputs[0].refusals[0].code,
            "receiver_custody_inversion"
        );

        let artifact = qualify_operational_observations(
            &profile,
            &[input("future", record, Some(payload))],
            "2026-08-30T01:00:01Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            artifact.inputs[0].refusals[0].code,
            "evaluation_time_inversion"
        );
    }
}
