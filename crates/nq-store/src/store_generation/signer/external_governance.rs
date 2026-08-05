//! Strict terminal-A1 external-governance carrier ingestion.
//!
//! Decoding accepts only exact canonical JSON conforming to the checked-in
//! closed schema.  Ed25519 verifies possession of the key named by the
//! carrier; the separate [`TerminalA1AuthenticityVerifierV1`] hook verifies
//! that the named key is the uniquely resolved terminal A1 generation.  This
//! module deliberately has no A1 signing or external-judgment constructor.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{canonical_json_bytes, sha256_bytes};
use serde_json::{Map, Value};

use super::messages::SignerIdentityV1;
use super::result::{QuarantineClosureEffectResultV2, RevocationEffectResultV2, SignerRefusalV2};

const INTERPRETATION_POLICY: &str = "nq.c2.a1_runtime_dependency_admission_refinement.v1";

const PROPOSAL_REQUEST_SCHEMA: &str = include_str!(
    "../../../../../schemas/c2/nq.c2_store_integrity_proposal_disposition_request.v1.json"
);
const PROPOSAL_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_proposal_disposition.v1.json");
const BOOTSTRAP_REQUEST_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_bootstrap_grant_request.v1.json");
const BOOTSTRAP_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_bootstrap_grant.v1.json");
const ACTIVATION_REQUEST_SCHEMA: &str = include_str!(
    "../../../../../schemas/c2/nq.c2_store_integrity_activation_successor_grant_request.v1.json"
);
const ACTIVATION_SCHEMA: &str = include_str!(
    "../../../../../schemas/c2/nq.c2_store_integrity_activation_successor_grant.v1.json"
);
const REVOCATION_REQUEST_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_revocation_request.v1.json");
const REVOCATION_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_revocation_judgment.v1.json");
const REVOCATION_RECEIPT_SCHEMA: &str = include_str!(
    "../../../../../schemas/c2/nq.c2_store_integrity_revocation_effect_receipt.v1.json"
);
const RECOVERY_REQUEST_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_recovery_request.v1.json");
const RECOVERY_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_store_integrity_recovery_grant.v1.json");
const RESTORE_REQUEST_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_restore_authorization_request.v1.json");
const RESTORE_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_restore_authorization.v1.json");
const QUARANTINE_REQUEST_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_quarantine_closure_request.v1.json");
const QUARANTINE_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_quarantine_closure_judgment.v1.json");
const QUARANTINE_RECEIPT_SCHEMA: &str =
    include_str!("../../../../../schemas/c2/nq.c2_quarantine_closure_effect_receipt.v1.json");

#[derive(Debug, Clone, Copy)]
struct DocumentSpec {
    schema_json: &'static str,
    schema: &'static str,
    identity_domain: &'static str,
    identity_field: &'static str,
    signature_domain: Option<&'static str>,
    request_schema: Option<&'static str>,
    request_identity_field: Option<&'static str>,
}

const PROPOSAL_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: PROPOSAL_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_proposal_disposition_request.v1",
    identity_domain: "nq.c2.store_integrity_proposal_disposition_request.identity.v1",
    identity_field: "proposal_disposition_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const PROPOSAL: DocumentSpec = DocumentSpec {
    schema_json: PROPOSAL_SCHEMA,
    schema: "nq.c2_store_integrity_proposal_disposition.v1",
    identity_domain: "nq.c2.store_integrity_proposal_disposition.identity.v1",
    identity_field: "proposal_disposition_identity",
    signature_domain: Some("nq.c2.store_integrity_proposal_disposition.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_proposal_disposition_request.v1"),
    request_identity_field: Some("proposal_disposition_request_identity"),
};
const BOOTSTRAP_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: BOOTSTRAP_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_bootstrap_grant_request.v1",
    identity_domain: "nq.c2.store_integrity_bootstrap_grant_request.identity.v1",
    identity_field: "grant_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const BOOTSTRAP: DocumentSpec = DocumentSpec {
    schema_json: BOOTSTRAP_SCHEMA,
    schema: "nq.c2_store_integrity_bootstrap_grant.v1",
    identity_domain: "nq.c2.store_integrity_bootstrap_grant.identity.v1",
    identity_field: "grant_identity",
    signature_domain: Some("nq.c2.store_integrity_bootstrap_grant.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_bootstrap_grant_request.v1"),
    request_identity_field: Some("grant_request_identity"),
};
const ACTIVATION_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: ACTIVATION_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_activation_successor_grant_request.v1",
    identity_domain: "nq.c2.store_integrity_activation_successor_grant_request.identity.v1",
    identity_field: "activation_successor_grant_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const ACTIVATION: DocumentSpec = DocumentSpec {
    schema_json: ACTIVATION_SCHEMA,
    schema: "nq.c2_store_integrity_activation_successor_grant.v1",
    identity_domain: "nq.c2.store_integrity_activation_successor_grant.identity.v1",
    identity_field: "activation_successor_grant_identity",
    signature_domain: Some("nq.c2.store_integrity_activation_successor_grant.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_activation_successor_grant_request.v1"),
    request_identity_field: Some("activation_successor_grant_request_identity"),
};
const REVOCATION_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: REVOCATION_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_revocation_request.v1",
    identity_domain: "nq.c2.store_integrity_revocation_request.identity.v1",
    identity_field: "revocation_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const REVOCATION: DocumentSpec = DocumentSpec {
    schema_json: REVOCATION_SCHEMA,
    schema: "nq.c2_store_integrity_revocation_judgment.v1",
    identity_domain: "nq.c2.store_integrity_revocation_judgment.identity.v1",
    identity_field: "revocation_judgment_identity",
    signature_domain: Some("nq.c2.store_integrity_revocation_judgment.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_revocation_request.v1"),
    request_identity_field: Some("revocation_request_identity"),
};
const RECOVERY_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: RECOVERY_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_recovery_request.v1",
    identity_domain: "nq.c2.store_integrity_recovery_request.identity.v1",
    identity_field: "recovery_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const RECOVERY: DocumentSpec = DocumentSpec {
    schema_json: RECOVERY_SCHEMA,
    schema: "nq.c2_store_integrity_recovery_grant.v1",
    identity_domain: "nq.c2.store_integrity_recovery_grant.identity.v1",
    identity_field: "recovery_grant_identity",
    signature_domain: Some("nq.c2.store_integrity_recovery_grant.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_recovery_request.v1"),
    request_identity_field: Some("recovery_request_identity"),
};
const RESTORE_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: RESTORE_REQUEST_SCHEMA,
    schema: "nq.c2_restore_authorization_request.v1",
    identity_domain: "nq.c2.restore_authorization_request.identity.v1",
    identity_field: "restore_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const RESTORE: DocumentSpec = DocumentSpec {
    schema_json: RESTORE_SCHEMA,
    schema: "nq.c2_restore_authorization.v1",
    identity_domain: "nq.c2.restore_authorization.identity.v1",
    identity_field: "restore_authorization_identity",
    signature_domain: Some("nq.c2.restore_authorization.a1_signature.v1"),
    request_schema: Some("nq.c2_restore_authorization_request.v1"),
    request_identity_field: Some("restore_request_identity"),
};
const QUARANTINE_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: QUARANTINE_REQUEST_SCHEMA,
    schema: "nq.c2_quarantine_closure_request.v1",
    identity_domain: "nq.c2.quarantine_closure_request.identity.v1",
    identity_field: "closure_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
};
const QUARANTINE: DocumentSpec = DocumentSpec {
    schema_json: QUARANTINE_SCHEMA,
    schema: "nq.c2_quarantine_closure_judgment.v1",
    identity_domain: "nq.c2.quarantine_closure_judgment.identity.v1",
    identity_field: "quarantine_closure_judgment_identity",
    signature_domain: Some("nq.c2.quarantine_closure_judgment.a1_signature.v1"),
    request_schema: Some("nq.c2_quarantine_closure_request.v1"),
    request_identity_field: Some("closure_request_identity"),
};

/// Stable replay identity of one exact canonical external carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExternalCarrierIdentityV1(SignerIdentityV1);

impl ExternalCarrierIdentityV1 {
    pub(crate) const fn bytes(&self) -> &SignerIdentityV1 {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalExternalDocumentV1 {
    value: Value,
    canonical_bytes: Vec<u8>,
    identity: ExternalCarrierIdentityV1,
}

impl CanonicalExternalDocumentV1 {
    fn field(&self, name: &str) -> Option<&Value> {
        self.value.get(name)
    }
    fn identity(&self) -> ExternalCarrierIdentityV1 {
        self.identity
    }
    fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

fn identity_bytes(text: &str) -> Result<SignerIdentityV1, SignerRefusalV2> {
    let Some(hex_text) = text.strip_prefix("sha256:") else {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    };
    if hex_text.len() != 64
        || !hex_text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    hex::decode(hex_text)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
        .try_into()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn domain_digest(domain: &str, value: &Value) -> Result<String, SignerRefusalV2> {
    let canonical =
        canonical_json_bytes(value).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let mut preimage = Vec::with_capacity(domain.len() + 1 + canonical.len());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_bytes(&preimage).into_string())
}

fn schema_object(spec: DocumentSpec) -> Result<Map<String, Value>, SignerRefusalV2> {
    let schema: Value = serde_json::from_str(spec.schema_json)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    schema
        .as_object()
        .cloned()
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn validate_pattern(value: &str, pattern: &str) -> bool {
    match pattern {
        "^sha256:[0-9a-f]{64}$" => identity_bytes(value).is_ok(),
        "^[0-9a-f]{64}$" => {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        "^[0-9a-f]{128}$" => {
            value.len() == 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        "^[A-Za-z0-9._:/@-]+$" => {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
        }
        _ => false,
    }
}

fn validate_property(value: &Value, property: &Map<String, Value>) -> bool {
    if let Some(expected) = property.get("const") {
        if value != expected {
            return false;
        }
    }
    if let Some(values) = property.get("enum").and_then(Value::as_array) {
        if !values.contains(value) {
            return false;
        }
    }
    if let Some(kind) = property.get("type").and_then(Value::as_str) {
        let matches = match kind {
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "array" => value.is_array(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "object" => value.is_object(),
            _ => false,
        };
        if !matches {
            return false;
        }
    }
    if let Some(text) = value.as_str() {
        if property
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|n| text.chars().count() < n as usize)
            || property
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|n| text.chars().count() > n as usize)
            || property
                .get("pattern")
                .and_then(Value::as_str)
                .is_some_and(|p| !validate_pattern(text, p))
        {
            return false;
        }
    }
    if let Some(number) = value.as_i64() {
        if property
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|n| number < n)
            || property
                .get("maximum")
                .and_then(Value::as_i64)
                .is_some_and(|n| number > n)
        {
            return false;
        }
    }
    if let Some(array) = value.as_array() {
        if property
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|n| array.len() < n as usize)
            || property
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|n| array.len() > n as usize)
            || property.get("uniqueItems").and_then(Value::as_bool) == Some(true) && {
                let set = array.iter().map(Value::to_string).collect::<BTreeSet<_>>();
                set.len() != array.len()
            }
        {
            return false;
        }
        if let Some(items) = property.get("items").and_then(Value::as_object) {
            if array.iter().any(|item| !validate_property(item, items)) {
                return false;
            }
        }
    }
    true
}

fn validate_against_checked_schema(
    value: &Value,
    spec: DocumentSpec,
) -> Result<(), SignerRefusalV2> {
    let schema = schema_object(spec)?;
    let object = value
        .as_object()
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if object.len() != required.len()
        || required
            .iter()
            .any(|name| name.as_str().is_none_or(|name| !object.contains_key(name)))
        || object.keys().any(|name| !properties.contains_key(name))
        || object.iter().any(|(name, field)| {
            properties
                .get(name)
                .and_then(Value::as_object)
                .is_none_or(|rules| !validate_property(field, rules))
        })
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    if value.get("schema") != Some(&Value::String(spec.schema.to_owned()))
        || value.get("schema_version") != Some(&Value::from(1))
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

fn decode_exact(
    bytes: &[u8],
    spec: DocumentSpec,
) -> Result<CanonicalExternalDocumentV1, SignerRefusalV2> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let canonical =
        canonical_json_bytes(&value).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if canonical != bytes {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    validate_against_checked_schema(&value, spec)?;
    let asserted = value
        .get(spec.identity_field)
        .and_then(Value::as_str)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
        .to_owned();
    let mut identity_preimage = value.clone();
    let object = identity_preimage
        .as_object_mut()
        .expect("schema validation required object");
    object.remove(spec.identity_field);
    object.remove("signature");
    if domain_digest(spec.identity_domain, &identity_preimage)? != asserted {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(CanonicalExternalDocumentV1 {
        value,
        canonical_bytes: canonical,
        identity: ExternalCarrierIdentityV1(identity_bytes(&asserted)?),
    })
}

fn construct_request(
    value: Value,
    spec: DocumentSpec,
) -> Result<CanonicalExternalDocumentV1, SignerRefusalV2> {
    let bytes =
        canonical_json_bytes(&value).map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    decode_exact(&bytes, spec)
}

macro_rules! document_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct $name(CanonicalExternalDocumentV1);
        impl $name {
            pub(crate) fn identity(&self) -> ExternalCarrierIdentityV1 {
                self.0.identity()
            }
            pub(crate) fn canonical_bytes(&self) -> &[u8] {
                self.0.canonical_bytes()
            }
            pub(crate) fn field(&self, name: &str) -> Option<&Value> {
                self.0.field(name)
            }
        }
    };
}

document_type!(StoreIntegrityProposalDispositionRequestV1);
document_type!(StoreIntegrityProposalDispositionV1);
document_type!(StoreIntegrityBootstrapGrantRequestV1);
document_type!(StoreIntegrityBootstrapGrantV1);
document_type!(StoreIntegrityActivationSuccessorGrantRequestV1);
document_type!(StoreIntegrityActivationSuccessorGrantV1);
document_type!(StoreIntegrityRevocationRequestV1);
document_type!(StoreIntegrityRevocationJudgmentV1);
document_type!(StoreIntegrityRecoveryRequestV1);
document_type!(StoreIntegrityRecoveryGrantV1);
document_type!(StoreIntegrityRestoreAuthorizationRequestV1);
document_type!(StoreIntegrityRestoreAuthorizationV1);
document_type!(StoreIntegrityQuarantineClosureRequestV1);
document_type!(StoreIntegrityQuarantineClosureJudgmentV1);

macro_rules! request_constructor {
    ($construct:ident, $verify:ident, $name:ident, $spec:ident) => {
        pub(crate) fn $construct(value: Value) -> Result<$name, SignerRefusalV2> {
            construct_request(value, $spec).map($name)
        }
        pub(crate) fn $verify(request: &$name) -> Result<(), SignerRefusalV2> {
            decode_exact(request.canonical_bytes(), $spec).map(|_| ())
        }
    };
}

request_constructor!(
    construct_proposal_disposition_request,
    verify_proposal_disposition_request_identity,
    StoreIntegrityProposalDispositionRequestV1,
    PROPOSAL_REQUEST
);
request_constructor!(
    construct_bootstrap_grant_request,
    verify_bootstrap_grant_request_identity,
    StoreIntegrityBootstrapGrantRequestV1,
    BOOTSTRAP_REQUEST
);
request_constructor!(
    construct_activation_successor_grant_request,
    verify_activation_successor_grant_request_identity,
    StoreIntegrityActivationSuccessorGrantRequestV1,
    ACTIVATION_REQUEST
);
request_constructor!(
    construct_revocation_request,
    verify_revocation_request_identity,
    StoreIntegrityRevocationRequestV1,
    REVOCATION_REQUEST
);
request_constructor!(
    construct_recovery_request,
    verify_recovery_request_identity,
    StoreIntegrityRecoveryRequestV1,
    RECOVERY_REQUEST
);
request_constructor!(
    construct_restore_authorization_request,
    verify_restore_authorization_request_identity,
    StoreIntegrityRestoreAuthorizationRequestV1,
    RESTORE_REQUEST
);
request_constructor!(
    construct_quarantine_closure_request,
    verify_quarantine_closure_request_identity,
    StoreIntegrityQuarantineClosureRequestV1,
    QUARANTINE_REQUEST
);

macro_rules! carrier_decoder {
    ($decode:ident, $name:ident, $spec:ident) => {
        pub(crate) fn $decode(bytes: &[u8]) -> Result<$name, SignerRefusalV2> {
            decode_exact(bytes, $spec).map($name)
        }
    };
}

carrier_decoder!(
    decode_store_integrity_proposal_disposition_v1,
    StoreIntegrityProposalDispositionV1,
    PROPOSAL
);
carrier_decoder!(
    decode_store_integrity_bootstrap_grant_v1,
    StoreIntegrityBootstrapGrantV1,
    BOOTSTRAP
);
carrier_decoder!(
    decode_store_integrity_activation_successor_grant_v1,
    StoreIntegrityActivationSuccessorGrantV1,
    ACTIVATION
);
carrier_decoder!(
    decode_store_integrity_revocation_judgment_v1,
    StoreIntegrityRevocationJudgmentV1,
    REVOCATION
);
carrier_decoder!(
    decode_store_integrity_recovery_grant_v1,
    StoreIntegrityRecoveryGrantV1,
    RECOVERY
);
carrier_decoder!(
    decode_restore_authorization_v1,
    StoreIntegrityRestoreAuthorizationV1,
    RESTORE
);
carrier_decoder!(
    decode_quarantine_closure_judgment_v1,
    StoreIntegrityQuarantineClosureJudgmentV1,
    QUARANTINE
);

/// A1 coordinates asserted by a cryptographically authentic carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalA1IssuerClaimV1 {
    pub(crate) digest: String,
    pub(crate) key_generation: u64,
    pub(crate) verification_key: [u8; 32],
    pub(crate) operator_principal: String,
    pub(crate) domain: String,
    pub(crate) policy_version: u64,
    pub(crate) policy_floor: u64,
    pub(crate) issued_against_gen4_cut: u64,
    pub(crate) issued_against_terminal_event: String,
    pub(crate) issued_against_candidate_set: String,
}

/// Terminality hook implemented only by the private same-snapshot Store-owned
/// projection. This tranche still exposes no production verification permit,
/// so decoded carriers cannot yet enter an authoritative Store consumer.
pub(super) trait TerminalA1AuthenticityVerifierV1 {
    fn verify_unique_terminal_a1(
        &self,
        claim: &TerminalA1IssuerClaimV1,
    ) -> Result<(), SignerRefusalV2>;
}

/// Linear authority for the eventual Store-owned terminal-A1 verification
/// driver. No production constructor exists until that driver projects an
/// exact, complete authority snapshot into this module.
#[derive(Debug)]
pub(super) struct ExternalCarrierVerificationPermitV1 {
    _private: (),
}

impl ExternalCarrierVerificationPermitV1 {
    #[cfg(test)]
    fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Pending exact Store-local coordinates expected at carrier consumption.
/// Production construction remains closed until the Store-owned terminal-A1
/// driver can derive the complete coordinate set from one resolved snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExternalGovernanceExpectationV1 {
    exact_fields: BTreeMap<String, Value>,
    earliest_cut: u64,
    latest_cut: u64,
}

impl ExternalGovernanceExpectationV1 {
    fn new(
        exact_fields: BTreeMap<String, Value>,
        earliest_cut: u64,
        latest_cut: u64,
    ) -> Result<Self, SignerRefusalV2> {
        let required = [
            "occurrence_id",
            "physical_store_generation_identity",
            "controlling_activation",
        ];
        let bootstrap_scope = exact_fields.contains_key("signer_scope_policy_identity")
            && exact_fields.contains_key("install_policy_digest");
        let transition_scope = exact_fields.contains_key("signer_lifecycle_root_identity")
            && exact_fields.contains_key("scope_identity")
            && exact_fields.contains_key("active_store_policy_identity");
        if earliest_cut == 0
            || latest_cut < earliest_cut
            || required
                .iter()
                .any(|name| !exact_fields.contains_key(*name))
            || !(bootstrap_scope || transition_scope)
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(Self {
            exact_fields,
            earliest_cut,
            latest_cut,
        })
    }
}

fn u64_field(document: &CanonicalExternalDocumentV1, name: &str) -> Result<u64, SignerRefusalV2> {
    document
        .field(name)
        .and_then(Value::as_u64)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn string_field<'a>(
    document: &'a CanonicalExternalDocumentV1,
    name: &str,
) -> Result<&'a str, SignerRefusalV2> {
    document
        .field(name)
        .and_then(Value::as_str)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn issuer_claim(
    document: &CanonicalExternalDocumentV1,
) -> Result<TerminalA1IssuerClaimV1, SignerRefusalV2> {
    let key_hex = string_field(document, "issuer_a1_verification_key")?;
    let verification_key: [u8; 32] = hex::decode(key_hex)
        .map_err(|_| SignerRefusalV2::WrongTerminalA1Issuer)?
        .try_into()
        .map_err(|_| SignerRefusalV2::WrongTerminalA1Issuer)?;
    Ok(TerminalA1IssuerClaimV1 {
        digest: string_field(document, "issuer_a1_digest")?.to_owned(),
        key_generation: u64_field(document, "issuer_a1_key_generation")?,
        verification_key,
        operator_principal: string_field(document, "issuer_operator_principal")?.to_owned(),
        domain: string_field(document, "issuer_domain")?.to_owned(),
        policy_version: u64_field(document, "issuer_policy_version")?,
        policy_floor: u64_field(document, "issuer_policy_floor")?,
        issued_against_gen4_cut: u64_field(document, "issued_against_gen4_cut")?,
        issued_against_terminal_event: string_field(
            document,
            "issued_against_gen4_terminal_event",
        )?
        .to_owned(),
        issued_against_candidate_set: string_field(document, "issued_against_candidate_set")?
            .to_owned(),
    })
}

fn verify_signature_and_terminal(
    document: &CanonicalExternalDocumentV1,
    spec: DocumentSpec,
    terminal: &impl TerminalA1AuthenticityVerifierV1,
) -> Result<TerminalA1IssuerClaimV1, SignerRefusalV2> {
    let signature_domain = spec
        .signature_domain
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if string_field(document, "signature_domain")? != signature_domain
        || string_field(document, "signature_algorithm")? != "ed25519"
        || string_field(document, "issuer_permitted_scope")? != "runtime_dependency_admission"
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let claim = issuer_claim(document)?;
    let signature_bytes: [u8; 64] = hex::decode(string_field(document, "signature")?)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
        .try_into()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let mut unsigned = document.value.clone();
    unsigned
        .as_object_mut()
        .expect("validated object")
        .remove("signature");
    let canonical = canonical_json_bytes(&unsigned)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let mut preimage = Vec::with_capacity(signature_domain.len() + 1 + canonical.len());
    preimage.extend_from_slice(signature_domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    let key = VerifyingKey::from_bytes(&claim.verification_key)
        .map_err(|_| SignerRefusalV2::WrongTerminalA1Issuer)?;
    key.verify_strict(&preimage, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| SignerRefusalV2::WrongTerminalA1Issuer)?;
    terminal.verify_unique_terminal_a1(&claim)?;
    Ok(claim)
}

fn verify_expectation(
    carrier: &CanonicalExternalDocumentV1,
    request: &CanonicalExternalDocumentV1,
    expectation: &ExternalGovernanceExpectationV1,
) -> Result<(), SignerRefusalV2> {
    for (name, expected) in &expectation.exact_fields {
        if carrier.field(name) != Some(expected) || request.field(name) != Some(expected) {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
    }
    let cut = carrier
        .field("proposed_effect_cut")
        .or_else(|| carrier.field("c2_lifecycle_cut"))
        .and_then(Value::as_u64)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if !(expectation.earliest_cut..=expectation.latest_cut).contains(&cut) {
        return Err(SignerRefusalV2::ExternalCarrierStale);
    }
    Ok(())
}

fn verify_pair(
    carrier: &CanonicalExternalDocumentV1,
    carrier_spec: DocumentSpec,
    request: &CanonicalExternalDocumentV1,
    request_spec: DocumentSpec,
    expectation: &ExternalGovernanceExpectationV1,
    terminal: &impl TerminalA1AuthenticityVerifierV1,
) -> Result<TerminalA1IssuerClaimV1, SignerRefusalV2> {
    decode_exact(carrier.canonical_bytes(), carrier_spec)?;
    decode_exact(request.canonical_bytes(), request_spec)?;
    let request_field = carrier_spec
        .request_identity_field
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let asserted_request = string_field(carrier, request_field)?;
    let expected_request = string_field(request, request_spec.identity_field)?;
    if asserted_request != expected_request {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    if let Some(schema) = carrier_spec.request_schema {
        let schema_field = if carrier_spec.schema == BOOTSTRAP.schema {
            "grant_request_schema"
        } else if carrier_spec.schema == ACTIVATION.schema {
            "activation_successor_request_schema"
        } else if carrier_spec.schema == PROPOSAL.schema {
            "proposal_disposition_request_schema"
        } else if carrier_spec.schema == REVOCATION.schema {
            "revocation_request_schema"
        } else if carrier_spec.schema == RECOVERY.schema {
            "recovery_request_schema"
        } else if carrier_spec.schema == RESTORE.schema {
            "restore_request_schema"
        } else {
            "closure_request_schema"
        };
        if carrier.field(schema_field) != Some(&Value::String(schema.to_owned())) {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
    }
    let carrier_object = carrier.value.as_object().expect("validated object");
    let request_object = request.value.as_object().expect("validated object");
    for (name, request_value) in request_object {
        if matches!(
            name.as_str(),
            "schema" | "schema_version" | "interpretation_policy"
        ) || name == request_spec.identity_field
            || name.starts_with("pre_effect_")
            || name.starts_with("desired_effect_")
        {
            continue;
        }
        if let Some(carrier_value) = carrier_object.get(name) {
            if carrier_value != request_value {
                return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
            }
        }
    }
    verify_expectation(carrier, request, expectation)?;
    verify_signature_and_terminal(carrier, carrier_spec, terminal)
}

/// Verified bootstrap carrier projection suitable for enrollment construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedBootstrapGrantV1 {
    request_identity: ExternalCarrierIdentityV1,
    grant_identity: ExternalCarrierIdentityV1,
    canonical_carrier_digest: SignerIdentityV1,
    issuer: TerminalA1IssuerClaimV1,
    occurrence_id: String,
    a2_chain_root: String,
    a2_chain_root_bytes: SignerIdentityV1,
    controlling_activation: String,
    controlling_activation_bytes: SignerIdentityV1,
    resident_identity: String,
    resident_identity_bytes: SignerIdentityV1,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    trust_anchor_id: String,
    trust_anchor_id_bytes: SignerIdentityV1,
    authority_domain: String,
    activation_policy_version: u64,
    physical_generation: String,
    physical_generation_bytes: SignerIdentityV1,
    lifecycle_root: Option<String>,
    signer_scope_policy: String,
    signer_scope_policy_bytes: SignerIdentityV1,
    signer_scope_policy_version: u64,
    install_policy_digest: SignerIdentityV1,
    store_integrity_public_key: [u8; 32],
    custody_instance_identity: SignerIdentityV1,
    proposed_key_generation: u64,
    proposal_identity: String,
    proposal_identity_bytes: SignerIdentityV1,
    interpretation_policy: String,
    installation_mode: String,
    lifecycle_cut: u64,
    canonical_signature: [u8; 64],
}

impl VerifiedBootstrapGrantV1 {
    pub(crate) const fn request_identity(&self) -> ExternalCarrierIdentityV1 {
        self.request_identity
    }
    pub(crate) const fn grant_identity(&self) -> ExternalCarrierIdentityV1 {
        self.grant_identity
    }
    pub(crate) const fn canonical_carrier_digest(&self) -> SignerIdentityV1 {
        self.canonical_carrier_digest
    }
    pub(crate) const fn carrier_identity(&self) -> ExternalCarrierIdentityV1 {
        self.grant_identity
    }
    pub(crate) fn issuer(&self) -> &TerminalA1IssuerClaimV1 {
        &self.issuer
    }
    pub(crate) fn occurrence_id(&self) -> &str {
        &self.occurrence_id
    }
    pub(crate) fn a2_chain_root(&self) -> &str {
        &self.a2_chain_root
    }
    pub(crate) const fn a2_chain_root_bytes(&self) -> SignerIdentityV1 {
        self.a2_chain_root_bytes
    }
    pub(crate) fn controlling_activation(&self) -> &str {
        &self.controlling_activation
    }
    pub(crate) const fn controlling_activation_bytes(&self) -> SignerIdentityV1 {
        self.controlling_activation_bytes
    }
    pub(crate) fn resident_identity(&self) -> &str {
        &self.resident_identity
    }
    pub(crate) const fn resident_identity_bytes(&self) -> SignerIdentityV1 {
        self.resident_identity_bytes
    }
    pub(crate) const fn resident_generation(&self) -> u64 {
        self.resident_generation
    }
    pub(crate) fn host_role(&self) -> &str {
        &self.host_role
    }
    pub(crate) const fn role_manifest_generation(&self) -> u64 {
        self.role_manifest_generation
    }
    pub(crate) fn trust_anchor_id(&self) -> &str {
        &self.trust_anchor_id
    }
    pub(crate) const fn trust_anchor_id_bytes(&self) -> SignerIdentityV1 {
        self.trust_anchor_id_bytes
    }
    pub(crate) fn authority_domain(&self) -> &str {
        &self.authority_domain
    }
    pub(crate) const fn activation_policy_version(&self) -> u64 {
        self.activation_policy_version
    }
    pub(crate) fn physical_generation(&self) -> &str {
        &self.physical_generation
    }
    pub(crate) const fn physical_generation_bytes(&self) -> SignerIdentityV1 {
        self.physical_generation_bytes
    }
    pub(crate) fn lifecycle_root(&self) -> Option<&str> {
        self.lifecycle_root.as_deref()
    }
    pub(crate) fn signer_scope_policy(&self) -> &str {
        &self.signer_scope_policy
    }
    pub(crate) const fn signer_scope_policy_bytes(&self) -> SignerIdentityV1 {
        self.signer_scope_policy_bytes
    }
    pub(crate) const fn signer_scope_policy_version(&self) -> u64 {
        self.signer_scope_policy_version
    }
    pub(crate) const fn install_policy_digest(&self) -> SignerIdentityV1 {
        self.install_policy_digest
    }
    pub(crate) const fn store_integrity_public_key(&self) -> [u8; 32] {
        self.store_integrity_public_key
    }
    pub(crate) const fn custody_instance_identity(&self) -> SignerIdentityV1 {
        self.custody_instance_identity
    }
    pub(crate) const fn proposed_key_generation(&self) -> u64 {
        self.proposed_key_generation
    }
    pub(crate) fn proposal_identity(&self) -> &str {
        &self.proposal_identity
    }
    pub(crate) const fn proposal_identity_bytes(&self) -> SignerIdentityV1 {
        self.proposal_identity_bytes
    }
    pub(crate) fn interpretation_policy(&self) -> &str {
        &self.interpretation_policy
    }
    pub(crate) fn installation_mode(&self) -> &str {
        &self.installation_mode
    }
    pub(crate) const fn lifecycle_cut(&self) -> u64 {
        self.lifecycle_cut
    }
    pub(crate) const fn canonical_signature(&self) -> &[u8; 64] {
        &self.canonical_signature
    }
}

pub(super) fn verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity(
    _permit: &ExternalCarrierVerificationPermitV1,
    grant: &StoreIntegrityBootstrapGrantV1,
    request: &StoreIntegrityBootstrapGrantRequestV1,
    expectation: &ExternalGovernanceExpectationV1,
    terminal: &impl TerminalA1AuthenticityVerifierV1,
) -> Result<VerifiedBootstrapGrantV1, SignerRefusalV2> {
    let issuer = verify_pair(
        &grant.0,
        BOOTSTRAP,
        &request.0,
        BOOTSTRAP_REQUEST,
        expectation,
        terminal,
    )?;
    if grant.field("interpretation_policy").and_then(Value::as_str) != Some(INTERPRETATION_POLICY)
        || grant
            .field("store_integrity_key_generation")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let signature: [u8; 64] = hex::decode(string_field(&grant.0, "signature")?)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
        .try_into()
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let store_integrity_public_key: [u8; 32] =
        hex::decode(string_field(&grant.0, "store_integrity_public_key")?)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
            .try_into()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let install_policy_digest = identity_bytes(string_field(&grant.0, "install_policy_digest")?)?;
    let custody_instance_identity =
        identity_bytes(string_field(&grant.0, "custody_instance_identity")?)?;
    let proposal_identity = string_field(&grant.0, "proposal_identity")?.to_owned();
    let proposal_identity_bytes = identity_bytes(&proposal_identity)?;
    let physical_generation =
        string_field(&grant.0, "physical_store_generation_identity")?.to_owned();
    let physical_generation_bytes = identity_bytes(&physical_generation)?;
    let signer_scope_policy = string_field(&grant.0, "signer_scope_policy_identity")?.to_owned();
    let signer_scope_policy_bytes = identity_bytes(&signer_scope_policy)?;
    let a2_chain_root = string_field(&grant.0, "a2_chain_root")?.to_owned();
    let a2_chain_root_bytes = identity_bytes(&a2_chain_root)?;
    let controlling_activation = string_field(&grant.0, "controlling_activation")?.to_owned();
    let controlling_activation_bytes = identity_bytes(&controlling_activation)?;
    let resident_identity = string_field(&grant.0, "resident_identity")?.to_owned();
    let resident_identity_bytes = identity_bytes(&resident_identity)?;
    let trust_anchor_id = string_field(&grant.0, "trust_anchor_id")?.to_owned();
    let trust_anchor_id_bytes = identity_bytes(&trust_anchor_id)?;
    let canonical_carrier_digest = identity_bytes(sha256_bytes(grant.canonical_bytes()).as_str())?;
    Ok(VerifiedBootstrapGrantV1 {
        request_identity: request.identity(),
        grant_identity: grant.identity(),
        canonical_carrier_digest,
        issuer,
        occurrence_id: string_field(&grant.0, "occurrence_id")?.to_owned(),
        a2_chain_root,
        a2_chain_root_bytes,
        controlling_activation,
        controlling_activation_bytes,
        resident_identity,
        resident_identity_bytes,
        resident_generation: u64_field(&grant.0, "resident_generation")?,
        host_role: string_field(&grant.0, "host_role")?.to_owned(),
        role_manifest_generation: u64_field(&grant.0, "role_manifest_generation")?,
        trust_anchor_id,
        trust_anchor_id_bytes,
        authority_domain: string_field(&grant.0, "authority_domain")?.to_owned(),
        activation_policy_version: u64_field(&grant.0, "activation_policy_version")?,
        physical_generation,
        physical_generation_bytes,
        lifecycle_root: grant
            .field("signer_lifecycle_root_identity")
            .and_then(Value::as_str)
            .map(str::to_owned),
        signer_scope_policy,
        signer_scope_policy_bytes,
        signer_scope_policy_version: u64_field(&grant.0, "signer_scope_policy_version")?,
        install_policy_digest,
        store_integrity_public_key,
        custody_instance_identity,
        proposed_key_generation: u64_field(&grant.0, "store_integrity_key_generation")?,
        proposal_identity,
        proposal_identity_bytes,
        interpretation_policy: string_field(&grant.0, "interpretation_policy")?.to_owned(),
        installation_mode: string_field(&grant.0, "installation_mode")?.to_owned(),
        lifecycle_cut: u64_field(&grant.0, "c2_lifecycle_cut")?,
        canonical_signature: signature,
    })
}

macro_rules! verified_pair_type {
    ($name:ident, $carrier:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct $name {
            carrier: $carrier,
            request_identity: ExternalCarrierIdentityV1,
            issuer: TerminalA1IssuerClaimV1,
        }

        impl $name {
            pub(crate) fn carrier(&self) -> &$carrier {
                &self.carrier
            }

            pub(crate) const fn carrier_identity(&self) -> ExternalCarrierIdentityV1 {
                self.carrier.0.identity
            }

            pub(crate) const fn request_identity(&self) -> ExternalCarrierIdentityV1 {
                self.request_identity
            }

            pub(crate) fn issuer(&self) -> &TerminalA1IssuerClaimV1 {
                &self.issuer
            }
        }
    };
}

verified_pair_type!(
    VerifiedProposalDispositionV1,
    StoreIntegrityProposalDispositionV1
);
verified_pair_type!(
    VerifiedActivationSuccessorGrantV1,
    StoreIntegrityActivationSuccessorGrantV1
);
verified_pair_type!(
    VerifiedRevocationJudgmentV1,
    StoreIntegrityRevocationJudgmentV1
);
verified_pair_type!(VerifiedRecoveryGrantV1, StoreIntegrityRecoveryGrantV1);
verified_pair_type!(
    VerifiedRestoreAuthorizationV1,
    StoreIntegrityRestoreAuthorizationV1
);
verified_pair_type!(
    VerifiedQuarantineClosureJudgmentV1,
    StoreIntegrityQuarantineClosureJudgmentV1
);

macro_rules! pair_verifier {
    ($name:ident, $verified:ident, $carrier:ident, $carrier_spec:ident, $request:ident, $request_spec:ident) => {
        pub(super) fn $name(
            _permit: &ExternalCarrierVerificationPermitV1,
            carrier: &$carrier,
            request: &$request,
            expectation: &ExternalGovernanceExpectationV1,
            terminal: &impl TerminalA1AuthenticityVerifierV1,
        ) -> Result<$verified, SignerRefusalV2> {
            let issuer = verify_pair(
                &carrier.0,
                $carrier_spec,
                &request.0,
                $request_spec,
                expectation,
                terminal,
            )?;
            Ok($verified {
                carrier: carrier.clone(),
                request_identity: request.identity(),
                issuer,
            })
        }
    };
}

pair_verifier!(
    verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity,
    VerifiedProposalDispositionV1,
    StoreIntegrityProposalDispositionV1,
    PROPOSAL,
    StoreIntegrityProposalDispositionRequestV1,
    PROPOSAL_REQUEST
);
pair_verifier!(
    verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity,
    VerifiedActivationSuccessorGrantV1,
    StoreIntegrityActivationSuccessorGrantV1,
    ACTIVATION,
    StoreIntegrityActivationSuccessorGrantRequestV1,
    ACTIVATION_REQUEST
);
pair_verifier!(
    verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity,
    VerifiedRevocationJudgmentV1,
    StoreIntegrityRevocationJudgmentV1,
    REVOCATION,
    StoreIntegrityRevocationRequestV1,
    REVOCATION_REQUEST
);
pair_verifier!(verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity,
    VerifiedRecoveryGrantV1, StoreIntegrityRecoveryGrantV1, RECOVERY, StoreIntegrityRecoveryRequestV1, RECOVERY_REQUEST);
pair_verifier!(
    verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity,
    VerifiedRestoreAuthorizationV1,
    StoreIntegrityRestoreAuthorizationV1,
    RESTORE,
    StoreIntegrityRestoreAuthorizationRequestV1,
    RESTORE_REQUEST
);
pair_verifier!(
    verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity,
    VerifiedQuarantineClosureJudgmentV1,
    StoreIntegrityQuarantineClosureJudgmentV1,
    QUARANTINE,
    StoreIntegrityQuarantineClosureRequestV1,
    QUARANTINE_REQUEST
);

/// Linear authority for the eventual Store-owned external-carrier ingress.
///
/// No production constructor exists until durable replay persistence and the
/// Store actor are wired. This prevents the process-local set below from being
/// represented as a durable replay decision.
#[derive(Debug)]
pub(super) struct ExternalCarrierStoreIngressPermitV1 {
    _private: (),
}

impl ExternalCarrierStoreIngressPermitV1 {
    #[cfg(test)]
    fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Process-local pending replay model keyed by canonical carrier identity.
///
/// This type is deliberately unreachable in production. It is not durable
/// replay evidence and must not be represented as transactionally persisted.
#[derive(Debug)]
pub(crate) struct ExternalCarrierReplayGuardV1 {
    _permit: ExternalCarrierStoreIngressPermitV1,
    consumed: BTreeSet<ExternalCarrierIdentityV1>,
}

impl ExternalCarrierReplayGuardV1 {
    pub(super) fn new(permit: ExternalCarrierStoreIngressPermitV1) -> Self {
        Self {
            _permit: permit,
            consumed: BTreeSet::new(),
        }
    }

    fn consume(&mut self, identity: ExternalCarrierIdentityV1) -> Result<(), SignerRefusalV2> {
        if !self.consumed.insert(identity) {
            return Err(SignerRefusalV2::ExternalCarrierReplay);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalCarrierDecodeResultV2 {
    ProposalDispositionAccepted,
    BootstrapGrantAccepted,
    ActivationSuccessorGrantAccepted,
    RevocationJudgmentAccepted,
    RecoveryGrantAccepted,
    RestoreAuthorizationAccepted,
    QuarantineClosureJudgmentAccepted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalRequestResultV2 {
    ProposalDispositionRequestPrepared,
    BootstrapGrantRequestPrepared,
    ActivationSuccessorGrantRequestPrepared,
    RevocationRequestPrepared,
    RecoveryRequestPrepared,
    RestoreAuthorizationRequestPrepared,
    QuarantineClosureRequestPrepared,
}

#[derive(Debug)]
pub(crate) enum ExternalCarrierIngressResultV2 {
    ProposalDispositionConsumed(ProposalDispositionIngressReceiptV1),
    BootstrapGrantConsumed(BootstrapGrantIngressReceiptV1),
    ActivationSuccessorGrantConsumed(ActivationSuccessorGrantIngressReceiptV1),
    RestoreAuthorizationConsumed(RestoreAuthorizationIngressReceiptV1),
    RevocationJudgmentConsumed(RevocationJudgmentIngressReceiptV1),
    RecoveryGrantConsumed(RecoveryGrantIngressReceiptV1),
    QuarantineClosureJudgmentConsumed(QuarantineClosureIngressReceiptV1),
}

macro_rules! ingress_type {
    ($name:ident, $verified:ident, $receipt:ident, $result:ident, $method:ident) => {
        #[derive(Debug, PartialEq, Eq)]
        pub(crate) struct $receipt {
            carrier_identity: ExternalCarrierIdentityV1,
            _private: (),
        }
        impl $receipt {
            pub(crate) const fn carrier_identity(&self) -> ExternalCarrierIdentityV1 {
                self.carrier_identity
            }
        }
        pub(crate) struct $name<'a> {
            verified: &'a $verified,
        }
        impl<'a> $name<'a> {
            pub(crate) const fn new(verified: &'a $verified) -> Self {
                Self { verified }
            }
            pub(crate) fn $method(
                &self,
                replay: &mut ExternalCarrierReplayGuardV1,
            ) -> Result<ExternalCarrierIngressResultV2, SignerRefusalV2> {
                let carrier_identity = self.verified.carrier_identity();
                replay.consume(carrier_identity)?;
                Ok(ExternalCarrierIngressResultV2::$result($receipt {
                    carrier_identity,
                    _private: (),
                }))
            }
        }
    };
}

ingress_type!(
    ProposalDispositionIngressV1,
    VerifiedProposalDispositionV1,
    ProposalDispositionIngressReceiptV1,
    ProposalDispositionConsumed,
    apply
);
ingress_type!(
    BootstrapGrantIngressV1,
    VerifiedBootstrapGrantV1,
    BootstrapGrantIngressReceiptV1,
    BootstrapGrantConsumed,
    consume
);
ingress_type!(
    ActivationSuccessorGrantIngressV1,
    VerifiedActivationSuccessorGrantV1,
    ActivationSuccessorGrantIngressReceiptV1,
    ActivationSuccessorGrantConsumed,
    apply
);
ingress_type!(
    RestoreAuthorizationIngressV1,
    VerifiedRestoreAuthorizationV1,
    RestoreAuthorizationIngressReceiptV1,
    RestoreAuthorizationConsumed,
    install_successor
);
ingress_type!(
    RevocationJudgmentIngressV1,
    VerifiedRevocationJudgmentV1,
    RevocationJudgmentIngressReceiptV1,
    RevocationJudgmentConsumed,
    apply
);
ingress_type!(
    RecoveryGrantIngressV1,
    VerifiedRecoveryGrantV1,
    RecoveryGrantIngressReceiptV1,
    RecoveryGrantConsumed,
    apply
);
ingress_type!(
    QuarantineClosureIngressV1,
    VerifiedQuarantineClosureJudgmentV1,
    QuarantineClosureIngressReceiptV1,
    QuarantineClosureJudgmentConsumed,
    close
);

pub(crate) fn verify_proposal_disposition_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::ProposalDispositionConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}

pub(crate) fn verify_bootstrap_grant_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::BootstrapGrantConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}
pub(crate) fn verify_activation_successor_grant_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::ActivationSuccessorGrantConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}
pub(crate) fn verify_restore_authorization_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::RestoreAuthorizationConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}
pub(crate) fn verify_revocation_judgment_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::RevocationJudgmentConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}
pub(crate) fn verify_recovery_grant_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::RecoveryGrantConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}
pub(crate) fn verify_quarantine_closure_ingress_consumption(
    result: ExternalCarrierIngressResultV2,
) -> Result<(), SignerRefusalV2> {
    match result {
        ExternalCarrierIngressResultV2::QuarantineClosureJudgmentConsumed(receipt) => {
            let _ = receipt.carrier_identity();
            Ok(())
        }
        _ => Err(SignerRefusalV2::ExternalCarrierScopeMismatch),
    }
}

/// Closed ingress ownership witness; no plugin or generic carrier arm exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalGovernanceIngressSetV1 {
    ClosedGovernedIngressOwnershipVerified,
}

pub(crate) const fn construct_sg_wu_06a_external_governance_ingress_set()
-> ExternalGovernanceIngressSetV1 {
    ExternalGovernanceIngressSetV1::ClosedGovernedIngressOwnershipVerified
}

pub(crate) fn verify_sg_wu_06a_external_governance_ingress_set_is_closed(
    set: ExternalGovernanceIngressSetV1,
) -> Result<(), SignerRefusalV2> {
    (set == ExternalGovernanceIngressSetV1::ClosedGovernedIngressOwnershipVerified)
        .then_some(())
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

/// Exact proposal-disposition consumption; no enrollment or standing output exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProposalDispositionConsumptionV1 {
    ProposalRetryDuplicateRejectionAbandonmentRestartStatesAreProposalDispositionVerified,
}

pub(crate) const fn construct_sg_n_12_proposal_retry_duplicate_rejection_abandonment_restart_states()
-> ProposalDispositionConsumptionV1 {
    ProposalDispositionConsumptionV1::ProposalRetryDuplicateRejectionAbandonmentRestartStatesAreProposalDispositionVerified
}

pub(crate) fn verify_sg_n_12_proposal_retry_duplicate_rejection_abandonment_restart_states(
    value: ProposalDispositionConsumptionV1,
) -> Result<(), SignerRefusalV2> {
    (value == ProposalDispositionConsumptionV1::ProposalRetryDuplicateRejectionAbandonmentRestartStatesAreProposalDispositionVerified)
        .then_some(()).ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityRevocationEffectReceiptV1(CanonicalExternalDocumentV1);
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuarantineClosureEffectReceiptV1(CanonicalExternalDocumentV1);

fn construct_unsigned_receipt(
    value: Value,
    schema_json: &'static str,
    schema: &'static str,
    identity_domain: &'static str,
    identity_field: &'static str,
) -> Result<CanonicalExternalDocumentV1, SignerRefusalV2> {
    let spec = DocumentSpec {
        schema_json,
        schema,
        identity_domain,
        identity_field,
        signature_domain: None,
        request_schema: None,
        request_identity_field: None,
    };
    let document = construct_request(value, spec)?;
    if document.field("signed") != Some(&Value::Bool(false)) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(document)
}

pub(crate) fn construct_sg_rec_10b_effect_receipt(
    value: Value,
) -> Result<StoreIntegrityRevocationEffectReceiptV1, SignerRefusalV2> {
    construct_unsigned_receipt(
        value,
        REVOCATION_RECEIPT_SCHEMA,
        "nq.c2_store_integrity_revocation_effect_receipt.v1",
        "nq.c2.store_integrity.revocation_effect_receipt.identity.v1",
        "effect_receipt_identity",
    )
    .map(StoreIntegrityRevocationEffectReceiptV1)
}
pub(crate) fn verify_sg_rec_10b_atomic_effect_receipt(
    receipt: &StoreIntegrityRevocationEffectReceiptV1,
) -> Result<RevocationEffectResultV2, SignerRefusalV2> {
    (receipt.0.field("signed") == Some(&Value::Bool(false)))
        .then_some(RevocationEffectResultV2::ReceiptPersisted)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}
pub(crate) fn construct_sg_rec_13b_effect_receipt(
    value: Value,
) -> Result<QuarantineClosureEffectReceiptV1, SignerRefusalV2> {
    construct_unsigned_receipt(
        value,
        QUARANTINE_RECEIPT_SCHEMA,
        "nq.c2_quarantine_closure_effect_receipt.v1",
        "nq.c2.quarantine_closure_effect_receipt.identity.v1",
        "effect_receipt_identity",
    )
    .map(QuarantineClosureEffectReceiptV1)
}
pub(crate) fn verify_sg_rec_13b_atomic_effect_receipt(
    receipt: &QuarantineClosureEffectReceiptV1,
) -> Result<QuarantineClosureEffectResultV2, SignerRefusalV2> {
    (receipt.0.field("signed") == Some(&Value::Bool(false)))
        .then_some(QuarantineClosureEffectResultV2::ReceiptPersisted)
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use nq_protocol::Sha256Digest;
    use serde_json::json;

    use super::*;

    struct TerminalVerifier([u8; 32]);

    impl TerminalA1AuthenticityVerifierV1 for TerminalVerifier {
        fn verify_unique_terminal_a1(
            &self,
            claim: &TerminalA1IssuerClaimV1,
        ) -> Result<(), SignerRefusalV2> {
            (claim.verification_key == self.0)
                .then_some(())
                .ok_or(SignerRefusalV2::WrongTerminalA1Issuer)
        }
    }

    fn sample_field(name: &str, rules: &Map<String, Value>, verifying_key: [u8; 32]) -> Value {
        if let Some(value) = rules.get("const") {
            return value.clone();
        }
        if let Some(value) = rules
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
        {
            return value.clone();
        }
        match rules.get("type").and_then(Value::as_str).unwrap() {
            "string" if name == "issuer_a1_verification_key" => {
                Value::String(hex::encode(verifying_key))
            }
            "string" if name == "signature" => Value::String("00".repeat(64)),
            "string"
                if rules.get("pattern").and_then(Value::as_str)
                    == Some("^sha256:[0-9a-f]{64}$") =>
            {
                Value::String(format!("sha256:{}", "1".repeat(64)))
            }
            "string" if rules.get("pattern").and_then(Value::as_str) == Some("^[0-9a-f]{64}$") => {
                Value::String("1".repeat(64))
            }
            "string" => Value::String("x".to_owned()),
            "integer" => Value::from(rules.get("minimum").and_then(Value::as_u64).unwrap_or(0)),
            "boolean" => Value::Bool(false),
            "null" => Value::Null,
            other => panic!("unsupported test field type {other}"),
        }
    }

    fn sample_document(spec: DocumentSpec, verifying_key: [u8; 32]) -> Value {
        let schema: Value = serde_json::from_str(spec.schema_json).unwrap();
        let mut value = Map::new();
        for (name, rules) in schema["properties"].as_object().unwrap() {
            value.insert(
                name.clone(),
                sample_field(name, rules.as_object().unwrap(), verifying_key),
            );
        }
        let mut document = Value::Object(value);
        let mut identity_preimage = document.clone();
        let object = identity_preimage.as_object_mut().unwrap();
        object.remove(spec.identity_field);
        object.remove("signature");
        let identity = domain_digest(spec.identity_domain, &identity_preimage).unwrap();
        document
            .as_object_mut()
            .unwrap()
            .insert(spec.identity_field.to_owned(), Value::String(identity));
        document
    }

    fn signed_pair_documents(
        request_spec: DocumentSpec,
        carrier_spec: DocumentSpec,
        signing: &SigningKey,
    ) -> (Value, Vec<u8>, ExternalGovernanceExpectationV1) {
        let key = signing.verifying_key().to_bytes();
        let request = sample_document(request_spec, key);
        let mut carrier = sample_document(carrier_spec, key);
        for (name, value) in request.as_object().unwrap() {
            if carrier.get(name).is_some() && !matches!(name.as_str(), "schema" | "schema_version")
            {
                carrier
                    .as_object_mut()
                    .unwrap()
                    .insert(name.clone(), value.clone());
            }
        }
        let mut identity_preimage = carrier.clone();
        identity_preimage
            .as_object_mut()
            .unwrap()
            .remove(carrier_spec.identity_field);
        identity_preimage
            .as_object_mut()
            .unwrap()
            .remove("signature");
        let carrier_identity =
            domain_digest(carrier_spec.identity_domain, &identity_preimage).unwrap();
        carrier.as_object_mut().unwrap().insert(
            carrier_spec.identity_field.to_owned(),
            Value::String(carrier_identity),
        );
        let mut unsigned = carrier.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let canonical = canonical_json_bytes(&unsigned).unwrap();
        let mut preimage = carrier_spec.signature_domain.unwrap().as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        carrier.as_object_mut().unwrap().insert(
            "signature".to_owned(),
            Value::String(hex::encode(signing.sign(&preimage).to_bytes())),
        );

        let names: &[&str] = if request.get("signer_scope_policy_identity").is_some() {
            &[
                "occurrence_id",
                "physical_store_generation_identity",
                "controlling_activation",
                "signer_scope_policy_identity",
                "install_policy_digest",
            ]
        } else {
            &[
                "occurrence_id",
                "physical_store_generation_identity",
                "controlling_activation",
                "signer_lifecycle_root_identity",
                "scope_identity",
                "active_store_policy_identity",
            ]
        };
        let exact_fields = names
            .iter()
            .map(|name| ((*name).to_owned(), request[*name].clone()))
            .collect();
        let cut = carrier
            .get("proposed_effect_cut")
            .or_else(|| carrier.get("c2_lifecycle_cut"))
            .and_then(Value::as_u64)
            .unwrap();
        let expectation = ExternalGovernanceExpectationV1::new(exact_fields, cut, cut).unwrap();
        (
            request,
            canonical_json_bytes(&carrier).unwrap(),
            expectation,
        )
    }

    #[test]
    fn noncanonical_bytes_and_unknown_fields_refuse() {
        let value =
            json!({"schema":"nq.c2_store_integrity_bootstrap_grant_request.v1","schema_version":1});
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        assert_eq!(
            decode_exact(&bytes, BOOTSTRAP_REQUEST),
            Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
        );
    }

    #[test]
    fn replay_guard_is_one_use() {
        let mut guard =
            ExternalCarrierReplayGuardV1::new(ExternalCarrierStoreIngressPermitV1::for_test());
        let identity = ExternalCarrierIdentityV1([7; 32]);
        assert!(guard.consume(identity).is_ok());
        assert_eq!(
            guard.consume(identity),
            Err(SignerRefusalV2::ExternalCarrierReplay)
        );
    }

    #[test]
    fn closed_ingress_has_no_generic_variant() {
        assert!(
            verify_sg_wu_06a_external_governance_ingress_set_is_closed(
                construct_sg_wu_06a_external_governance_ingress_set()
            )
            .is_ok()
        );
    }

    #[test]
    fn bootstrap_pair_is_canonical_signed_terminal_and_one_to_one() {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let key = signing.verifying_key().to_bytes();
        let request_value = sample_document(BOOTSTRAP_REQUEST, key);
        let request = construct_bootstrap_grant_request(request_value.clone()).unwrap();
        let mut grant_value = sample_document(BOOTSTRAP, key);
        for (name, value) in request_value.as_object().unwrap() {
            if grant_value.get(name).is_some()
                && !matches!(name.as_str(), "schema" | "schema_version")
            {
                grant_value
                    .as_object_mut()
                    .unwrap()
                    .insert(name.clone(), value.clone());
            }
        }
        grant_value.as_object_mut().unwrap().insert(
            "grant_request_identity".to_owned(),
            request_value["grant_request_identity"].clone(),
        );
        let mut identity_preimage = grant_value.clone();
        identity_preimage
            .as_object_mut()
            .unwrap()
            .remove("grant_identity");
        identity_preimage
            .as_object_mut()
            .unwrap()
            .remove("signature");
        let grant_identity = domain_digest(BOOTSTRAP.identity_domain, &identity_preimage).unwrap();
        grant_value
            .as_object_mut()
            .unwrap()
            .insert("grant_identity".to_owned(), Value::String(grant_identity));
        let mut unsigned = grant_value.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let canonical = canonical_json_bytes(&unsigned).unwrap();
        let mut preimage = BOOTSTRAP.signature_domain.unwrap().as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        grant_value.as_object_mut().unwrap().insert(
            "signature".to_owned(),
            Value::String(hex::encode(signing.sign(&preimage).to_bytes())),
        );
        let grant_bytes = canonical_json_bytes(&grant_value).unwrap();
        let grant = decode_store_integrity_bootstrap_grant_v1(&grant_bytes).unwrap();
        let exact_fields = [
            "occurrence_id",
            "physical_store_generation_identity",
            "controlling_activation",
            "signer_scope_policy_identity",
            "install_policy_digest",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), request_value[name].clone()))
        .collect();
        let expectation = ExternalGovernanceExpectationV1::new(exact_fields, 1, 1).unwrap();
        let verified =
            verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity(
                &ExternalCarrierVerificationPermitV1::for_test(),
                &grant,
                &request,
                &expectation,
                &TerminalVerifier(key),
            )
            .unwrap();
        assert_eq!(verified.proposed_key_generation(), 0);
        assert_eq!(
            verified.canonical_signature(),
            &signing.sign(&preimage).to_bytes()
        );
        let claim = verified.issuer().clone();
        let issuer = super::super::authority::TerminalA1BootstrapIssuerV1 {
            snapshot_identity: Sha256Digest::parse(claim.issued_against_candidate_set.clone())
                .unwrap(),
            occurrence: verified.occurrence_id().to_owned(),
            trust_anchor_id: Sha256Digest::parse(verified.trust_anchor_id().to_owned()).unwrap(),
            record_digest: Sha256Digest::parse(claim.digest.clone()).unwrap(),
            key_generation: claim.key_generation,
            verifying_key: claim.verification_key,
            operator_principal: claim.operator_principal,
            domain: claim.domain,
            policy_version: claim.policy_version,
            policy_floor: claim.policy_floor,
            terminal_a1_cut: claim.issued_against_gen4_cut,
            terminal_event: Sha256Digest::parse(claim.issued_against_terminal_event).unwrap(),
            issuance_cut: claim.issued_against_gen4_cut,
        };
        let scope = super::super::authority::construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
            &issuer,
            &verified,
        )
        .expect("project complete scope only from verified carrier");
        super::super::authority::verify_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
            &issuer,
            &verified,
            &scope,
        )
        .expect("complete carrier-derived scope revalidates");
        let identity = super::super::authority::construct_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
            &issuer,
            &verified,
        )
        .expect("project canonical signed grant identity");
        super::super::authority::verify_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
            &identity,
        )
        .expect("canonical signed grant identity revalidates");
        assert_eq!(identity.request_identity(), request.identity().bytes());
        assert_eq!(identity.grant_identity(), grant.identity().bytes());

        let mut incomplete = verified.clone();
        incomplete.resident_generation = 0;
        assert!(matches!(
            super::super::authority::construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
                &issuer,
                &incomplete,
            ),
            Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
        ));
        let mut replay =
            ExternalCarrierReplayGuardV1::new(ExternalCarrierStoreIngressPermitV1::for_test());
        let ingress = BootstrapGrantIngressV1::new(&verified);
        let result = ingress.consume(&mut replay).unwrap();
        match &result {
            ExternalCarrierIngressResultV2::BootstrapGrantConsumed(receipt) => {
                assert_eq!(receipt.carrier_identity(), verified.carrier_identity());
            }
            _ => panic!("bootstrap ingress returned another route"),
        }
        assert!(verify_bootstrap_grant_ingress_consumption(result).is_ok());
        assert!(matches!(
            ingress.consume(&mut replay),
            Err(SignerRefusalV2::ExternalCarrierReplay)
        ));
    }

    #[test]
    fn every_nonbootstrap_pair_requires_terminal_verification_before_typed_ingress() {
        let signing = SigningKey::from_bytes(&[73; 32]);
        let key = signing.verifying_key().to_bytes();
        let terminal = TerminalVerifier(key);
        let verification_permit = ExternalCarrierVerificationPermitV1::for_test();

        macro_rules! verify_route {
            ($request_spec:ident, $carrier_spec:ident, $request_ctor:ident, $carrier_decode:ident,
             $pair_verify:ident, $ingress:ident, $method:ident, $result:ident,
             $receipt_verify:ident) => {{
                let (request_value, carrier_bytes, expectation) =
                    signed_pair_documents($request_spec, $carrier_spec, &signing);
                let request = $request_ctor(request_value).unwrap();
                let carrier = $carrier_decode(&carrier_bytes).unwrap();
                let verified = $pair_verify(
                    &verification_permit,
                    &carrier,
                    &request,
                    &expectation,
                    &terminal,
                )
                .unwrap();
                assert_eq!(verified.request_identity(), request.identity());
                let mut replay = ExternalCarrierReplayGuardV1::new(
                    ExternalCarrierStoreIngressPermitV1::for_test(),
                );
                let result = $ingress::new(&verified).$method(&mut replay).unwrap();
                match &result {
                    ExternalCarrierIngressResultV2::$result(receipt) => {
                        assert_eq!(receipt.carrier_identity(), verified.carrier_identity());
                    }
                    _ => panic!("typed ingress returned another route"),
                }
                assert!($receipt_verify(result).is_ok());
            }};
        }

        verify_route!(
            PROPOSAL_REQUEST,
            PROPOSAL,
            construct_proposal_disposition_request,
            decode_store_integrity_proposal_disposition_v1,
            verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity,
            ProposalDispositionIngressV1,
            apply,
            ProposalDispositionConsumed,
            verify_proposal_disposition_ingress_consumption
        );
        verify_route!(
            ACTIVATION_REQUEST,
            ACTIVATION,
            construct_activation_successor_grant_request,
            decode_store_integrity_activation_successor_grant_v1,
            verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity,
            ActivationSuccessorGrantIngressV1,
            apply,
            ActivationSuccessorGrantConsumed,
            verify_activation_successor_grant_ingress_consumption
        );
        verify_route!(
            REVOCATION_REQUEST,
            REVOCATION,
            construct_revocation_request,
            decode_store_integrity_revocation_judgment_v1,
            verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity,
            RevocationJudgmentIngressV1,
            apply,
            RevocationJudgmentConsumed,
            verify_revocation_judgment_ingress_consumption
        );
        verify_route!(
            RECOVERY_REQUEST,
            RECOVERY,
            construct_recovery_request,
            decode_store_integrity_recovery_grant_v1,
            verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity,
            RecoveryGrantIngressV1,
            apply,
            RecoveryGrantConsumed,
            verify_recovery_grant_ingress_consumption
        );
        verify_route!(
            RESTORE_REQUEST,
            RESTORE,
            construct_restore_authorization_request,
            decode_restore_authorization_v1,
            verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity,
            RestoreAuthorizationIngressV1,
            install_successor,
            RestoreAuthorizationConsumed,
            verify_restore_authorization_ingress_consumption
        );
        verify_route!(
            QUARANTINE_REQUEST,
            QUARANTINE,
            construct_quarantine_closure_request,
            decode_quarantine_closure_judgment_v1,
            verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity,
            QuarantineClosureIngressV1,
            close,
            QuarantineClosureJudgmentConsumed,
            verify_quarantine_closure_ingress_consumption
        );
    }
}
