//! Strict terminal-A1 external-governance carrier ingestion.
//!
//! Decoding accepts only exact canonical JSON conforming to the checked-in
//! closed schema.  Ed25519 verifies possession of the key named by the
//! carrier; the separate [`TerminalA1AuthenticityVerifierV1`] hook verifies
//! that the named key is the uniquely resolved terminal A1 generation.  This
//! module deliberately has no A1 signing or external-judgment constructor.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use super::messages::{C2ExternalSigningRouteV1, SignerIdentityV1};
use super::result::SignerRefusalV2;
use crate::StoreError;
use crate::store_generation::live_c2::StoreC2SnapshotActorV1;

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
    route: Option<C2ExternalSigningRouteV1>,
}

const PROPOSAL_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: PROPOSAL_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_proposal_disposition_request.v1",
    identity_domain: "nq.c2.store_integrity_proposal_disposition_request.identity.v1",
    identity_field: "proposal_disposition_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const PROPOSAL: DocumentSpec = DocumentSpec {
    schema_json: PROPOSAL_SCHEMA,
    schema: "nq.c2_store_integrity_proposal_disposition.v1",
    identity_domain: "nq.c2.store_integrity_proposal_disposition.identity.v1",
    identity_field: "proposal_disposition_identity",
    signature_domain: Some("nq.c2.store_integrity_proposal_disposition.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_proposal_disposition_request.v1"),
    request_identity_field: Some("proposal_disposition_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg01ProposalDisposition),
};
const BOOTSTRAP_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: BOOTSTRAP_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_bootstrap_grant_request.v1",
    identity_domain: "nq.c2.store_integrity_bootstrap_grant_request.identity.v1",
    identity_field: "grant_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const BOOTSTRAP: DocumentSpec = DocumentSpec {
    schema_json: BOOTSTRAP_SCHEMA,
    schema: "nq.c2_store_integrity_bootstrap_grant.v1",
    identity_domain: "nq.c2.store_integrity_bootstrap_grant.identity.v1",
    identity_field: "grant_identity",
    signature_domain: Some("nq.c2.store_integrity_bootstrap_grant.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_bootstrap_grant_request.v1"),
    request_identity_field: Some("grant_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg01BootstrapGrant),
};
const ACTIVATION_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: ACTIVATION_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_activation_successor_grant_request.v1",
    identity_domain: "nq.c2.store_integrity_activation_successor_grant_request.identity.v1",
    identity_field: "activation_successor_grant_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const ACTIVATION: DocumentSpec = DocumentSpec {
    schema_json: ACTIVATION_SCHEMA,
    schema: "nq.c2_store_integrity_activation_successor_grant.v1",
    identity_domain: "nq.c2.store_integrity_activation_successor_grant.identity.v1",
    identity_field: "activation_successor_grant_identity",
    signature_domain: Some("nq.c2.store_integrity_activation_successor_grant.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_activation_successor_grant_request.v1"),
    request_identity_field: Some("activation_successor_grant_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg01ActivationSuccessorGrant),
};
const REVOCATION_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: REVOCATION_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_revocation_request.v1",
    identity_domain: "nq.c2.store_integrity_revocation_request.identity.v1",
    identity_field: "revocation_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const REVOCATION: DocumentSpec = DocumentSpec {
    schema_json: REVOCATION_SCHEMA,
    schema: "nq.c2_store_integrity_revocation_judgment.v1",
    identity_domain: "nq.c2.store_integrity_revocation_judgment.identity.v1",
    identity_field: "revocation_judgment_identity",
    signature_domain: Some("nq.c2.store_integrity_revocation_judgment.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_revocation_request.v1"),
    request_identity_field: Some("revocation_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg14RevocationJudgment),
};
const RECOVERY_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: RECOVERY_REQUEST_SCHEMA,
    schema: "nq.c2_store_integrity_recovery_request.v1",
    identity_domain: "nq.c2.store_integrity_recovery_request.identity.v1",
    identity_field: "recovery_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const RECOVERY: DocumentSpec = DocumentSpec {
    schema_json: RECOVERY_SCHEMA,
    schema: "nq.c2_store_integrity_recovery_grant.v1",
    identity_domain: "nq.c2.store_integrity_recovery_grant.identity.v1",
    identity_field: "recovery_grant_identity",
    signature_domain: Some("nq.c2.store_integrity_recovery_grant.a1_signature.v1"),
    request_schema: Some("nq.c2_store_integrity_recovery_request.v1"),
    request_identity_field: Some("recovery_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg15RecoveryGrant),
};
const RESTORE_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: RESTORE_REQUEST_SCHEMA,
    schema: "nq.c2_restore_authorization_request.v1",
    identity_domain: "nq.c2.restore_authorization_request.identity.v1",
    identity_field: "restore_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const RESTORE: DocumentSpec = DocumentSpec {
    schema_json: RESTORE_SCHEMA,
    schema: "nq.c2_restore_authorization.v1",
    identity_domain: "nq.c2.restore_authorization.identity.v1",
    identity_field: "restore_authorization_identity",
    signature_domain: Some("nq.c2.restore_authorization.a1_signature.v1"),
    request_schema: Some("nq.c2_restore_authorization_request.v1"),
    request_identity_field: Some("restore_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg13RestoreAuthorization),
};
const QUARANTINE_REQUEST: DocumentSpec = DocumentSpec {
    schema_json: QUARANTINE_REQUEST_SCHEMA,
    schema: "nq.c2_quarantine_closure_request.v1",
    identity_domain: "nq.c2.quarantine_closure_request.identity.v1",
    identity_field: "closure_request_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const QUARANTINE: DocumentSpec = DocumentSpec {
    schema_json: QUARANTINE_SCHEMA,
    schema: "nq.c2_quarantine_closure_judgment.v1",
    identity_domain: "nq.c2.quarantine_closure_judgment.identity.v1",
    identity_field: "quarantine_closure_judgment_identity",
    signature_domain: Some("nq.c2.quarantine_closure_judgment.a1_signature.v1"),
    request_schema: Some("nq.c2_quarantine_closure_request.v1"),
    request_identity_field: Some("closure_request_identity"),
    route: Some(C2ExternalSigningRouteV1::Msg16QuarantineClosure),
};
const REVOCATION_EFFECT_RECEIPT: DocumentSpec = DocumentSpec {
    schema_json: REVOCATION_RECEIPT_SCHEMA,
    schema: "nq.c2_store_integrity_revocation_effect_receipt.v1",
    identity_domain: "nq.c2.store_integrity.revocation_effect_receipt.identity.v1",
    identity_field: "effect_receipt_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
};
const QUARANTINE_EFFECT_RECEIPT: DocumentSpec = DocumentSpec {
    schema_json: QUARANTINE_RECEIPT_SCHEMA,
    schema: "nq.c2_quarantine_closure_effect_receipt.v1",
    identity_domain: "nq.c2.quarantine_closure_effect_receipt.identity.v1",
    identity_field: "effect_receipt_identity",
    signature_domain: None,
    request_schema: None,
    request_identity_field: None,
    route: None,
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
        "^[^\\u0000-\\u001F\\u007F-\\u009F]+$" => {
            !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
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
pub(in crate::store_generation) trait TerminalA1AuthenticityVerifierV1 {
    fn verify_unique_terminal_a1(
        &self,
        claim: &TerminalA1IssuerClaimV1,
    ) -> Result<(), SignerRefusalV2>;
}

/// Lexical terminal-A1 verification authority borrowed from one exact live
/// Store actor.  The borrow prevents this token from crossing a mutation
/// epoch, while the sealed coordinates prevent substitution of another
/// actor/snapshot/process at verification time.
pub(in crate::store_generation) struct ExternalCarrierVerificationPermitV1<'actor, 'store> {
    basis: ExternalCarrierVerificationPermitBasisV1<'actor, 'store>,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

enum ExternalCarrierVerificationPermitBasisV1<'actor, 'store> {
    Actor(&'actor StoreC2SnapshotActorV1<'store>),
    #[cfg(test)]
    TestOnly,
}

impl<'actor, 'store> ExternalCarrierVerificationPermitV1<'actor, 'store> {
    /// Issue the lexical verification token only from a live Store actor that
    /// has just re-established its exact same-snapshot correspondence.
    pub(in crate::store_generation) fn from_store_actor(
        actor: &'actor StoreC2SnapshotActorV1<'store>,
    ) -> Result<Self, SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        Ok(Self {
            basis: ExternalCarrierVerificationPermitBasisV1::Actor(actor),
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            creator_pid: std::process::id(),
        })
    }

    fn verify_current_actor(&self) -> Result<(), SignerRefusalV2> {
        match self.basis {
            ExternalCarrierVerificationPermitBasisV1::Actor(actor) => {
                actor
                    .verify_same_snapshot()
                    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
                if self.creator_pid != std::process::id()
                    || self.actor_instance_identity != *actor.actor_instance_identity()
                    || self.actor_snapshot_identity != *actor.current_snapshot_identity()
                    || self.actor_effect_epoch != actor.effect_epoch()
                {
                    return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
                }
                Ok(())
            }
            #[cfg(test)]
            ExternalCarrierVerificationPermitBasisV1::TestOnly => Ok(()),
        }
    }

    /// Require the Store-derived expectation and the lexical verification
    /// permit to come from the same actor, snapshot, mutation epoch and
    /// process.  Verifying the permit alone is insufficient: without this
    /// join, an expectation prepared by another Store actor could be paired
    /// with an otherwise-current permit.
    fn verify_expectation_basis(
        &self,
        expectation: &ExternalGovernanceExpectationV1,
    ) -> Result<(), SignerRefusalV2> {
        self.verify_current_actor()?;
        expectation
            .verify_process_local_basis()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if self.creator_pid != expectation.creator_pid
            || self.actor_instance_identity != expectation.actor_instance_identity
            || self.actor_snapshot_identity != expectation.actor_snapshot_identity
            || self.actor_effect_epoch != expectation.actor_effect_epoch
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            basis: ExternalCarrierVerificationPermitBasisV1::TestOnly,
            actor_instance_identity: Sha256Digest::parse(format!("sha256:{}", "a".repeat(64)))
                .unwrap(),
            actor_snapshot_identity: Sha256Digest::parse(format!("sha256:{}", "b".repeat(64)))
                .unwrap(),
            actor_effect_epoch: 0,
            creator_pid: std::process::id(),
        }
    }
}

/// Pending exact Store-local coordinates expected at carrier consumption.
/// Production construction remains closed until the Store-owned terminal-A1
/// driver can derive the complete coordinate set from one resolved snapshot.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::store_generation) struct ExternalGovernanceExpectationV1 {
    exact_fields: BTreeMap<String, Value>,
    earliest_cut: u64,
    latest_cut: u64,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

impl ExternalGovernanceExpectationV1 {
    pub(in crate::store_generation) fn new(
        actor: &StoreC2SnapshotActorV1<'_>,
        exact_fields: BTreeMap<String, Value>,
        earliest_cut: u64,
        latest_cut: u64,
    ) -> Result<Self, SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let required = ["occurrence_id", "controlling_activation"];
        let bootstrap_scope = exact_fields.contains_key("signer_scope_policy_identity")
            && exact_fields.contains_key("installed_policy_calculation_identity");
        let transition_scope = exact_fields.contains_key("physical_store_generation_identity")
            && exact_fields.contains_key("signer_lifecycle_root_identity")
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
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            creator_pid: std::process::id(),
        })
    }

    fn verify_process_local_basis(&self) -> Result<(), C2ExternalIngressRefusalV1> {
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity.as_str().is_empty()
            || self.actor_snapshot_identity.as_str().is_empty()
        {
            return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
        }
        Ok(())
    }

    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2ExternalIngressRefusalV1> {
        actor
            .verify_same_snapshot()
            .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)?;
        self.verify_process_local_basis()?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
        {
            return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
        }
        Ok(())
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

fn verify_signature_claim(
    document: &CanonicalExternalDocumentV1,
    spec: DocumentSpec,
) -> Result<TerminalA1IssuerClaimV1, SignerRefusalV2> {
    let route = spec
        .route
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    let signature_domain = spec
        .signature_domain
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    if spec.identity_domain != route.identity_domain()
        || signature_domain != route.signature_domain()
        || string_field(document, "signature_domain")? != route.signature_domain()
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
    Ok(claim)
}

fn verify_signature_and_terminal(
    document: &CanonicalExternalDocumentV1,
    spec: DocumentSpec,
    terminal: &impl TerminalA1AuthenticityVerifierV1,
) -> Result<TerminalA1IssuerClaimV1, SignerRefusalV2> {
    let claim = verify_signature_claim(document, spec)?;
    terminal.verify_unique_terminal_a1(&claim)?;
    Ok(claim)
}

fn verify_expectation(
    carrier: &CanonicalExternalDocumentV1,
    request: &CanonicalExternalDocumentV1,
    expectation: &ExternalGovernanceExpectationV1,
) -> Result<(), SignerRefusalV2> {
    for (name, expected) in &expectation.exact_fields {
        let carrier_value = carrier.field(name);
        let request_value = request.field(name);
        if (carrier_value.is_none() && request_value.is_none())
            || carrier_value.is_some_and(|value| value != expected)
            || request_value.is_some_and(|value| value != expected)
        {
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

fn verify_pair_content_correspondence(
    carrier: &CanonicalExternalDocumentV1,
    carrier_spec: DocumentSpec,
    request: &CanonicalExternalDocumentV1,
    request_spec: DocumentSpec,
) -> Result<(), SignerRefusalV2> {
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
    verify_pair_content_correspondence(carrier, carrier_spec, request, request_spec)?;
    verify_expectation(carrier, request, expectation)?;
    verify_signature_and_terminal(carrier, carrier_spec, terminal)
}

/// Verified bootstrap carrier projection suitable for enrollment construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedBootstrapGrantV1 {
    request_identity: ExternalCarrierIdentityV1,
    grant_identity: ExternalCarrierIdentityV1,
    canonical_request_bytes: Vec<u8>,
    canonical_carrier_digest: SignerIdentityV1,
    canonical_carrier_bytes: Vec<u8>,
    issuer: TerminalA1IssuerClaimV1,
    occurrence_id: String,
    a2_chain_root: String,
    a2_chain_root_bytes: SignerIdentityV1,
    controlling_activation: String,
    controlling_activation_bytes: SignerIdentityV1,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    trust_anchor_id: String,
    trust_anchor_id_bytes: SignerIdentityV1,
    authority_domain: String,
    activation_policy_version: u64,
    lifecycle_root: Option<String>,
    signer_scope_policy: String,
    signer_scope_policy_bytes: SignerIdentityV1,
    signer_scope_policy_version: u64,
    installed_policy_calculation_identity: SignerIdentityV1,
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
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        &self.canonical_request_bytes
    }
    pub(crate) fn canonical_carrier_bytes(&self) -> &[u8] {
        &self.canonical_carrier_bytes
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
    pub(crate) const fn installed_policy_calculation_identity(&self) -> SignerIdentityV1 {
        self.installed_policy_calculation_identity
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

pub(in crate::store_generation) fn verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity(
    permit: &ExternalCarrierVerificationPermitV1<'_, '_>,
    grant: &StoreIntegrityBootstrapGrantV1,
    request: &StoreIntegrityBootstrapGrantRequestV1,
    expectation: &ExternalGovernanceExpectationV1,
    terminal: &impl TerminalA1AuthenticityVerifierV1,
) -> Result<VerifiedBootstrapGrantV1, SignerRefusalV2> {
    permit.verify_expectation_basis(expectation)?;
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
    let installed_policy_calculation_identity = identity_bytes(string_field(
        &grant.0,
        "installed_policy_calculation_identity",
    )?)?;
    let custody_instance_identity =
        identity_bytes(string_field(&grant.0, "custody_instance_identity")?)?;
    let proposal_identity = string_field(&grant.0, "proposal_identity")?.to_owned();
    let proposal_identity_bytes = identity_bytes(&proposal_identity)?;
    let signer_scope_policy = string_field(&grant.0, "signer_scope_policy_identity")?.to_owned();
    let signer_scope_policy_bytes = identity_bytes(&signer_scope_policy)?;
    let a2_chain_root = string_field(&grant.0, "a2_chain_root")?.to_owned();
    let a2_chain_root_bytes = identity_bytes(&a2_chain_root)?;
    let controlling_activation = string_field(&grant.0, "controlling_activation")?.to_owned();
    let controlling_activation_bytes = identity_bytes(&controlling_activation)?;
    let resident_identity = string_field(&grant.0, "resident_identity")?.to_owned();
    let trust_anchor_id = string_field(&grant.0, "trust_anchor_id")?.to_owned();
    let trust_anchor_id_bytes = identity_bytes(&trust_anchor_id)?;
    let canonical_carrier_digest = identity_bytes(sha256_bytes(grant.canonical_bytes()).as_str())?;
    Ok(VerifiedBootstrapGrantV1 {
        request_identity: request.identity(),
        grant_identity: grant.identity(),
        canonical_request_bytes: request.canonical_bytes().to_vec(),
        canonical_carrier_digest,
        canonical_carrier_bytes: grant.canonical_bytes().to_vec(),
        issuer,
        occurrence_id: string_field(&grant.0, "occurrence_id")?.to_owned(),
        a2_chain_root,
        a2_chain_root_bytes,
        controlling_activation,
        controlling_activation_bytes,
        resident_identity,
        resident_generation: u64_field(&grant.0, "resident_generation")?,
        host_role: string_field(&grant.0, "host_role")?.to_owned(),
        role_manifest_generation: u64_field(&grant.0, "role_manifest_generation")?,
        trust_anchor_id,
        trust_anchor_id_bytes,
        authority_domain: string_field(&grant.0, "authority_domain")?.to_owned(),
        activation_policy_version: u64_field(&grant.0, "activation_policy_version")?,
        lifecycle_root: grant
            .field("signer_lifecycle_root_identity")
            .and_then(Value::as_str)
            .map(str::to_owned),
        signer_scope_policy,
        signer_scope_policy_bytes,
        signer_scope_policy_version: u64_field(&grant.0, "signer_scope_policy_version")?,
        installed_policy_calculation_identity,
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
    ($name:ident, $carrier:ident, $request:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct $name {
            carrier: $carrier,
            request: $request,
            request_identity: ExternalCarrierIdentityV1,
            issuer: TerminalA1IssuerClaimV1,
        }

        impl $name {
            pub(crate) fn carrier(&self) -> &$carrier {
                &self.carrier
            }

            pub(crate) fn request(&self) -> &$request {
                &self.request
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
    StoreIntegrityProposalDispositionV1,
    StoreIntegrityProposalDispositionRequestV1
);
verified_pair_type!(
    VerifiedActivationSuccessorGrantV1,
    StoreIntegrityActivationSuccessorGrantV1,
    StoreIntegrityActivationSuccessorGrantRequestV1
);
verified_pair_type!(
    VerifiedRevocationJudgmentV1,
    StoreIntegrityRevocationJudgmentV1,
    StoreIntegrityRevocationRequestV1
);
verified_pair_type!(
    VerifiedRecoveryGrantV1,
    StoreIntegrityRecoveryGrantV1,
    StoreIntegrityRecoveryRequestV1
);
verified_pair_type!(
    VerifiedRestoreAuthorizationV1,
    StoreIntegrityRestoreAuthorizationV1,
    StoreIntegrityRestoreAuthorizationRequestV1
);
verified_pair_type!(
    VerifiedQuarantineClosureJudgmentV1,
    StoreIntegrityQuarantineClosureJudgmentV1,
    StoreIntegrityQuarantineClosureRequestV1
);

macro_rules! pair_verifier {
    ($name:ident, $verified:ident, $carrier:ident, $carrier_spec:ident, $request:ident, $request_spec:ident) => {
        pub(in crate::store_generation) fn $name(
            permit: &ExternalCarrierVerificationPermitV1<'_, '_>,
            carrier: &$carrier,
            request: &$request,
            expectation: &ExternalGovernanceExpectationV1,
            terminal: &impl TerminalA1AuthenticityVerifierV1,
        ) -> Result<$verified, SignerRefusalV2> {
            permit.verify_expectation_basis(expectation)?;
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
                request: request.clone(),
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

/// Opaque, already-verified governed carrier handed from the terminal-A1
/// verifier to the Store actor.  Its fields are deliberately private: only a
/// closed verified carrier/request pair can create one, and the only consumer
/// is the actor-owned durable ingress transaction.
#[derive(Debug)]
pub(crate) struct C2PreparedExternalIngressV1 {
    route: C2ExternalSigningRouteV1,
    request_identity: ExternalCarrierIdentityV1,
    carrier_identity: ExternalCarrierIdentityV1,
    canonical_request: Vec<u8>,
    canonical_carrier: Vec<u8>,
}

macro_rules! prepared_external_ingress_constructor {
    ($name:ident, $verified:ident, $route:ident, $request_bytes:expr, $carrier_bytes:expr) => {
        pub(crate) fn $name(verified: &$verified) -> C2PreparedExternalIngressV1 {
            C2PreparedExternalIngressV1 {
                route: C2ExternalSigningRouteV1::$route,
                request_identity: verified.request_identity(),
                carrier_identity: verified.carrier_identity(),
                canonical_request: ($request_bytes)(verified),
                canonical_carrier: ($carrier_bytes)(verified),
            }
        }
    };
}

prepared_external_ingress_constructor!(
    prepare_bootstrap_grant_ingress,
    VerifiedBootstrapGrantV1,
    Msg01BootstrapGrant,
    |verified: &VerifiedBootstrapGrantV1| verified.canonical_request_bytes().to_vec(),
    |verified: &VerifiedBootstrapGrantV1| verified.canonical_carrier_bytes().to_vec()
);
prepared_external_ingress_constructor!(
    prepare_activation_successor_grant_ingress,
    VerifiedActivationSuccessorGrantV1,
    Msg01ActivationSuccessorGrant,
    |verified: &VerifiedActivationSuccessorGrantV1| verified.request().canonical_bytes().to_vec(),
    |verified: &VerifiedActivationSuccessorGrantV1| verified.carrier().canonical_bytes().to_vec()
);
prepared_external_ingress_constructor!(
    prepare_proposal_disposition_ingress,
    VerifiedProposalDispositionV1,
    Msg01ProposalDisposition,
    |verified: &VerifiedProposalDispositionV1| verified.request().canonical_bytes().to_vec(),
    |verified: &VerifiedProposalDispositionV1| verified.carrier().canonical_bytes().to_vec()
);
prepared_external_ingress_constructor!(
    prepare_restore_authorization_ingress,
    VerifiedRestoreAuthorizationV1,
    Msg13RestoreAuthorization,
    |verified: &VerifiedRestoreAuthorizationV1| verified.request().canonical_bytes().to_vec(),
    |verified: &VerifiedRestoreAuthorizationV1| verified.carrier().canonical_bytes().to_vec()
);
prepared_external_ingress_constructor!(
    prepare_revocation_judgment_ingress,
    VerifiedRevocationJudgmentV1,
    Msg14RevocationJudgment,
    |verified: &VerifiedRevocationJudgmentV1| verified.request().canonical_bytes().to_vec(),
    |verified: &VerifiedRevocationJudgmentV1| verified.carrier().canonical_bytes().to_vec()
);
prepared_external_ingress_constructor!(
    prepare_recovery_grant_ingress,
    VerifiedRecoveryGrantV1,
    Msg15RecoveryGrant,
    |verified: &VerifiedRecoveryGrantV1| verified.request().canonical_bytes().to_vec(),
    |verified: &VerifiedRecoveryGrantV1| verified.carrier().canonical_bytes().to_vec()
);
prepared_external_ingress_constructor!(
    prepare_quarantine_closure_ingress,
    VerifiedQuarantineClosureJudgmentV1,
    Msg16QuarantineClosure,
    |verified: &VerifiedQuarantineClosureJudgmentV1| verified.request().canonical_bytes().to_vec(),
    |verified: &VerifiedQuarantineClosureJudgmentV1| verified.carrier().canonical_bytes().to_vec()
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableExternalIngressDispositionV1 {
    Appended,
    ExactReplay,
}

/// Durable adoption/effect receipt.  This is evidence only; it has no
/// conversion into standing, custody, a signer phase, or an ingress permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableExternalIngressReceiptV1 {
    pub(crate) disposition: DurableExternalIngressDispositionV1,
    pub(crate) route: C2ExternalSigningRouteV1,
    pub(crate) request_identity: ExternalCarrierIdentityV1,
    pub(crate) carrier_identity: ExternalCarrierIdentityV1,
    pub(crate) ingress_sequence: u64,
    pub(crate) effect_identity: String,
    pub(crate) receipt_identity: String,
    pub(crate) receipt_bytes: Vec<u8>,
}

/// Store-adopted bootstrap grant.  Unlike `VerifiedBootstrapGrantV1`, this
/// value proves that the exact verified carrier crossed the sole durable
/// Store ingress boundary at this actor epoch.  It is process-local,
/// nonserializable, noncloneable, and has no constructor from a receipt or
/// carrier digest.
pub(crate) struct StoreAdoptedBootstrapGrantV1 {
    verified: VerifiedBootstrapGrantV1,
    durable_receipt: DurableExternalIngressReceiptV1,
    actor_instance_identity: Sha256Digest,
    post_adoption_snapshot_identity: Sha256Digest,
    post_adoption_effect_epoch: u64,
    creator_pid: u32,
}

impl StoreAdoptedBootstrapGrantV1 {
    pub(in crate::store_generation) fn from_actor_append(
        actor: &StoreC2SnapshotActorV1<'_>,
        verified: VerifiedBootstrapGrantV1,
        durable_receipt: DurableExternalIngressReceiptV1,
    ) -> Result<Self, SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if durable_receipt.route != C2ExternalSigningRouteV1::Msg01BootstrapGrant
            || durable_receipt.request_identity != verified.request_identity()
            || durable_receipt.carrier_identity != verified.grant_identity()
            || durable_receipt.effect_identity.is_empty()
            || durable_receipt.receipt_identity.is_empty()
            || durable_receipt.receipt_bytes.is_empty()
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(Self {
            verified,
            durable_receipt,
            actor_instance_identity: actor.actor_instance_identity().clone(),
            post_adoption_snapshot_identity: actor.current_snapshot_identity().clone(),
            post_adoption_effect_epoch: actor.effect_epoch(),
            creator_pid: std::process::id(),
        })
    }

    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if self.creator_pid != std::process::id()
            || &self.actor_instance_identity != actor.actor_instance_identity()
            || actor.effect_epoch() < self.post_adoption_effect_epoch
            || (actor.effect_epoch() == self.post_adoption_effect_epoch
                && &self.post_adoption_snapshot_identity != actor.current_snapshot_identity())
            || self.durable_receipt.route != C2ExternalSigningRouteV1::Msg01BootstrapGrant
            || self.durable_receipt.request_identity != self.verified.request_identity()
            || self.durable_receipt.carrier_identity != self.verified.grant_identity()
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn verified(&self) -> &VerifiedBootstrapGrantV1 {
        &self.verified
    }

    #[must_use]
    pub(crate) const fn durable_receipt(&self) -> &DurableExternalIngressReceiptV1 {
        &self.durable_receipt
    }

    /// Exact post-ingress actor snapshot bound by the Store adoption.  This
    /// scalar accessor is evidence only; the private adoption wrapper and its
    /// `verify_for_actor` check remain required before it can participate in
    /// the initial possession path.
    pub(in crate::store_generation) const fn post_adoption_snapshot_identity(
        &self,
    ) -> &Sha256Digest {
        &self.post_adoption_snapshot_identity
    }

    /// Exact actor effect epoch after durable MSG-01 adoption.
    pub(in crate::store_generation) const fn post_adoption_effect_epoch(&self) -> u64 {
        self.post_adoption_effect_epoch
    }
}

/// Define a process-local Store adoption wrapper for an external transition
/// input.  The verified carrier and durable ingress receipt remain evidence;
/// only this actor-bound, nonserializable and noncloneable wrapper proves
/// that the exact input crossed the Store-owned ingress boundary in the
/// current process.  There is deliberately no constructor from raw
/// identities, canonical bytes, or a detached receipt.
macro_rules! store_adopted_external_input {
    ($name:ident, $verified:ident, $route:ident) => {
        pub(crate) struct $name {
            verified: $verified,
            durable_receipt: DurableExternalIngressReceiptV1,
            actor_instance_identity: Sha256Digest,
            post_adoption_snapshot_identity: Sha256Digest,
            post_adoption_effect_epoch: u64,
            creator_pid: u32,
        }

        impl $name {
            pub(in crate::store_generation) fn from_actor_append(
                actor: &StoreC2SnapshotActorV1<'_>,
                verified: $verified,
                durable_receipt: DurableExternalIngressReceiptV1,
            ) -> Result<Self, SignerRefusalV2> {
                actor
                    .verify_same_snapshot()
                    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
                if durable_receipt.route != C2ExternalSigningRouteV1::$route
                    || durable_receipt.request_identity != verified.request_identity()
                    || durable_receipt.carrier_identity != verified.carrier_identity()
                    || durable_receipt.effect_identity.is_empty()
                    || durable_receipt.receipt_identity.is_empty()
                    || durable_receipt.receipt_bytes.is_empty()
                {
                    return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
                }
                Ok(Self {
                    verified,
                    durable_receipt,
                    actor_instance_identity: actor.actor_instance_identity().clone(),
                    post_adoption_snapshot_identity: actor.current_snapshot_identity().clone(),
                    post_adoption_effect_epoch: actor.effect_epoch(),
                    creator_pid: std::process::id(),
                })
            }

            pub(crate) fn verify_for_actor(
                &self,
                actor: &StoreC2SnapshotActorV1<'_>,
            ) -> Result<(), SignerRefusalV2> {
                actor
                    .verify_same_snapshot()
                    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
                if self.creator_pid != std::process::id()
                    || &self.actor_instance_identity != actor.actor_instance_identity()
                    || actor.effect_epoch() < self.post_adoption_effect_epoch
                    || (actor.effect_epoch() == self.post_adoption_effect_epoch
                        && &self.post_adoption_snapshot_identity
                            != actor.current_snapshot_identity())
                    || self.durable_receipt.route != C2ExternalSigningRouteV1::$route
                    || self.durable_receipt.request_identity != self.verified.request_identity()
                    || self.durable_receipt.carrier_identity != self.verified.carrier_identity()
                {
                    return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
                }
                Ok(())
            }

            #[must_use]
            pub(crate) const fn verified(&self) -> &$verified {
                &self.verified
            }

            #[must_use]
            pub(crate) const fn durable_receipt(&self) -> &DurableExternalIngressReceiptV1 {
                &self.durable_receipt
            }
        }
    };
}

store_adopted_external_input!(
    StoreAdoptedActivationSuccessorGrantV1,
    VerifiedActivationSuccessorGrantV1,
    Msg01ActivationSuccessorGrant
);
store_adopted_external_input!(
    StoreAdoptedProposalDispositionV1,
    VerifiedProposalDispositionV1,
    Msg01ProposalDisposition
);
store_adopted_external_input!(
    StoreAdoptedRestoreAuthorizationV1,
    VerifiedRestoreAuthorizationV1,
    Msg13RestoreAuthorization
);
store_adopted_external_input!(
    StoreAdoptedRecoveryGrantV1,
    VerifiedRecoveryGrantV1,
    Msg15RecoveryGrant
);

/// The restore-successor driver must consume this exact Store-adopted input,
/// not a decoded authorization or an ingress receipt.  Verification is
/// intentionally actor-relative and therefore cannot survive restart.
pub(crate) fn verify_restore_authorization_ingress_consumption(
    actor: &StoreC2SnapshotActorV1<'_>,
    adopted: &StoreAdoptedRestoreAuthorizationV1,
) -> Result<(), SignerRefusalV2> {
    adopted.verify_for_actor(actor)
}

/// Recovery follows the same noninheritance rule as restore authorization:
/// durable evidence must be freshly verified and resealed by the current
/// Store actor before a recovery transition can consume it.
pub(crate) fn verify_recovery_grant_ingress_consumption(
    actor: &StoreC2SnapshotActorV1<'_>,
    adopted: &StoreAdoptedRecoveryGrantV1,
) -> Result<(), SignerRefusalV2> {
    adopted.verify_for_actor(actor)
}

/// Store-adopted policy-transition regrant evidence.  Its only positive use
/// is the later active-policy transition; adoption itself mints no signer
/// standing, enrollment, policy currentness, or signing capability.
pub(crate) fn verify_activation_successor_grant_ingress_consumption(
    actor: &StoreC2SnapshotActorV1<'_>,
    adopted: &StoreAdoptedActivationSuccessorGrantV1,
) -> Result<(), SignerRefusalV2> {
    adopted.verify_for_actor(actor)
}

/// Store-adopted deterministic proposal disposition.  This sealed input may
/// drive only proposal retry/reject/abandon state; it cannot select signer
/// currentness or enter any signing route.
pub(crate) fn verify_proposal_disposition_ingress_consumption(
    actor: &StoreC2SnapshotActorV1<'_>,
    adopted: &StoreAdoptedProposalDispositionV1,
) -> Result<(), SignerRefusalV2> {
    adopted.verify_for_actor(actor)
}

#[derive(Debug, Error)]
pub(crate) enum C2ExternalIngressRefusalV1 {
    #[error("the same governed-carrier occurrence carried changed canonical content")]
    ChangedContentCollision,
    #[error("durable governed-carrier evidence is malformed or substituted")]
    DurableEvidenceMalformed,
    #[error(
        "the governed effect does not match the exact verified request, Store state, or ingress receipt"
    )]
    EffectPreconditionMismatch,
    #[error("the exact current signer has a durable revocation effect")]
    CurrentSignerRevoked,
    #[error("the restore successor remains quarantined because exact closure evidence is absent")]
    RestoreQuarantineOpen,
    #[error("the durable governed-carrier ingress transaction failed: {0}")]
    DurableStore(#[from] StoreError),
}

#[derive(Debug, Serialize)]
struct GovernedCarrierAdoptionEffectV1<'a> {
    schema: &'static str,
    route: &'static str,
    family: &'static str,
    request_identity: &'a str,
    carrier_identity: &'a str,
    canonical_request_sha256: &'a str,
    canonical_carrier_sha256: &'a str,
    ingress_sequence: u64,
    sole_consumer: &'static str,
}

#[derive(Debug, Serialize)]
struct GovernedCarrierReceiptBodyV1<'a> {
    schema: &'static str,
    route: &'static str,
    family: &'static str,
    request_identity: &'a str,
    carrier_identity: &'a str,
    canonical_request_sha256: &'a str,
    canonical_carrier_sha256: &'a str,
    ingress_sequence: u64,
    effect_identity: &'a str,
    sole_consumer: &'static str,
}

#[derive(Debug, Serialize)]
struct GovernedCarrierReceiptV1<'a> {
    #[serde(flatten)]
    body: GovernedCarrierReceiptBodyV1<'a>,
    receipt_identity: &'a str,
}

fn external_identity_text(identity: ExternalCarrierIdentityV1) -> String {
    format!("sha256:{}", hex::encode(identity.0))
}

fn qualified_digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    sha256_bytes(&preimage).into_string()
}

struct ExistingExternalIngressV1 {
    ingress_sequence: u64,
    receipt_identity: String,
    route: String,
    family: String,
    identity_domain: String,
    signature_domain: String,
    input_kind: String,
    sole_consumer: String,
    request_identity: Vec<u8>,
    carrier_identity: Vec<u8>,
    canonical_request: Vec<u8>,
    canonical_request_sha256: String,
    canonical_carrier: Vec<u8>,
    canonical_carrier_sha256: String,
    effect_identity: String,
    receipt_bytes: Vec<u8>,
}

fn load_external_ingress_for_request(
    transaction: &Transaction<'_>,
    request_identity: ExternalCarrierIdentityV1,
) -> Result<Option<ExistingExternalIngressV1>, C2ExternalIngressRefusalV1> {
    transaction
        .query_row(
            "SELECT ingress_sequence, receipt_identity, route, family,
                    identity_domain, signature_domain, input_kind, sole_consumer,
                    request_identity, carrier_identity, canonical_request,
                    canonical_request_sha256, canonical_carrier,
                    canonical_carrier_sha256, effect_identity, receipt_bytes
             FROM c2_external_carrier_ingress
             WHERE request_identity = ?1",
            params![request_identity.0.as_slice()],
            |row| {
                Ok(ExistingExternalIngressV1 {
                    ingress_sequence: row.get(0)?,
                    receipt_identity: row.get(1)?,
                    route: row.get(2)?,
                    family: row.get(3)?,
                    identity_domain: row.get(4)?,
                    signature_domain: row.get(5)?,
                    input_kind: row.get(6)?,
                    sole_consumer: row.get(7)?,
                    request_identity: row.get(8)?,
                    carrier_identity: row.get(9)?,
                    canonical_request: row.get(10)?,
                    canonical_request_sha256: row.get(11)?,
                    canonical_carrier: row.get(12)?,
                    canonical_carrier_sha256: row.get(13)?,
                    effect_identity: row.get(14)?,
                    receipt_bytes: row.get(15)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
        .map_err(C2ExternalIngressRefusalV1::DurableStore)
}

/// Recompute the generic ingress effect and receipt from the exact durable
/// carrier row.  A row whose registry coordinates or canonical receipt bytes
/// were substituted is malformed evidence, never an exact replay.
fn verify_existing_external_ingress_v1(
    existing: &ExistingExternalIngressV1,
    route: C2ExternalSigningRouteV1,
    request_identity: ExternalCarrierIdentityV1,
    carrier_identity: ExternalCarrierIdentityV1,
    canonical_request: &[u8],
    canonical_carrier: &[u8],
) -> Result<(), C2ExternalIngressRefusalV1> {
    let request_identity_text = external_identity_text(request_identity);
    let carrier_identity_text = external_identity_text(carrier_identity);
    let canonical_request_sha256 = sha256_bytes(canonical_request).into_string();
    let canonical_carrier_sha256 = sha256_bytes(canonical_carrier).into_string();
    let effect_body = GovernedCarrierAdoptionEffectV1 {
        schema: "nq.c2_store_governed_carrier_adoption_effect.v1",
        route: route.as_str(),
        family: route.family().as_str(),
        request_identity: &request_identity_text,
        carrier_identity: &carrier_identity_text,
        canonical_request_sha256: &canonical_request_sha256,
        canonical_carrier_sha256: &canonical_carrier_sha256,
        ingress_sequence: existing.ingress_sequence,
        sole_consumer: route.sole_consumer(),
    };
    let canonical_effect = canonical_json_bytes(&effect_body)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let effect_identity = qualified_digest(
        b"nq.c2.store_governed_carrier_adoption_effect.identity.v1\0",
        &canonical_effect,
    );
    let receipt_body = GovernedCarrierReceiptBodyV1 {
        schema: "nq.c2_store_governed_carrier_ingress_receipt.v1",
        route: route.as_str(),
        family: route.family().as_str(),
        request_identity: &request_identity_text,
        carrier_identity: &carrier_identity_text,
        canonical_request_sha256: &canonical_request_sha256,
        canonical_carrier_sha256: &canonical_carrier_sha256,
        ingress_sequence: existing.ingress_sequence,
        effect_identity: &effect_identity,
        sole_consumer: route.sole_consumer(),
    };
    let canonical_receipt_body = canonical_json_bytes(&receipt_body)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let receipt_identity = qualified_digest(
        b"nq.c2.store_governed_carrier_ingress_receipt.identity.v1\0",
        &canonical_receipt_body,
    );
    let receipt_bytes = canonical_json_bytes(&GovernedCarrierReceiptV1 {
        body: receipt_body,
        receipt_identity: &receipt_identity,
    })
    .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;

    if existing.route != route.as_str()
        || existing.family != route.family().as_str()
        || existing.identity_domain != route.identity_domain()
        || existing.signature_domain != route.signature_domain()
        || existing.input_kind != route.input_kind()
        || existing.sole_consumer != route.sole_consumer()
        || existing.request_identity != request_identity.0
        || existing.carrier_identity != carrier_identity.0
        || existing.canonical_request != canonical_request
        || existing.canonical_request_sha256 != canonical_request_sha256
        || existing.canonical_carrier != canonical_carrier
        || existing.canonical_carrier_sha256 != canonical_carrier_sha256
        || existing.effect_identity != effect_identity
        || existing.receipt_identity != receipt_identity
        || existing.receipt_bytes != receipt_bytes
    {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(())
}

/// Load the one exact inert MSG-01 bootstrap request/grant pair already
/// adopted by the Store.  This does not recreate verification, adoption, or
/// authority: the live actor must still re-run terminal-A1/same-snapshot
/// verification and seal a fresh process-local adoption wrapper.
pub(crate) fn load_durable_bootstrap_grant_pair_for_reopen_v1(
    transaction: &Transaction<'_>,
    expected_request_identity: &Sha256Digest,
    expected_grant_identity: &Sha256Digest,
) -> Result<
    (
        StoreIntegrityBootstrapGrantRequestV1,
        StoreIntegrityBootstrapGrantV1,
    ),
    C2ExternalIngressRefusalV1,
> {
    let request_identity = ExternalCarrierIdentityV1(
        identity_bytes(expected_request_identity.as_str())
            .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?,
    );
    let expected_grant = identity_bytes(expected_grant_identity.as_str())
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let row = load_external_ingress_for_request(transaction, request_identity)?
        .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_existing_external_ingress_v1(
        &row,
        C2ExternalSigningRouteV1::Msg01BootstrapGrant,
        request_identity,
        ExternalCarrierIdentityV1(expected_grant),
        &row.canonical_request,
        &row.canonical_carrier,
    )?;
    let request = decode_exact(&row.canonical_request, BOOTSTRAP_REQUEST)
        .map(StoreIntegrityBootstrapGrantRequestV1)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let grant = decode_store_integrity_bootstrap_grant_v1(&row.canonical_carrier)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if request.identity() != request_identity
        || grant.identity().0 != expected_grant
        || grant.canonical_bytes() != row.canonical_carrier
    {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok((request, grant))
}

/// Atomically adopt one verified governed external carrier and persist its
/// exact replay identity plus effect receipt.  The Store actor is the only
/// production caller and retains ownership of the transaction.
pub(crate) fn append_prepared_external_ingress(
    transaction: &Transaction<'_>,
    prepared: C2PreparedExternalIngressV1,
) -> Result<DurableExternalIngressReceiptV1, C2ExternalIngressRefusalV1> {
    let route = prepared.route;
    if let Some(existing) =
        load_external_ingress_for_request(transaction, prepared.request_identity)?
    {
        match verify_existing_external_ingress_v1(
            &existing,
            route,
            prepared.request_identity,
            prepared.carrier_identity,
            &prepared.canonical_request,
            &prepared.canonical_carrier,
        ) {
            Ok(()) => {}
            Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)
                if existing.route == route.as_str()
                    && existing.request_identity == prepared.request_identity.0
                    && (existing.carrier_identity != prepared.carrier_identity.0
                        || existing.canonical_request != prepared.canonical_request
                        || existing.canonical_carrier != prepared.canonical_carrier) =>
            {
                return Err(C2ExternalIngressRefusalV1::ChangedContentCollision);
            }
            Err(error) => return Err(error),
        }
        return Ok(DurableExternalIngressReceiptV1 {
            disposition: DurableExternalIngressDispositionV1::ExactReplay,
            route,
            request_identity: prepared.request_identity,
            carrier_identity: prepared.carrier_identity,
            ingress_sequence: existing.ingress_sequence,
            effect_identity: existing.effect_identity,
            receipt_identity: existing.receipt_identity,
            receipt_bytes: existing.receipt_bytes,
        });
    }

    // A carrier identity is itself single-use.  Rebinding the same canonical
    // carrier to another request/route is not exact replay.
    let duplicate_carrier = transaction
        .query_row(
            "SELECT 1 FROM c2_external_carrier_ingress WHERE carrier_identity = ?1",
            params![prepared.carrier_identity.0.as_slice()],
            |_| Ok(()),
        )
        .optional()
        .map_err(StoreError::from)?;
    if duplicate_carrier.is_some() {
        return Err(C2ExternalIngressRefusalV1::ChangedContentCollision);
    }

    let ingress_sequence: u64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(ingress_sequence), 0) + 1 FROM c2_external_carrier_ingress",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)?;
    let request_identity = external_identity_text(prepared.request_identity);
    let carrier_identity = external_identity_text(prepared.carrier_identity);
    let canonical_request_sha256 = sha256_bytes(&prepared.canonical_request).into_string();
    let canonical_carrier_sha256 = sha256_bytes(&prepared.canonical_carrier).into_string();
    let effect_body = GovernedCarrierAdoptionEffectV1 {
        schema: "nq.c2_store_governed_carrier_adoption_effect.v1",
        route: route.as_str(),
        family: route.family().as_str(),
        request_identity: &request_identity,
        carrier_identity: &carrier_identity,
        canonical_request_sha256: &canonical_request_sha256,
        canonical_carrier_sha256: &canonical_carrier_sha256,
        ingress_sequence,
        sole_consumer: route.sole_consumer(),
    };
    let canonical_effect = canonical_json_bytes(&effect_body)
        .map_err(|_| StoreError::Invariant("canonical external-ingress effect encoding".into()))?;
    let effect_identity = qualified_digest(
        b"nq.c2.store_governed_carrier_adoption_effect.identity.v1\0",
        &canonical_effect,
    );
    let receipt_body = GovernedCarrierReceiptBodyV1 {
        schema: "nq.c2_store_governed_carrier_ingress_receipt.v1",
        route: route.as_str(),
        family: route.family().as_str(),
        request_identity: &request_identity,
        carrier_identity: &carrier_identity,
        canonical_request_sha256: &canonical_request_sha256,
        canonical_carrier_sha256: &canonical_carrier_sha256,
        ingress_sequence,
        effect_identity: &effect_identity,
        sole_consumer: route.sole_consumer(),
    };
    let canonical_receipt_body = canonical_json_bytes(&receipt_body)
        .map_err(|_| StoreError::Invariant("canonical external-ingress receipt encoding".into()))?;
    let receipt_identity = qualified_digest(
        b"nq.c2.store_governed_carrier_ingress_receipt.identity.v1\0",
        &canonical_receipt_body,
    );
    let receipt_bytes = canonical_json_bytes(&GovernedCarrierReceiptV1 {
        body: receipt_body,
        receipt_identity: &receipt_identity,
    })
    .map_err(|_| StoreError::Invariant("canonical external-ingress receipt encoding".into()))?;
    transaction
        .execute(
            "INSERT INTO c2_external_carrier_ingress (
                ingress_sequence, receipt_identity, route, family,
                identity_domain, signature_domain, input_kind, sole_consumer,
                request_identity, carrier_identity, canonical_request,
                canonical_request_sha256, canonical_carrier,
                canonical_carrier_sha256, effect_identity, receipt_bytes,
                committed_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
             )",
            params![
                ingress_sequence,
                receipt_identity,
                route.as_str(),
                route.family().as_str(),
                route.identity_domain(),
                route.signature_domain(),
                route.input_kind(),
                route.sole_consumer(),
                prepared.request_identity.0.as_slice(),
                prepared.carrier_identity.0.as_slice(),
                prepared.canonical_request,
                canonical_request_sha256,
                prepared.canonical_carrier,
                canonical_carrier_sha256,
                effect_identity,
                receipt_bytes,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(StoreError::from)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-54");

    Ok(DurableExternalIngressReceiptV1 {
        disposition: DurableExternalIngressDispositionV1::Appended,
        route,
        request_identity: prepared.request_identity,
        carrier_identity: prepared.carrier_identity,
        ingress_sequence,
        effect_identity,
        receipt_identity,
        receipt_bytes,
    })
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

impl StoreIntegrityRevocationEffectReceiptV1 {
    #[must_use]
    pub(crate) fn identity(&self) -> ExternalCarrierIdentityV1 {
        self.0.identity()
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        self.0.canonical_bytes()
    }
}

impl QuarantineClosureEffectReceiptV1 {
    #[must_use]
    pub(crate) fn identity(&self) -> ExternalCarrierIdentityV1 {
        self.0.identity()
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        self.0.canonical_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableGovernedEffectDispositionV1 {
    Appended,
    ExactReplay,
}

#[derive(Debug)]
pub(crate) struct DurableRevocationEffectV1 {
    disposition: DurableGovernedEffectDispositionV1,
    receipt: StoreIntegrityRevocationEffectReceiptV1,
}

impl DurableRevocationEffectV1 {
    #[must_use]
    pub(crate) const fn disposition(&self) -> DurableGovernedEffectDispositionV1 {
        self.disposition
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &StoreIntegrityRevocationEffectReceiptV1 {
        &self.receipt
    }
}

#[derive(Debug)]
pub(crate) struct DurableQuarantineClosureEffectV1 {
    disposition: DurableGovernedEffectDispositionV1,
    receipt: QuarantineClosureEffectReceiptV1,
}

impl DurableQuarantineClosureEffectV1 {
    #[must_use]
    pub(crate) const fn disposition(&self) -> DurableGovernedEffectDispositionV1 {
        self.disposition
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &QuarantineClosureEffectReceiptV1 {
        &self.receipt
    }
}

fn construct_unsigned_receipt(
    mut body: Map<String, Value>,
    spec: DocumentSpec,
) -> Result<CanonicalExternalDocumentV1, SignerRefusalV2> {
    if body.contains_key(spec.identity_field) || body.contains_key("signature") {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let identity = domain_digest(spec.identity_domain, &Value::Object(body.clone()))?;
    body.insert(spec.identity_field.to_owned(), Value::String(identity));
    let value = Value::Object(body);
    let document = construct_request(value, spec)?;
    if document.field("signed") != Some(&Value::Bool(false)) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(document)
}

fn effect_string(
    document: &CanonicalExternalDocumentV1,
    field: &str,
) -> Result<String, C2ExternalIngressRefusalV1> {
    string_field(document, field)
        .map(str::to_owned)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
}

fn effect_u64(
    document: &CanonicalExternalDocumentV1,
    field: &str,
) -> Result<u64, C2ExternalIngressRefusalV1> {
    u64_field(document, field).map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
}

fn effect_public_key(
    document: &CanonicalExternalDocumentV1,
    field: &str,
) -> Result<[u8; 32], C2ExternalIngressRefusalV1> {
    hex::decode(effect_string(document, field)?)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)?
        .try_into()
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
}

fn verify_ingress_receipt_for_exact_pair_v1(
    transaction: &Transaction<'_>,
    ingress: &DurableExternalIngressReceiptV1,
    route: C2ExternalSigningRouteV1,
    request: &CanonicalExternalDocumentV1,
    carrier: &CanonicalExternalDocumentV1,
) -> Result<(), C2ExternalIngressRefusalV1> {
    if ingress.route != route
        || ingress.request_identity != request.identity()
        || ingress.carrier_identity != carrier.identity()
    {
        return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
    }
    let row = load_external_ingress_for_request(transaction, request.identity())?
        .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_existing_external_ingress_v1(
        &row,
        route,
        request.identity(),
        carrier.identity(),
        request.canonical_bytes(),
        carrier.canonical_bytes(),
    )?;
    if row.ingress_sequence != ingress.ingress_sequence
        || row.effect_identity != ingress.effect_identity
        || row.receipt_identity != ingress.receipt_identity
        || row.receipt_bytes != ingress.receipt_bytes
    {
        return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
    }
    Ok(())
}

fn verify_effect_expectation_v1(
    expectation: &ExternalGovernanceExpectationV1,
    request: &CanonicalExternalDocumentV1,
    carrier: &CanonicalExternalDocumentV1,
    required_fields: &[&str],
) -> Result<(), C2ExternalIngressRefusalV1> {
    expectation.verify_process_local_basis()?;
    if expectation.actor_effect_epoch > 9_007_199_254_740_991
        || required_fields
            .iter()
            .any(|field| !expectation.exact_fields.contains_key(*field))
    {
        return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
    }
    verify_expectation(carrier, request, expectation)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
}

const REVOCATION_EFFECT_REQUIRED_FIELDS_V1: &[&str] = &[
    "issued_against_candidate_set",
    "occurrence_id",
    "a2_chain_root",
    "controlling_activation",
    "resident_identity",
    "resident_generation",
    "host_role",
    "role_manifest_generation",
    "trust_anchor_id",
    "authority_domain",
    "activation_policy_version",
    "physical_store_generation_identity",
    "signer_lifecycle_root_identity",
    "scope_identity",
    "active_store_policy_identity",
    "active_store_policy_generation",
    "pre_effect_frontier_identity",
    "desired_effect_projection_identity",
    "proposed_effect_cut",
    "target_enrollment_identity",
    "target_public_key",
    "target_key_generation",
    "target_standing_identity",
    "last_completed_lifecycle_receipt_identity",
    "effective_cut",
    "reason_code",
    "disposition",
    "revocation_projection_identity",
];

const QUARANTINE_EFFECT_REQUIRED_FIELDS_V1: &[&str] = &[
    "issued_against_candidate_set",
    "occurrence_id",
    "a2_chain_root",
    "controlling_activation",
    "resident_identity",
    "resident_generation",
    "host_role",
    "role_manifest_generation",
    "trust_anchor_id",
    "authority_domain",
    "activation_policy_version",
    "physical_store_generation_identity",
    "signer_lifecycle_root_identity",
    "scope_identity",
    "active_store_policy_identity",
    "active_store_policy_generation",
    "pre_effect_frontier_identity",
    "desired_effect_projection_identity",
    "proposed_effect_cut",
    "restore_authorization_identity",
    "predecessor_physical_store_generation_identity",
    "restore_lineage_identity",
    "restore_disposition_identity",
    "restore_proof_identity",
    "generation_commitment_identity",
    "installation_receipt_identity",
    "current_signer_enrollment_identity",
    "current_signer_public_key",
    "current_signer_key_generation",
    "current_signer_standing_identity",
    "b_root_identity",
    "b_cursor",
    "g_root_identity",
    "g_cursor",
    "lock_domain_identity",
    "backend_profile_identity",
    "implementation_manifest_identity",
    "quarantine_identity",
    "quarantine_state",
    "closure_cut",
    "quarantine_closure_projection_identity",
    "disposition",
    "estate_wide_scope",
];

#[derive(Debug)]
struct RevocationEffectFactsV1 {
    request_identity: ExternalCarrierIdentityV1,
    judgment_identity: ExternalCarrierIdentityV1,
    physical_generation_identity: String,
    lifecycle_root_identity: String,
    scope_identity: String,
    active_policy_identity: String,
    active_policy_generation: u64,
    target_enrollment_identity: String,
    target_public_key: [u8; 32],
    target_key_generation: u64,
    target_standing_identity: String,
    pre_effect_frontier_identity: String,
    effective_cut: u64,
    revocation_projection_identity: String,
    candidate_set_identity: String,
}

fn derive_revocation_effect_facts_v1(
    request: &CanonicalExternalDocumentV1,
    judgment: &CanonicalExternalDocumentV1,
) -> Result<RevocationEffectFactsV1, C2ExternalIngressRefusalV1> {
    verify_pair_content_correspondence(judgment, REVOCATION, request, REVOCATION_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)?;
    verify_signature_claim(judgment, REVOCATION)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)?;
    let desired_projection = effect_string(request, "desired_effect_projection_identity")?;
    let revocation_projection = effect_string(judgment, "revocation_projection_identity")?;
    let proposed_cut = effect_u64(judgment, "proposed_effect_cut")?;
    let effective_cut = effect_u64(judgment, "effective_cut")?;
    if desired_projection != revocation_projection
        || proposed_cut != effective_cut
        || judgment.field("disposition") != Some(&Value::String("revoked".to_owned()))
    {
        return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
    }
    Ok(RevocationEffectFactsV1 {
        request_identity: request.identity(),
        judgment_identity: judgment.identity(),
        physical_generation_identity: effect_string(
            judgment,
            "physical_store_generation_identity",
        )?,
        lifecycle_root_identity: effect_string(judgment, "signer_lifecycle_root_identity")?,
        scope_identity: effect_string(judgment, "scope_identity")?,
        active_policy_identity: effect_string(judgment, "active_store_policy_identity")?,
        active_policy_generation: effect_u64(judgment, "active_store_policy_generation")?,
        target_enrollment_identity: effect_string(judgment, "target_enrollment_identity")?,
        target_public_key: effect_public_key(judgment, "target_public_key")?,
        target_key_generation: effect_u64(judgment, "target_key_generation")?,
        target_standing_identity: effect_string(judgment, "target_standing_identity")?,
        pre_effect_frontier_identity: effect_string(request, "pre_effect_frontier_identity")?,
        effective_cut,
        revocation_projection_identity: revocation_projection,
        candidate_set_identity: effect_string(judgment, "issued_against_candidate_set")?,
    })
}

#[derive(Debug)]
struct QuarantineClosureEffectFactsV1 {
    request_identity: ExternalCarrierIdentityV1,
    judgment_identity: ExternalCarrierIdentityV1,
    physical_generation_identity: String,
    lifecycle_root_identity: String,
    scope_identity: String,
    active_policy_identity: String,
    active_policy_generation: u64,
    restore_authorization_identity: String,
    predecessor_generation_identity: String,
    restore_lineage_identity: String,
    restore_disposition_identity: String,
    restore_proof_identity: String,
    generation_commitment_identity: String,
    installation_receipt_identity: String,
    current_enrollment_identity: String,
    current_public_key: [u8; 32],
    current_key_generation: u64,
    current_standing_identity: String,
    quarantine_identity: String,
    pre_effect_frontier_identity: String,
    closure_cut: u64,
    quarantine_closure_projection_identity: String,
    candidate_set_identity: String,
}

fn derive_quarantine_closure_effect_facts_v1(
    request: &CanonicalExternalDocumentV1,
    judgment: &CanonicalExternalDocumentV1,
) -> Result<QuarantineClosureEffectFactsV1, C2ExternalIngressRefusalV1> {
    verify_pair_content_correspondence(judgment, QUARANTINE, request, QUARANTINE_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)?;
    verify_signature_claim(judgment, QUARANTINE)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)?;
    let desired_projection = effect_string(request, "desired_effect_projection_identity")?;
    let closure_projection = effect_string(judgment, "quarantine_closure_projection_identity")?;
    let proposed_cut = effect_u64(judgment, "proposed_effect_cut")?;
    let closure_cut = effect_u64(judgment, "closure_cut")?;
    if desired_projection != closure_projection
        || proposed_cut != closure_cut
        || judgment.field("quarantine_state") != Some(&Value::String("closed_to_writes".to_owned()))
        || judgment.field("disposition")
            != Some(&Value::String("quarantine_closure_authorized".to_owned()))
        || judgment.field("estate_wide_scope") != Some(&Value::Bool(false))
    {
        return Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch);
    }
    Ok(QuarantineClosureEffectFactsV1 {
        request_identity: request.identity(),
        judgment_identity: judgment.identity(),
        physical_generation_identity: effect_string(
            judgment,
            "physical_store_generation_identity",
        )?,
        lifecycle_root_identity: effect_string(judgment, "signer_lifecycle_root_identity")?,
        scope_identity: effect_string(judgment, "scope_identity")?,
        active_policy_identity: effect_string(judgment, "active_store_policy_identity")?,
        active_policy_generation: effect_u64(judgment, "active_store_policy_generation")?,
        restore_authorization_identity: effect_string(judgment, "restore_authorization_identity")?,
        predecessor_generation_identity: effect_string(
            judgment,
            "predecessor_physical_store_generation_identity",
        )?,
        restore_lineage_identity: effect_string(judgment, "restore_lineage_identity")?,
        restore_disposition_identity: effect_string(judgment, "restore_disposition_identity")?,
        restore_proof_identity: effect_string(judgment, "restore_proof_identity")?,
        generation_commitment_identity: effect_string(judgment, "generation_commitment_identity")?,
        installation_receipt_identity: effect_string(judgment, "installation_receipt_identity")?,
        current_enrollment_identity: effect_string(judgment, "current_signer_enrollment_identity")?,
        current_public_key: effect_public_key(judgment, "current_signer_public_key")?,
        current_key_generation: effect_u64(judgment, "current_signer_key_generation")?,
        current_standing_identity: effect_string(judgment, "current_signer_standing_identity")?,
        quarantine_identity: effect_string(judgment, "quarantine_identity")?,
        pre_effect_frontier_identity: effect_string(request, "pre_effect_frontier_identity")?,
        closure_cut,
        quarantine_closure_projection_identity: closure_projection,
        candidate_set_identity: effect_string(judgment, "issued_against_candidate_set")?,
    })
}

fn build_revocation_effect_receipt_v1(
    facts: &RevocationEffectFactsV1,
) -> Result<StoreIntegrityRevocationEffectReceiptV1, C2ExternalIngressRefusalV1> {
    let mut body = Map::new();
    body.insert(
        "schema".to_owned(),
        Value::String(REVOCATION_EFFECT_RECEIPT.schema.to_owned()),
    );
    body.insert("schema_version".to_owned(), Value::from(1));
    body.insert(
        "revocation_judgment_identity".to_owned(),
        Value::String(external_identity_text(facts.judgment_identity)),
    );
    body.insert(
        "revocation_request_identity".to_owned(),
        Value::String(external_identity_text(facts.request_identity)),
    );
    body.insert(
        "pre_effect_frontier_identity".to_owned(),
        Value::String(facts.pre_effect_frontier_identity.clone()),
    );
    body.insert(
        "revocation_projection_identity".to_owned(),
        Value::String(facts.revocation_projection_identity.clone()),
    );
    body.insert("append_cut".to_owned(), Value::from(facts.effective_cut));
    body.insert(
        "candidate_set_identity".to_owned(),
        Value::String(facts.candidate_set_identity.clone()),
    );
    body.insert("effect".to_owned(), Value::String("revoked".to_owned()));
    body.insert("signed".to_owned(), Value::Bool(false));
    construct_unsigned_receipt(body, REVOCATION_EFFECT_RECEIPT)
        .map(StoreIntegrityRevocationEffectReceiptV1)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
}

fn build_quarantine_closure_effect_receipt_v1(
    facts: &QuarantineClosureEffectFactsV1,
) -> Result<QuarantineClosureEffectReceiptV1, C2ExternalIngressRefusalV1> {
    let mut body = Map::new();
    body.insert(
        "schema".to_owned(),
        Value::String(QUARANTINE_EFFECT_RECEIPT.schema.to_owned()),
    );
    body.insert("schema_version".to_owned(), Value::from(1));
    body.insert(
        "quarantine_closure_judgment_identity".to_owned(),
        Value::String(external_identity_text(facts.judgment_identity)),
    );
    body.insert(
        "closure_request_identity".to_owned(),
        Value::String(external_identity_text(facts.request_identity)),
    );
    body.insert(
        "restore_authorization_identity".to_owned(),
        Value::String(facts.restore_authorization_identity.clone()),
    );
    body.insert(
        "pre_effect_quarantine_frontier_identity".to_owned(),
        Value::String(facts.pre_effect_frontier_identity.clone()),
    );
    body.insert(
        "quarantine_closure_projection_identity".to_owned(),
        Value::String(facts.quarantine_closure_projection_identity.clone()),
    );
    body.insert("append_cut".to_owned(), Value::from(facts.closure_cut));
    body.insert(
        "candidate_set_identity".to_owned(),
        Value::String(facts.candidate_set_identity.clone()),
    );
    body.insert("effect".to_owned(), Value::String("closed".to_owned()));
    body.insert("signed".to_owned(), Value::Bool(false));
    construct_unsigned_receipt(body, QUARANTINE_EFFECT_RECEIPT)
        .map(QuarantineClosureEffectReceiptV1)
        .map_err(|_| C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
}

fn any_row_for_blob(
    transaction: &Transaction<'_>,
    sql: &str,
    identity: &[u8; 32],
) -> Result<bool, C2ExternalIngressRefusalV1> {
    transaction
        .query_row(sql, params![identity.as_slice()], |_| Ok(()))
        .optional()
        .map(|row| row.is_some())
        .map_err(StoreError::from)
        .map_err(C2ExternalIngressRefusalV1::DurableStore)
}

fn load_exact_revocation_effect_receipt_v1(
    transaction: &Transaction<'_>,
    ingress_sequence: u64,
    facts: &RevocationEffectFactsV1,
) -> Result<Option<StoreIntegrityRevocationEffectReceiptV1>, C2ExternalIngressRefusalV1> {
    let row = transaction
        .query_row(
            "SELECT effect_receipt_identity, effect_receipt_bytes,
                    effect_receipt_sha256
             FROM c2_revocation_effects
             WHERE ingress_sequence = ?1 AND request_identity = ?2
               AND judgment_identity = ?3
               AND physical_generation_identity = ?4
               AND lifecycle_root_identity = ?5 AND scope_identity = ?6
               AND active_policy_identity = ?7 AND active_policy_generation = ?8
               AND target_enrollment_identity = ?9 AND target_public_key = ?10
               AND target_key_generation = ?11 AND target_standing_identity = ?12
               AND pre_effect_frontier_identity = ?13 AND effective_cut = ?14
               AND revocation_projection_identity = ?15
               AND candidate_set_identity = ?16",
            params![
                ingress_sequence,
                facts.request_identity.0.as_slice(),
                facts.judgment_identity.0.as_slice(),
                &facts.physical_generation_identity,
                &facts.lifecycle_root_identity,
                &facts.scope_identity,
                &facts.active_policy_identity,
                facts.active_policy_generation,
                &facts.target_enrollment_identity,
                facts.target_public_key.as_slice(),
                facts.target_key_generation,
                &facts.target_standing_identity,
                &facts.pre_effect_frontier_identity,
                facts.effective_cut,
                &facts.revocation_projection_identity,
                &facts.candidate_set_identity,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(StoreError::from)?;
    let Some((identity, bytes, digest)) = row else {
        return Ok(None);
    };
    let document = decode_exact(&bytes, REVOCATION_EFFECT_RECEIPT)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if identity != external_identity_text(document.identity())
        || digest != sha256_bytes(&bytes).as_str()
        || document.field("signed") != Some(&Value::Bool(false))
    {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(Some(StoreIntegrityRevocationEffectReceiptV1(document)))
}

fn load_exact_quarantine_closure_effect_receipt_v1(
    transaction: &Transaction<'_>,
    ingress_sequence: u64,
    facts: &QuarantineClosureEffectFactsV1,
) -> Result<Option<QuarantineClosureEffectReceiptV1>, C2ExternalIngressRefusalV1> {
    let row = transaction
        .query_row(
            "SELECT effect_receipt_identity, effect_receipt_bytes,
                    effect_receipt_sha256
             FROM c2_quarantine_closure_effects
             WHERE ingress_sequence = ?1 AND request_identity = ?2
               AND judgment_identity = ?3
               AND physical_generation_identity = ?4
               AND lifecycle_root_identity = ?5 AND scope_identity = ?6
               AND active_policy_identity = ?7 AND active_policy_generation = ?8
               AND restore_authorization_identity = ?9
               AND predecessor_generation_identity = ?10
               AND restore_lineage_identity = ?11
               AND restore_disposition_identity = ?12
               AND restore_proof_identity = ?13
               AND generation_commitment_identity = ?14
               AND installation_receipt_identity = ?15
               AND current_enrollment_identity = ?16
               AND current_public_key = ?17 AND current_key_generation = ?18
               AND current_standing_identity = ?19
               AND quarantine_identity = ?20
               AND pre_effect_frontier_identity = ?21 AND closure_cut = ?22
               AND quarantine_closure_projection_identity = ?23
               AND candidate_set_identity = ?24",
            params![
                ingress_sequence,
                facts.request_identity.0.as_slice(),
                facts.judgment_identity.0.as_slice(),
                &facts.physical_generation_identity,
                &facts.lifecycle_root_identity,
                &facts.scope_identity,
                &facts.active_policy_identity,
                facts.active_policy_generation,
                &facts.restore_authorization_identity,
                &facts.predecessor_generation_identity,
                &facts.restore_lineage_identity,
                &facts.restore_disposition_identity,
                &facts.restore_proof_identity,
                &facts.generation_commitment_identity,
                &facts.installation_receipt_identity,
                &facts.current_enrollment_identity,
                facts.current_public_key.as_slice(),
                facts.current_key_generation,
                &facts.current_standing_identity,
                &facts.quarantine_identity,
                &facts.pre_effect_frontier_identity,
                facts.closure_cut,
                &facts.quarantine_closure_projection_identity,
                &facts.candidate_set_identity,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(StoreError::from)?;
    let Some((identity, bytes, digest)) = row else {
        return Ok(None);
    };
    let document = decode_exact(&bytes, QUARANTINE_EFFECT_RECEIPT)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if identity != external_identity_text(document.identity())
        || digest != sha256_bytes(&bytes).as_str()
        || document.field("signed") != Some(&Value::Bool(false))
    {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(Some(QuarantineClosureEffectReceiptV1(document)))
}

/// Opaque actor-sealed MSG-14 transaction input.  It owns the exact generic
/// ingress payload and Store expectation so the actor can append ingress,
/// judgment effect and unsigned receipt under one savepoint.  There is no
/// constructor from a detached receipt, request identity, or raw digest.
pub(in crate::store_generation) struct StorePreparedRevocationEffectV1<'input> {
    verified: &'input VerifiedRevocationJudgmentV1,
    ingress: C2PreparedExternalIngressV1,
    expectation: ExternalGovernanceExpectationV1,
}

impl StorePreparedRevocationEffectV1<'_> {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2ExternalIngressRefusalV1> {
        self.expectation.verify_for_actor(actor)
    }

    pub(in crate::store_generation) fn apply(
        self,
        transaction: &Transaction<'_>,
    ) -> Result<DurableRevocationEffectV1, C2ExternalIngressRefusalV1> {
        let receipt = append_prepared_external_ingress(transaction, self.ingress)?;
        apply_verified_revocation_effect_in_transaction_v1(
            transaction,
            self.verified,
            &receipt,
            self.expectation,
        )
    }
}

pub(in crate::store_generation) fn prepare_verified_revocation_effect_v1<'input>(
    actor: &StoreC2SnapshotActorV1<'_>,
    verified: &'input VerifiedRevocationJudgmentV1,
    expectation: ExternalGovernanceExpectationV1,
) -> Result<StorePreparedRevocationEffectV1<'input>, C2ExternalIngressRefusalV1> {
    expectation.verify_for_actor(actor)?;
    Ok(StorePreparedRevocationEffectV1 {
        verified,
        ingress: prepare_revocation_judgment_ingress(verified),
        expectation,
    })
}

/// Opaque actor-sealed MSG-16 transaction input.  The exact MSG-13
/// prerequisite is reloaded inside `apply`; ingress plus closure effect and
/// unsigned receipt therefore commit or refuse as one Store-owned effect.
pub(in crate::store_generation) struct StorePreparedQuarantineClosureEffectV1<'input> {
    verified: &'input VerifiedQuarantineClosureJudgmentV1,
    ingress: C2PreparedExternalIngressV1,
    expectation: ExternalGovernanceExpectationV1,
}

impl StorePreparedQuarantineClosureEffectV1<'_> {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2ExternalIngressRefusalV1> {
        self.expectation.verify_for_actor(actor)
    }

    pub(in crate::store_generation) fn apply(
        self,
        transaction: &Transaction<'_>,
    ) -> Result<DurableQuarantineClosureEffectV1, C2ExternalIngressRefusalV1> {
        let receipt = append_prepared_external_ingress(transaction, self.ingress)?;
        apply_verified_quarantine_closure_effect_in_transaction_v1(
            transaction,
            self.verified,
            &receipt,
            self.expectation,
        )
    }
}

pub(in crate::store_generation) fn prepare_verified_quarantine_closure_effect_v1<'input>(
    actor: &StoreC2SnapshotActorV1<'_>,
    verified: &'input VerifiedQuarantineClosureJudgmentV1,
    expectation: ExternalGovernanceExpectationV1,
) -> Result<StorePreparedQuarantineClosureEffectV1<'input>, C2ExternalIngressRefusalV1> {
    expectation.verify_for_actor(actor)?;
    Ok(StorePreparedQuarantineClosureEffectV1 {
        verified,
        ingress: prepare_quarantine_closure_ingress(verified),
        expectation,
    })
}

/// Atomically append (or reopen exact) the MSG-14 judgment -> revocation
/// projection -> unsigned receipt association.  The only input is a typed
/// terminal-A1 verification result plus the exact durable ingress receipt;
/// no receipt constructor is exposed independently of this write.
fn apply_verified_revocation_effect_in_transaction_v1(
    transaction: &Transaction<'_>,
    verified: &VerifiedRevocationJudgmentV1,
    ingress: &DurableExternalIngressReceiptV1,
    expectation: ExternalGovernanceExpectationV1,
) -> Result<DurableRevocationEffectV1, C2ExternalIngressRefusalV1> {
    verify_ingress_receipt_for_exact_pair_v1(
        transaction,
        ingress,
        C2ExternalSigningRouteV1::Msg14RevocationJudgment,
        &verified.request().0,
        &verified.carrier().0,
    )?;
    verify_effect_expectation_v1(
        &expectation,
        &verified.request().0,
        &verified.carrier().0,
        REVOCATION_EFFECT_REQUIRED_FIELDS_V1,
    )?;
    let facts = derive_revocation_effect_facts_v1(&verified.request().0, &verified.carrier().0)?;
    let expected_receipt = build_revocation_effect_receipt_v1(&facts)?;
    if let Some(receipt) =
        load_exact_revocation_effect_receipt_v1(transaction, ingress.ingress_sequence, &facts)?
    {
        if receipt.canonical_bytes() != expected_receipt.canonical_bytes() {
            return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
        }
        return Ok(DurableRevocationEffectV1 {
            disposition: DurableGovernedEffectDispositionV1::ExactReplay,
            receipt,
        });
    }
    if any_row_for_blob(
        transaction,
        "SELECT 1 FROM c2_revocation_effects WHERE request_identity = ?1",
        &facts.request_identity.0,
    )? {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    let conflict = transaction
        .query_row(
            "SELECT 1 FROM c2_revocation_effects
             WHERE judgment_identity = ?1 OR target_standing_identity = ?2",
            params![
                facts.judgment_identity.0.as_slice(),
                &facts.target_standing_identity,
            ],
            |_| Ok(()),
        )
        .optional()
        .map_err(StoreError::from)?;
    if conflict.is_some() {
        return Err(C2ExternalIngressRefusalV1::ChangedContentCollision);
    }
    let effect_sequence: u64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(effect_sequence), 0) + 1 FROM c2_revocation_effects",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)?;
    transaction
        .execute(
            "INSERT INTO c2_revocation_effects (
                effect_sequence, ingress_sequence, request_identity,
                judgment_identity, physical_generation_identity,
                lifecycle_root_identity, scope_identity, active_policy_identity,
                active_policy_generation, target_enrollment_identity,
                target_public_key, target_key_generation, target_standing_identity,
                pre_effect_frontier_identity, effective_cut,
                revocation_projection_identity, candidate_set_identity,
                effect_receipt_identity, effect_receipt_bytes,
                effect_receipt_sha256, committed_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
             )",
            params![
                effect_sequence,
                ingress.ingress_sequence,
                facts.request_identity.0.as_slice(),
                facts.judgment_identity.0.as_slice(),
                &facts.physical_generation_identity,
                &facts.lifecycle_root_identity,
                &facts.scope_identity,
                &facts.active_policy_identity,
                facts.active_policy_generation,
                &facts.target_enrollment_identity,
                facts.target_public_key.as_slice(),
                facts.target_key_generation,
                &facts.target_standing_identity,
                &facts.pre_effect_frontier_identity,
                facts.effective_cut,
                &facts.revocation_projection_identity,
                &facts.candidate_set_identity,
                external_identity_text(expected_receipt.identity()),
                expected_receipt.canonical_bytes(),
                sha256_bytes(expected_receipt.canonical_bytes()).as_str(),
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(StoreError::from)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-55");
    let receipt =
        load_exact_revocation_effect_receipt_v1(transaction, ingress.ingress_sequence, &facts)?
            .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if receipt.canonical_bytes() != expected_receipt.canonical_bytes() {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(DurableRevocationEffectV1 {
        disposition: DurableGovernedEffectDispositionV1::Appended,
        receipt,
    })
}

/// Atomically append (or reopen exact) the MSG-16 judgment -> quarantine
/// closure projection -> unsigned receipt association.
fn apply_verified_quarantine_closure_effect_in_transaction_v1(
    transaction: &Transaction<'_>,
    verified: &VerifiedQuarantineClosureJudgmentV1,
    ingress: &DurableExternalIngressReceiptV1,
    expectation: ExternalGovernanceExpectationV1,
) -> Result<DurableQuarantineClosureEffectV1, C2ExternalIngressRefusalV1> {
    verify_ingress_receipt_for_exact_pair_v1(
        transaction,
        ingress,
        C2ExternalSigningRouteV1::Msg16QuarantineClosure,
        &verified.request().0,
        &verified.carrier().0,
    )?;
    verify_effect_expectation_v1(
        &expectation,
        &verified.request().0,
        &verified.carrier().0,
        QUARANTINE_EFFECT_REQUIRED_FIELDS_V1,
    )?;
    let facts =
        derive_quarantine_closure_effect_facts_v1(&verified.request().0, &verified.carrier().0)?;
    verify_durable_restore_authorization_identity_v1(
        transaction,
        &facts.restore_authorization_identity,
    )?;
    let expected_receipt = build_quarantine_closure_effect_receipt_v1(&facts)?;
    if let Some(receipt) = load_exact_quarantine_closure_effect_receipt_v1(
        transaction,
        ingress.ingress_sequence,
        &facts,
    )? {
        if receipt.canonical_bytes() != expected_receipt.canonical_bytes() {
            return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
        }
        return Ok(DurableQuarantineClosureEffectV1 {
            disposition: DurableGovernedEffectDispositionV1::ExactReplay,
            receipt,
        });
    }
    if any_row_for_blob(
        transaction,
        "SELECT 1 FROM c2_quarantine_closure_effects WHERE request_identity = ?1",
        &facts.request_identity.0,
    )? {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    let conflict = transaction
        .query_row(
            "SELECT 1 FROM c2_quarantine_closure_effects
             WHERE judgment_identity = ?1 OR quarantine_identity = ?2",
            params![
                facts.judgment_identity.0.as_slice(),
                &facts.quarantine_identity,
            ],
            |_| Ok(()),
        )
        .optional()
        .map_err(StoreError::from)?;
    if conflict.is_some() {
        return Err(C2ExternalIngressRefusalV1::ChangedContentCollision);
    }
    let effect_sequence: u64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(effect_sequence), 0) + 1
             FROM c2_quarantine_closure_effects",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)?;
    transaction
        .execute(
            "INSERT INTO c2_quarantine_closure_effects (
                effect_sequence, ingress_sequence, request_identity,
                judgment_identity, physical_generation_identity,
                lifecycle_root_identity, scope_identity, active_policy_identity,
                active_policy_generation, restore_authorization_identity,
                predecessor_generation_identity, restore_lineage_identity,
                restore_disposition_identity, restore_proof_identity,
                generation_commitment_identity, installation_receipt_identity,
                current_enrollment_identity, current_public_key,
                current_key_generation, current_standing_identity,
                quarantine_identity, pre_effect_frontier_identity, closure_cut,
                quarantine_closure_projection_identity, candidate_set_identity,
                effect_receipt_identity, effect_receipt_bytes,
                effect_receipt_sha256, committed_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29
             )",
            params![
                effect_sequence,
                ingress.ingress_sequence,
                facts.request_identity.0.as_slice(),
                facts.judgment_identity.0.as_slice(),
                &facts.physical_generation_identity,
                &facts.lifecycle_root_identity,
                &facts.scope_identity,
                &facts.active_policy_identity,
                facts.active_policy_generation,
                &facts.restore_authorization_identity,
                &facts.predecessor_generation_identity,
                &facts.restore_lineage_identity,
                &facts.restore_disposition_identity,
                &facts.restore_proof_identity,
                &facts.generation_commitment_identity,
                &facts.installation_receipt_identity,
                &facts.current_enrollment_identity,
                facts.current_public_key.as_slice(),
                facts.current_key_generation,
                &facts.current_standing_identity,
                &facts.quarantine_identity,
                &facts.pre_effect_frontier_identity,
                facts.closure_cut,
                &facts.quarantine_closure_projection_identity,
                &facts.candidate_set_identity,
                external_identity_text(expected_receipt.identity()),
                expected_receipt.canonical_bytes(),
                sha256_bytes(expected_receipt.canonical_bytes()).as_str(),
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(StoreError::from)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-56");
    let receipt = load_exact_quarantine_closure_effect_receipt_v1(
        transaction,
        ingress.ingress_sequence,
        &facts,
    )?
    .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if receipt.canonical_bytes() != expected_receipt.canonical_bytes() {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(DurableQuarantineClosureEffectV1 {
        disposition: DurableGovernedEffectDispositionV1::Appended,
        receipt,
    })
}

fn load_and_validate_revocation_effect_v1(
    transaction: &Transaction<'_>,
    request_identity: ExternalCarrierIdentityV1,
) -> Result<RevocationEffectFactsV1, C2ExternalIngressRefusalV1> {
    let ingress = load_external_ingress_for_request(transaction, request_identity)?
        .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let request = decode_exact(&ingress.canonical_request, REVOCATION_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let judgment = decode_exact(&ingress.canonical_carrier, REVOCATION)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_existing_external_ingress_v1(
        &ingress,
        C2ExternalSigningRouteV1::Msg14RevocationJudgment,
        request.identity(),
        judgment.identity(),
        request.canonical_bytes(),
        judgment.canonical_bytes(),
    )?;
    let facts = derive_revocation_effect_facts_v1(&request, &judgment)?;
    let expected = build_revocation_effect_receipt_v1(&facts)?;
    let receipt =
        load_exact_revocation_effect_receipt_v1(transaction, ingress.ingress_sequence, &facts)?
            .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if receipt.canonical_bytes() != expected.canonical_bytes() {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(facts)
}

fn load_and_validate_quarantine_closure_effect_v1(
    transaction: &Transaction<'_>,
    request_identity: ExternalCarrierIdentityV1,
) -> Result<QuarantineClosureEffectFactsV1, C2ExternalIngressRefusalV1> {
    let ingress = load_external_ingress_for_request(transaction, request_identity)?
        .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let request = decode_exact(&ingress.canonical_request, QUARANTINE_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let judgment = decode_exact(&ingress.canonical_carrier, QUARANTINE)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_existing_external_ingress_v1(
        &ingress,
        C2ExternalSigningRouteV1::Msg16QuarantineClosure,
        request.identity(),
        judgment.identity(),
        request.canonical_bytes(),
        judgment.canonical_bytes(),
    )?;
    let facts = derive_quarantine_closure_effect_facts_v1(&request, &judgment)?;
    let expected = build_quarantine_closure_effect_receipt_v1(&facts)?;
    let receipt = load_exact_quarantine_closure_effect_receipt_v1(
        transaction,
        ingress.ingress_sequence,
        &facts,
    )?
    .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    if receipt.canonical_bytes() != expected.canonical_bytes() {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(facts)
}

pub(super) fn verify_durable_restore_authorization_identity_v1(
    transaction: &Transaction<'_>,
    restore_authorization_identity: &str,
) -> Result<(), C2ExternalIngressRefusalV1> {
    let carrier_identity = identity_bytes(restore_authorization_identity)
        .map(ExternalCarrierIdentityV1)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let request_identity: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT request_identity FROM c2_external_carrier_ingress
             WHERE route = 'msg13_restore_authorization' AND carrier_identity = ?1",
            params![carrier_identity.0.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)?;
    let request_identity: [u8; 32] = request_identity
        .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?
        .try_into()
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let ingress = load_external_ingress_for_request(
        transaction,
        ExternalCarrierIdentityV1(request_identity),
    )?
    .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let request = decode_exact(&ingress.canonical_request, RESTORE_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let authorization = decode_exact(&ingress.canonical_carrier, RESTORE)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_existing_external_ingress_v1(
        &ingress,
        C2ExternalSigningRouteV1::Msg13RestoreAuthorization,
        request.identity(),
        authorization.identity(),
        request.canonical_bytes(),
        authorization.canonical_bytes(),
    )?;
    verify_pair_content_correspondence(&authorization, RESTORE, &request, RESTORE_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_signature_claim(&authorization, RESTORE)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    Ok(())
}

/// Reauthenticate one exact durably adopted MSG-15 request/grant pair.
///
/// This is deliberately a refusal-only seam for sibling Store-owned
/// resolvers.  Successful verification returns no entry authority, phase,
/// custody, or standing; those remain fresh actor-relative constructions.
pub(super) fn verify_durable_recovery_grant_identity_v1(
    transaction: &Transaction<'_>,
    recovery_grant_identity: &str,
) -> Result<(), C2ExternalIngressRefusalV1> {
    let carrier_identity = identity_bytes(recovery_grant_identity)
        .map(ExternalCarrierIdentityV1)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let request_identity: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT request_identity FROM c2_external_carrier_ingress
             WHERE route = 'msg15_recovery_grant' AND carrier_identity = ?1",
            params![carrier_identity.0.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)?;
    let request_identity: [u8; 32] = request_identity
        .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?
        .try_into()
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let ingress = load_external_ingress_for_request(
        transaction,
        ExternalCarrierIdentityV1(request_identity),
    )?
    .ok_or(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let request = decode_exact(&ingress.canonical_request, RECOVERY_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let grant = decode_exact(&ingress.canonical_carrier, RECOVERY)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_existing_external_ingress_v1(
        &ingress,
        C2ExternalSigningRouteV1::Msg15RecoveryGrant,
        request.identity(),
        grant.identity(),
        request.canonical_bytes(),
        grant.canonical_bytes(),
    )?;
    verify_pair_content_correspondence(&grant, RECOVERY, &request, RECOVERY_REQUEST)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    verify_signature_claim(&grant, RECOVERY)
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    Ok(())
}

/// Resolver-visible revocation gate.  It is a refusal-only query: raw target
/// coordinates can never construct standing.  If the exact current
/// enrollment/key/standing tuple has a complete durable MSG-14 association,
/// reopen must refuse; malformed effect evidence also refuses.
pub(in crate::store_generation) fn refuse_if_current_signer_revoked_v1(
    transaction: &Transaction<'_>,
    physical_generation_identity: &str,
    lifecycle_root_identity: &str,
    scope_identity: &str,
    current_enrollment_identity: &str,
    current_public_key: &[u8; 32],
    current_key_generation: u64,
    current_standing_identity: &str,
) -> Result<(), C2ExternalIngressRefusalV1> {
    let request_identities = transaction
        .prepare(
            "SELECT request_identity FROM c2_revocation_effects
             WHERE physical_generation_identity = ?1
               AND lifecycle_root_identity = ?2 AND scope_identity = ?3
               AND target_enrollment_identity = ?4 AND target_public_key = ?5
               AND target_key_generation = ?6 AND target_standing_identity = ?7",
        )
        .map_err(StoreError::from)?
        .query_map(
            params![
                physical_generation_identity,
                lifecycle_root_identity,
                scope_identity,
                current_enrollment_identity,
                current_public_key.as_slice(),
                current_key_generation,
                current_standing_identity,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(StoreError::from)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    if request_identities.len() > 1 {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    if let Some(request_identity) = request_identities.into_iter().next() {
        let request_identity: [u8; 32] = request_identity
            .try_into()
            .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
        let facts = load_and_validate_revocation_effect_v1(
            transaction,
            ExternalCarrierIdentityV1(request_identity),
        )?;
        if facts.physical_generation_identity != physical_generation_identity
            || facts.lifecycle_root_identity != lifecycle_root_identity
            || facts.scope_identity != scope_identity
            || facts.target_enrollment_identity != current_enrollment_identity
            || facts.target_public_key != *current_public_key
            || facts.target_key_generation != current_key_generation
            || facts.target_standing_identity != current_standing_identity
        {
            return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
        }
        return Err(C2ExternalIngressRefusalV1::CurrentSignerRevoked);
    }
    Ok(())
}

/// Resolver-visible restore-quarantine gate. Fresh generations pass with no
/// restore authorization. A restore successor remains closed to writes until
/// one exact MSG-16 effect names its authorization, generation, installation
/// receipt and current signer tuple; the closure also has to point at a
/// durably admitted MSG-13 authorization.
pub(in crate::store_generation) fn verify_restore_quarantine_closed_v1(
    transaction: &Transaction<'_>,
    restore_authorization_identity: Option<&str>,
    physical_generation_identity: &str,
    lifecycle_root_identity: &str,
    scope_identity: &str,
    installation_receipt_identity: &str,
    current_enrollment_identity: &str,
    current_public_key: &[u8; 32],
    current_key_generation: u64,
    current_standing_identity: &str,
) -> Result<(), C2ExternalIngressRefusalV1> {
    let Some(restore_authorization_identity) = restore_authorization_identity else {
        return Ok(());
    };
    verify_durable_restore_authorization_identity_v1(transaction, restore_authorization_identity)?;
    let request_identities = transaction
        .prepare(
            "SELECT request_identity FROM c2_quarantine_closure_effects
             WHERE restore_authorization_identity = ?1
               AND physical_generation_identity = ?2
               AND lifecycle_root_identity = ?3 AND scope_identity = ?4
               AND installation_receipt_identity = ?5
               AND current_enrollment_identity = ?6 AND current_public_key = ?7
               AND current_key_generation = ?8 AND current_standing_identity = ?9",
        )
        .map_err(StoreError::from)?
        .query_map(
            params![
                restore_authorization_identity,
                physical_generation_identity,
                lifecycle_root_identity,
                scope_identity,
                installation_receipt_identity,
                current_enrollment_identity,
                current_public_key.as_slice(),
                current_key_generation,
                current_standing_identity,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(StoreError::from)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    if request_identities.len() > 1 {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    let request_identity = request_identities
        .into_iter()
        .next()
        .ok_or(C2ExternalIngressRefusalV1::RestoreQuarantineOpen)?;
    let request_identity: [u8; 32] = request_identity
        .try_into()
        .map_err(|_| C2ExternalIngressRefusalV1::DurableEvidenceMalformed)?;
    let facts = load_and_validate_quarantine_closure_effect_v1(
        transaction,
        ExternalCarrierIdentityV1(request_identity),
    )?;
    if facts.restore_authorization_identity != restore_authorization_identity
        || facts.physical_generation_identity != physical_generation_identity
        || facts.lifecycle_root_identity != lifecycle_root_identity
        || facts.scope_identity != scope_identity
        || facts.installation_receipt_identity != installation_receipt_identity
        || facts.current_enrollment_identity != current_enrollment_identity
        || facts.current_public_key != *current_public_key
        || facts.current_key_generation != current_key_generation
        || facts.current_standing_identity != current_standing_identity
    {
        return Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::tempdir;

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

    fn set_field(document: &mut Value, name: &str, value: impl Into<Value>) {
        document
            .as_object_mut()
            .expect("test document is an object")
            .insert(name.to_owned(), value.into());
    }

    fn recompute_identity(document: &mut Value, spec: DocumentSpec) {
        let mut identity_preimage = document.clone();
        let object = identity_preimage
            .as_object_mut()
            .expect("test document is an object");
        object.remove(spec.identity_field);
        object.remove("signature");
        let identity = domain_digest(spec.identity_domain, &identity_preimage).unwrap();
        set_field(document, spec.identity_field, identity);
    }

    fn finish_request(mut document: Value, spec: DocumentSpec) -> CanonicalExternalDocumentV1 {
        recompute_identity(&mut document, spec);
        construct_request(document, spec).unwrap()
    }

    fn finish_signed_carrier(
        mut document: Value,
        spec: DocumentSpec,
        signing_key: &SigningKey,
    ) -> CanonicalExternalDocumentV1 {
        recompute_identity(&mut document, spec);
        let mut unsigned = document.clone();
        unsigned
            .as_object_mut()
            .expect("test document is an object")
            .remove("signature");
        let canonical = canonical_json_bytes(&unsigned).unwrap();
        let signature_domain = spec.signature_domain.expect("signed carrier");
        let mut preimage = Vec::with_capacity(signature_domain.len() + 1 + canonical.len());
        preimage.extend_from_slice(signature_domain.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        set_field(
            &mut document,
            "signature",
            hex::encode(signing_key.sign(&preimage).to_bytes()),
        );
        let bytes = canonical_json_bytes(&document).unwrap();
        decode_exact(&bytes, spec).unwrap()
    }

    fn exact_fields_for_test(
        request: &CanonicalExternalDocumentV1,
        carrier: &CanonicalExternalDocumentV1,
        required: &[&str],
    ) -> BTreeMap<String, Value> {
        required
            .iter()
            .map(|name| {
                let value = carrier
                    .field(name)
                    .or_else(|| request.field(name))
                    .unwrap_or_else(|| panic!("missing required test field {name}"));
                ((*name).to_owned(), value.clone())
            })
            .collect()
    }

    fn expectation_for_test(
        exact_fields: BTreeMap<String, Value>,
        cut: u64,
    ) -> ExternalGovernanceExpectationV1 {
        ExternalGovernanceExpectationV1 {
            exact_fields,
            earliest_cut: cut,
            latest_cut: cut,
            actor_instance_identity: Sha256Digest::parse(format!("sha256:{}", "a".repeat(64)))
                .unwrap(),
            actor_snapshot_identity: Sha256Digest::parse(format!("sha256:{}", "b".repeat(64)))
                .unwrap(),
            actor_effect_epoch: 0,
            creator_pid: std::process::id(),
        }
    }

    fn transition_expectation_for_test(
        request: &CanonicalExternalDocumentV1,
        carrier: &CanonicalExternalDocumentV1,
        cut: u64,
    ) -> ExternalGovernanceExpectationV1 {
        expectation_for_test(
            exact_fields_for_test(
                request,
                carrier,
                &[
                    "occurrence_id",
                    "controlling_activation",
                    "physical_store_generation_identity",
                    "signer_lifecycle_root_identity",
                    "scope_identity",
                    "active_store_policy_identity",
                ],
            ),
            cut,
        )
    }

    /// Construct one exact request/carrier pair from the checked schemas,
    /// copying every shared semantic coordinate from the request into the
    /// carrier before signing.  This keeps the test fixture honest: route
    /// verification exercises canonical identities and real Ed25519 rather
    /// than hand-built verified wrappers.
    fn make_schema_pair(
        signing_key: &SigningKey,
        request_spec: DocumentSpec,
        carrier_spec: DocumentSpec,
        cut: u64,
    ) -> (CanonicalExternalDocumentV1, CanonicalExternalDocumentV1) {
        let key = signing_key.verifying_key().to_bytes();
        let mut request = sample_document(request_spec, key);
        for name in [
            "proposed_effect_cut",
            "c2_lifecycle_cut",
            "effective_cut",
            "restore_cut",
            "closure_cut",
        ] {
            if request.get(name).is_some() {
                set_field(&mut request, name, cut);
            }
        }
        let request = finish_request(request, request_spec);

        let mut carrier = sample_document(carrier_spec, key);
        for (name, value) in request.value.as_object().unwrap() {
            if !matches!(name.as_str(), "schema" | "schema_version") && carrier.get(name).is_some()
            {
                set_field(&mut carrier, name, value.clone());
            }
        }
        let request_identity_field = carrier_spec
            .request_identity_field
            .expect("signed test carrier has a request identity field");
        set_field(
            &mut carrier,
            request_identity_field,
            external_identity_text(request.identity()),
        );
        for name in [
            "proposed_effect_cut",
            "c2_lifecycle_cut",
            "effective_cut",
            "restore_cut",
            "closure_cut",
        ] {
            if carrier.get(name).is_some() {
                set_field(&mut carrier, name, cut);
            }
        }
        let carrier = finish_signed_carrier(carrier, carrier_spec, signing_key);
        (request, carrier)
    }

    /// Sign the exact request mechanically emitted by the live Store
    /// bootstrap root.  This test helper constructs no verified ingress or
    /// authority wrapper: production decoding, signature verification,
    /// request correspondence, Store admission, and one-use consumption are
    /// still exercised by the continuation root.
    pub(crate) fn sign_exact_bootstrap_grant_for_test(
        request: &StoreIntegrityBootstrapGrantRequestV1,
        signing_key: &SigningKey,
    ) -> StoreIntegrityBootstrapGrantV1 {
        let mut carrier = sample_document(BOOTSTRAP, signing_key.verifying_key().to_bytes());
        for (name, value) in request.0.value.as_object().unwrap() {
            if !matches!(name.as_str(), "schema" | "schema_version")
                && carrier.get(name).is_some()
            {
                set_field(&mut carrier, name, value.clone());
            }
        }
        set_field(
            &mut carrier,
            BOOTSTRAP
                .request_identity_field
                .expect("bootstrap grant request identity field"),
            external_identity_text(request.identity()),
        );
        StoreIntegrityBootstrapGrantV1(finish_signed_carrier(
            carrier,
            BOOTSTRAP,
            signing_key,
        ))
    }

    /// Sign the exact recovery request mechanically emitted by the live
    /// Store preparation root.  Like the bootstrap helper, this creates only
    /// external carrier evidence; production verification, Store adoption,
    /// discontinuity resolution, and live entry-authority construction are
    /// still exercised by the consequence-bearing continuation root.
    pub(crate) fn sign_exact_recovery_grant_for_test(
        request: &StoreIntegrityRecoveryRequestV1,
        signing_key: &SigningKey,
    ) -> StoreIntegrityRecoveryGrantV1 {
        let mut carrier = sample_document(RECOVERY, signing_key.verifying_key().to_bytes());
        for (name, value) in request.0.value.as_object().unwrap() {
            if !matches!(name.as_str(), "schema" | "schema_version")
                && carrier.get(name).is_some()
            {
                set_field(&mut carrier, name, value.clone());
            }
        }
        set_field(
            &mut carrier,
            RECOVERY
                .request_identity_field
                .expect("recovery grant request identity field"),
            external_identity_text(request.identity()),
        );
        StoreIntegrityRecoveryGrantV1(finish_signed_carrier(
            carrier,
            RECOVERY,
            signing_key,
        ))
    }

    fn exact_schema_pair_from_store_fields_for_test(
        exact_fields: BTreeMap<String, Value>,
        request_spec: DocumentSpec,
        carrier_spec: DocumentSpec,
        signing_key: &SigningKey,
    ) -> (CanonicalExternalDocumentV1, CanonicalExternalDocumentV1) {
        let key = signing_key.verifying_key().to_bytes();
        let mut request = sample_document(request_spec, key);
        for (name, value) in exact_fields {
            if request.get(&name).is_some() {
                set_field(&mut request, &name, value);
            }
        }
        let request = finish_request(request, request_spec);

        let mut carrier = sample_document(carrier_spec, key);
        for (name, value) in request.value.as_object().unwrap() {
            if !matches!(name.as_str(), "schema" | "schema_version")
                && carrier.get(name).is_some()
            {
                set_field(&mut carrier, name, value.clone());
            }
        }
        set_field(
            &mut carrier,
            carrier_spec
                .request_identity_field
                .expect("signed carrier request identity field"),
            external_identity_text(request.identity()),
        );
        let carrier = finish_signed_carrier(carrier, carrier_spec, signing_key);
        (request, carrier)
    }

    /// Build one canonical MSG-14 request/judgment pair from exact inert
    /// fields projected by the Store test actor.  No verified ingress or live
    /// authority wrapper is constructed here.
    pub(crate) fn sign_exact_revocation_judgment_for_test(
        exact_fields: BTreeMap<String, Value>,
        signing_key: &SigningKey,
    ) -> (
        StoreIntegrityRevocationRequestV1,
        StoreIntegrityRevocationJudgmentV1,
    ) {
        let (request, judgment) = exact_schema_pair_from_store_fields_for_test(
            exact_fields,
            REVOCATION_REQUEST,
            REVOCATION,
            signing_key,
        );
        (
            StoreIntegrityRevocationRequestV1(request),
            StoreIntegrityRevocationJudgmentV1(judgment),
        )
    }

    /// Build one canonical MSG-13 request/authorization pair from exact inert
    /// fields projected by the Store test actor.  The production restore root
    /// must still verify and adopt it before any discontinuity entry exists.
    pub(crate) fn sign_exact_restore_authorization_for_test(
        exact_fields: BTreeMap<String, Value>,
        signing_key: &SigningKey,
    ) -> (
        StoreIntegrityRestoreAuthorizationRequestV1,
        StoreIntegrityRestoreAuthorizationV1,
    ) {
        let (request, authorization) = exact_schema_pair_from_store_fields_for_test(
            exact_fields,
            RESTORE_REQUEST,
            RESTORE,
            signing_key,
        );
        (
            StoreIntegrityRestoreAuthorizationRequestV1(request),
            StoreIntegrityRestoreAuthorizationV1(authorization),
        )
    }

    /// Build one canonical MSG-16 request/judgment pair from exact inert
    /// fields projected by the live Store test actor.  Production still owns
    /// verification, MSG-13 association, ingress, effect, and receipt.
    pub(crate) fn sign_exact_quarantine_closure_for_test(
        exact_fields: BTreeMap<String, Value>,
        signing_key: &SigningKey,
    ) -> (
        StoreIntegrityQuarantineClosureRequestV1,
        StoreIntegrityQuarantineClosureJudgmentV1,
    ) {
        let (request, judgment) = exact_schema_pair_from_store_fields_for_test(
            exact_fields,
            QUARANTINE_REQUEST,
            QUARANTINE,
            signing_key,
        );
        (
            StoreIntegrityQuarantineClosureRequestV1(request),
            StoreIntegrityQuarantineClosureJudgmentV1(judgment),
        )
    }

    fn bootstrap_expectation_for_test(
        request: &CanonicalExternalDocumentV1,
        carrier: &CanonicalExternalDocumentV1,
        cut: u64,
    ) -> ExternalGovernanceExpectationV1 {
        expectation_for_test(
            exact_fields_for_test(
                request,
                carrier,
                &[
                    "occurrence_id",
                    "controlling_activation",
                    "signer_scope_policy_identity",
                    "installed_policy_calculation_identity",
                ],
            ),
            cut,
        )
    }

    fn substitute_expectation_snapshot(
        mut expectation: ExternalGovernanceExpectationV1,
    ) -> ExternalGovernanceExpectationV1 {
        expectation.actor_snapshot_identity =
            Sha256Digest::parse(format!("sha256:{}", "e".repeat(64))).unwrap();
        expectation
    }

    fn make_revocation_pair(
        signing_key: &SigningKey,
    ) -> (
        StoreIntegrityRevocationRequestV1,
        StoreIntegrityRevocationJudgmentV1,
    ) {
        let key = signing_key.verifying_key().to_bytes();
        let projection = format!("sha256:{}", "2".repeat(64));
        let mut request = sample_document(REVOCATION_REQUEST, key);
        set_field(
            &mut request,
            "desired_effect_projection_identity",
            projection.clone(),
        );
        set_field(
            &mut request,
            "revocation_projection_identity",
            projection.clone(),
        );
        set_field(&mut request, "proposed_effect_cut", 7_u64);
        set_field(&mut request, "effective_cut", 7_u64);
        let request = finish_request(request, REVOCATION_REQUEST);

        let mut judgment = sample_document(REVOCATION, key);
        set_field(
            &mut judgment,
            "revocation_request_identity",
            external_identity_text(request.identity()),
        );
        set_field(&mut judgment, "revocation_projection_identity", projection);
        set_field(&mut judgment, "proposed_effect_cut", 7_u64);
        set_field(&mut judgment, "effective_cut", 7_u64);
        let judgment = finish_signed_carrier(judgment, REVOCATION, signing_key);
        (
            StoreIntegrityRevocationRequestV1(request),
            StoreIntegrityRevocationJudgmentV1(judgment),
        )
    }

    fn make_restore_pair(
        signing_key: &SigningKey,
    ) -> (
        StoreIntegrityRestoreAuthorizationRequestV1,
        StoreIntegrityRestoreAuthorizationV1,
    ) {
        let key = signing_key.verifying_key().to_bytes();
        let mut request = sample_document(RESTORE_REQUEST, key);
        set_field(&mut request, "proposed_effect_cut", 11_u64);
        set_field(&mut request, "restore_cut", 11_u64);
        let request = finish_request(request, RESTORE_REQUEST);

        let mut authorization = sample_document(RESTORE, key);
        set_field(
            &mut authorization,
            "restore_request_identity",
            external_identity_text(request.identity()),
        );
        set_field(&mut authorization, "proposed_effect_cut", 11_u64);
        set_field(&mut authorization, "restore_cut", 11_u64);
        let authorization = finish_signed_carrier(authorization, RESTORE, signing_key);
        (
            StoreIntegrityRestoreAuthorizationRequestV1(request),
            StoreIntegrityRestoreAuthorizationV1(authorization),
        )
    }

    fn make_quarantine_pair(
        signing_key: &SigningKey,
        restore_authorization_identity: &str,
    ) -> (
        StoreIntegrityQuarantineClosureRequestV1,
        StoreIntegrityQuarantineClosureJudgmentV1,
    ) {
        let key = signing_key.verifying_key().to_bytes();
        let projection = format!("sha256:{}", "3".repeat(64));
        let mut request = sample_document(QUARANTINE_REQUEST, key);
        set_field(
            &mut request,
            "restore_authorization_identity",
            restore_authorization_identity,
        );
        set_field(
            &mut request,
            "desired_effect_projection_identity",
            projection.clone(),
        );
        set_field(
            &mut request,
            "quarantine_closure_projection_identity",
            projection.clone(),
        );
        set_field(&mut request, "proposed_effect_cut", 13_u64);
        set_field(&mut request, "closure_cut", 13_u64);
        let request = finish_request(request, QUARANTINE_REQUEST);

        let mut judgment = sample_document(QUARANTINE, key);
        set_field(
            &mut judgment,
            "closure_request_identity",
            external_identity_text(request.identity()),
        );
        set_field(
            &mut judgment,
            "restore_authorization_identity",
            restore_authorization_identity,
        );
        set_field(
            &mut judgment,
            "quarantine_closure_projection_identity",
            projection,
        );
        set_field(&mut judgment, "proposed_effect_cut", 13_u64);
        set_field(&mut judgment, "closure_cut", 13_u64);
        let judgment = finish_signed_carrier(judgment, QUARANTINE, signing_key);
        (
            StoreIntegrityQuarantineClosureRequestV1(request),
            StoreIntegrityQuarantineClosureJudgmentV1(judgment),
        )
    }

    #[test]
    fn bootstrap_schema_preserves_the_exact_raw_gen4_resident_bound() {
        let key = SigningKey::from_bytes(&[1_u8; 32])
            .verifying_key()
            .to_bytes();
        let mut value = sample_document(BOOTSTRAP_REQUEST, key);
        value["resident_identity"] = Value::String("resident/node-a".to_owned());
        assert!(validate_against_checked_schema(&value, BOOTSTRAP_REQUEST).is_ok());

        value["resident_identity"] = Value::String("resident\nnode-a".to_owned());
        assert!(validate_against_checked_schema(&value, BOOTSTRAP_REQUEST).is_err());
        value["resident_identity"] = Value::String("é".repeat(513));
        assert!(validate_against_checked_schema(&value, BOOTSTRAP_REQUEST).is_err());
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
    fn closed_ingress_has_no_generic_variant() {
        assert!(
            verify_sg_wu_06a_external_governance_ingress_set_is_closed(
                construct_sg_wu_06a_external_governance_ingress_set()
            )
            .is_ok()
        );
    }

    fn prepared_for_test(
        route: C2ExternalSigningRouteV1,
        marker: u8,
        canonical_carrier: &[u8],
    ) -> C2PreparedExternalIngressV1 {
        C2PreparedExternalIngressV1 {
            route,
            request_identity: ExternalCarrierIdentityV1([marker; 32]),
            carrier_identity: ExternalCarrierIdentityV1([marker.wrapping_add(80); 32]),
            canonical_request: format!("request-{marker}").into_bytes(),
            canonical_carrier: canonical_carrier.to_vec(),
        }
    }

    fn real_verified_ingresses_for_all_routes(
        signing_key: &SigningKey,
    ) -> Vec<C2PreparedExternalIngressV1> {
        let permit = ExternalCarrierVerificationPermitV1::for_test();
        let terminal = TerminalVerifier(signing_key.verifying_key().to_bytes());

        let (bootstrap_request, bootstrap_grant) =
            make_schema_pair(signing_key, BOOTSTRAP_REQUEST, BOOTSTRAP, 1);
        let bootstrap_request = StoreIntegrityBootstrapGrantRequestV1(bootstrap_request);
        let bootstrap_grant = StoreIntegrityBootstrapGrantV1(bootstrap_grant);
        let bootstrap =
            verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &bootstrap_grant,
                &bootstrap_request,
                &bootstrap_expectation_for_test(&bootstrap_request.0, &bootstrap_grant.0, 1),
                &terminal,
            )
            .unwrap();

        let (activation_request, activation_grant) =
            make_schema_pair(signing_key, ACTIVATION_REQUEST, ACTIVATION, 2);
        let activation_request =
            StoreIntegrityActivationSuccessorGrantRequestV1(activation_request);
        let activation_grant = StoreIntegrityActivationSuccessorGrantV1(activation_grant);
        let activation =
            verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &activation_grant,
                &activation_request,
                &transition_expectation_for_test(
                    &activation_request.0,
                    &activation_grant.0,
                    2,
                ),
                &terminal,
            )
            .unwrap();

        let (proposal_request, proposal_disposition) =
            make_schema_pair(signing_key, PROPOSAL_REQUEST, PROPOSAL, 3);
        let proposal_request = StoreIntegrityProposalDispositionRequestV1(proposal_request);
        let proposal_disposition = StoreIntegrityProposalDispositionV1(proposal_disposition);
        let proposal =
            verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &proposal_disposition,
                &proposal_request,
                &transition_expectation_for_test(&proposal_request.0, &proposal_disposition.0, 3),
                &terminal,
            )
            .unwrap();

        let (revocation_request, revocation_judgment) = make_revocation_pair(signing_key);
        let revocation =
            verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &revocation_judgment,
                &revocation_request,
                &expectation_for_test(
                    exact_fields_for_test(
                        &revocation_request.0,
                        &revocation_judgment.0,
                        REVOCATION_EFFECT_REQUIRED_FIELDS_V1,
                    ),
                    7,
                ),
                &terminal,
            )
            .unwrap();

        let (recovery_request, recovery_grant) =
            make_schema_pair(signing_key, RECOVERY_REQUEST, RECOVERY, 9);
        let recovery_request = StoreIntegrityRecoveryRequestV1(recovery_request);
        let recovery_grant = StoreIntegrityRecoveryGrantV1(recovery_grant);
        let recovery =
            verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity(
                &permit,
                &recovery_grant,
                &recovery_request,
                &transition_expectation_for_test(&recovery_request.0, &recovery_grant.0, 9),
                &terminal,
            )
            .unwrap();

        let (restore_request, restore_authorization) = make_restore_pair(signing_key);
        let restore =
            verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &restore_authorization,
                &restore_request,
                &transition_expectation_for_test(&restore_request.0, &restore_authorization.0, 11),
                &terminal,
            )
            .unwrap();
        let restore_identity = external_identity_text(restore_authorization.identity());

        let (closure_request, closure_judgment) =
            make_quarantine_pair(signing_key, &restore_identity);
        let closure =
            verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &closure_judgment,
                &closure_request,
                &expectation_for_test(
                    exact_fields_for_test(
                        &closure_request.0,
                        &closure_judgment.0,
                        QUARANTINE_EFFECT_REQUIRED_FIELDS_V1,
                    ),
                    13,
                ),
                &terminal,
            )
            .unwrap();

        vec![
            prepare_bootstrap_grant_ingress(&bootstrap),
            prepare_activation_successor_grant_ingress(&activation),
            prepare_proposal_disposition_ingress(&proposal),
            prepare_restore_authorization_ingress(&restore),
            prepare_revocation_judgment_ingress(&revocation),
            prepare_recovery_grant_ingress(&recovery),
            prepare_quarantine_closure_ingress(&closure),
        ]
    }

    #[test]
    fn all_seven_real_signed_routes_reject_cross_actor_snapshot_expectations() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let terminal = TerminalVerifier(signing_key.verifying_key().to_bytes());
        let permit = ExternalCarrierVerificationPermitV1::for_test();
        macro_rules! assert_substituted_snapshot_refuses {
            ($verify:ident, $carrier:expr, $request:expr, $expectation:expr) => {{
                let expectation = substitute_expectation_snapshot($expectation);
                assert!(matches!(
                    $verify(&permit, $carrier, $request, &expectation, &terminal),
                    Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
                ));
            }};
        }

        let (request, carrier) = make_schema_pair(&signing_key, BOOTSTRAP_REQUEST, BOOTSTRAP, 1);
        let request = StoreIntegrityBootstrapGrantRequestV1(request);
        let carrier = StoreIntegrityBootstrapGrantV1(carrier);
        assert_substituted_snapshot_refuses!(
            verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity,
            &carrier,
            &request,
            bootstrap_expectation_for_test(&request.0, &carrier.0, 1)
        );

        let (request, carrier) = make_schema_pair(&signing_key, ACTIVATION_REQUEST, ACTIVATION, 2);
        let request = StoreIntegrityActivationSuccessorGrantRequestV1(request);
        let carrier = StoreIntegrityActivationSuccessorGrantV1(carrier);
        assert_substituted_snapshot_refuses!(
            verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity,
            &carrier,
            &request,
            transition_expectation_for_test(&request.0, &carrier.0, 2)
        );

        let (request, carrier) = make_schema_pair(&signing_key, PROPOSAL_REQUEST, PROPOSAL, 3);
        let request = StoreIntegrityProposalDispositionRequestV1(request);
        let carrier = StoreIntegrityProposalDispositionV1(carrier);
        assert_substituted_snapshot_refuses!(
            verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity,
            &carrier,
            &request,
            transition_expectation_for_test(&request.0, &carrier.0, 3)
        );

        let (request, carrier) = make_revocation_pair(&signing_key);
        assert_substituted_snapshot_refuses!(
            verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity,
            &carrier,
            &request,
            expectation_for_test(
                exact_fields_for_test(&request.0, &carrier.0, REVOCATION_EFFECT_REQUIRED_FIELDS_V1,),
                7,
            )
        );

        let (request, carrier) = make_schema_pair(&signing_key, RECOVERY_REQUEST, RECOVERY, 9);
        let request = StoreIntegrityRecoveryRequestV1(request);
        let carrier = StoreIntegrityRecoveryGrantV1(carrier);
        assert_substituted_snapshot_refuses!(
            verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity,
            &carrier,
            &request,
            transition_expectation_for_test(&request.0, &carrier.0, 9)
        );

        let (restore_request, restore) = make_restore_pair(&signing_key);
        assert_substituted_snapshot_refuses!(
            verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity,
            &restore,
            &restore_request,
            transition_expectation_for_test(&restore_request.0, &restore.0, 11)
        );

        let restore_identity = external_identity_text(restore.identity());
        let (request, carrier) = make_quarantine_pair(&signing_key, &restore_identity);
        assert_substituted_snapshot_refuses!(
            verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity,
            &carrier,
            &request,
            expectation_for_test(
                exact_fields_for_test(&request.0, &carrier.0, QUARANTINE_EFFECT_REQUIRED_FIELDS_V1,),
                13,
            )
        );
    }

    #[test]
    fn permit_expectation_join_refuses_actor_snapshot_epoch_and_process_substitution() {
        let permit = ExternalCarrierVerificationPermitV1::for_test();
        let fresh = || expectation_for_test(BTreeMap::new(), 1);
        permit.verify_expectation_basis(&fresh()).unwrap();

        let mut wrong_actor = fresh();
        wrong_actor.actor_instance_identity =
            Sha256Digest::parse(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert_eq!(
            permit.verify_expectation_basis(&wrong_actor),
            Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
        );

        let mut wrong_snapshot = fresh();
        wrong_snapshot.actor_snapshot_identity =
            Sha256Digest::parse(format!("sha256:{}", "e".repeat(64))).unwrap();
        assert_eq!(
            permit.verify_expectation_basis(&wrong_snapshot),
            Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
        );

        let mut stale_epoch = fresh();
        stale_epoch.actor_effect_epoch += 1;
        assert_eq!(
            permit.verify_expectation_basis(&stale_epoch),
            Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
        );

        let mut prior_process = fresh();
        prior_process.creator_pid = prior_process.creator_pid.wrapping_add(1);
        assert_eq!(
            permit.verify_expectation_basis(&prior_process),
            Err(SignerRefusalV2::ExternalCarrierScopeMismatch)
        );
    }

    #[test]
    fn all_seven_real_signed_routes_have_durable_exact_replay_collision_no_write_and_no_authority_side_effects()
     {
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let ingresses = real_verified_ingresses_for_all_routes(&signing_key);
        assert_eq!(ingresses.len(), 7);
        assert_eq!(
            ingresses
                .iter()
                .map(|ingress| ingress.route)
                .collect::<Vec<_>>(),
            C2ExternalSigningRouteV1::ALL
        );

        let root = tempdir().unwrap();
        let path = root.path().join("store.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            connection.execute_batch(crate::SCHEMA).unwrap();
            let transaction = connection.transaction().unwrap();
            for ingress in ingresses {
                let route = ingress.route;
                let appended = append_prepared_external_ingress(&transaction, ingress).unwrap();
                assert_eq!(appended.route, route);
                assert_eq!(
                    appended.disposition,
                    DurableExternalIngressDispositionV1::Appended
                );
            }
            transaction.commit().unwrap();
        }

        let ingresses = real_verified_ingresses_for_all_routes(&signing_key);
        let mut reopened = Connection::open(&path).unwrap();
        let transaction = reopened.transaction().unwrap();
        for ingress in ingresses {
            let route = ingress.route;
            let request_identity = ingress.request_identity;
            let carrier_identity = ingress.carrier_identity;
            let canonical_request = ingress.canonical_request.clone();
            let canonical_carrier = ingress.canonical_carrier.clone();
            let exact_replay = append_prepared_external_ingress(&transaction, ingress).unwrap();
            assert_eq!(
                exact_replay.disposition,
                DurableExternalIngressDispositionV1::ExactReplay
            );
            match route {
                C2ExternalSigningRouteV1::Msg13RestoreAuthorization => {
                    verify_durable_restore_authorization_identity_v1(
                        &transaction,
                        &external_identity_text(carrier_identity),
                    )
                    .unwrap();
                }
                C2ExternalSigningRouteV1::Msg15RecoveryGrant => {
                    verify_durable_recovery_grant_identity_v1(
                        &transaction,
                        &external_identity_text(carrier_identity),
                    )
                    .unwrap();
                }
                _ => {}
            }

            let before = transaction
                .query_row(
                    "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap();
            let mut changed_carrier = canonical_carrier.clone();
            changed_carrier.push(b' ');
            assert!(matches!(
                append_prepared_external_ingress(
                    &transaction,
                    C2PreparedExternalIngressV1 {
                        route,
                        request_identity,
                        carrier_identity,
                        canonical_request: canonical_request.clone(),
                        canonical_carrier: changed_carrier,
                    },
                ),
                Err(C2ExternalIngressRefusalV1::ChangedContentCollision)
            ));
            let after = transaction
                .query_row(
                    "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap();
            assert_eq!(before, after, "{route:?} collision wrote ingress state");

            let mut changed_request = canonical_request;
            changed_request.push(b' ');
            assert!(matches!(
                append_prepared_external_ingress(
                    &transaction,
                    C2PreparedExternalIngressV1 {
                        route,
                        request_identity,
                        carrier_identity,
                        canonical_request: changed_request,
                        canonical_carrier: canonical_carrier.clone(),
                    },
                ),
                Err(C2ExternalIngressRefusalV1::ChangedContentCollision)
            ));
            let after_request_collision = transaction
                .query_row(
                    "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap();
            assert_eq!(
                before, after_request_collision,
                "{route:?} request collision wrote ingress state"
            );
        }

        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                    [],
                    |row| { row.get::<_, u64>(0) }
                )
                .unwrap(),
            7
        );
        for table in [
            "c2_foundational_enrollment_adoptions",
            "c2_signer_enrollment_acceptances",
            "c2_signer_current_binding_projection",
            "c2_revocation_effects",
            "c2_quarantine_closure_effects",
        ] {
            let count = transaction
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap();
            assert_eq!(count, 0, "governed ingress unexpectedly mutated {table}");
        }
    }

    #[test]
    fn durable_ingress_exact_replay_survives_database_reopen_and_collision_is_no_write() {
        let root = tempdir().unwrap();
        let path = root.path().join("store.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            connection.execute_batch(crate::SCHEMA).unwrap();
            let transaction = connection.transaction().unwrap();
            let receipt = append_prepared_external_ingress(
                &transaction,
                prepared_for_test(
                    C2ExternalSigningRouteV1::Msg01BootstrapGrant,
                    1,
                    br#"{"carrier":"exact-a"}"#,
                ),
            )
            .unwrap();
            assert_eq!(
                receipt.disposition,
                DurableExternalIngressDispositionV1::Appended
            );
            transaction.commit().unwrap();
        }

        let mut reopened = Connection::open(&path).unwrap();
        let transaction = reopened.transaction().unwrap();
        let replay = append_prepared_external_ingress(
            &transaction,
            prepared_for_test(
                C2ExternalSigningRouteV1::Msg01BootstrapGrant,
                1,
                br#"{"carrier":"exact-a"}"#,
            ),
        )
        .unwrap();
        assert_eq!(
            replay.disposition,
            DurableExternalIngressDispositionV1::ExactReplay
        );
        let before = transaction
            .query_row(
                "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap();
        assert!(matches!(
            append_prepared_external_ingress(
                &transaction,
                prepared_for_test(
                    C2ExternalSigningRouteV1::Msg01BootstrapGrant,
                    1,
                    br#"{"carrier":"changed"}"#,
                ),
            ),
            Err(C2ExternalIngressRefusalV1::ChangedContentCollision)
        ));
        let after = transaction
            .query_row(
                "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn durable_ingress_registry_census_is_sql_enforced_for_all_seven_routes() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        for (index, route) in C2ExternalSigningRouteV1::ALL.iter().copied().enumerate() {
            let receipt = append_prepared_external_ingress(
                &transaction,
                prepared_for_test(route, (index + 1) as u8, route.as_str().as_bytes()),
            )
            .unwrap();
            assert_eq!(receipt.route, route);
            assert_eq!(
                receipt.disposition,
                DurableExternalIngressDispositionV1::Appended
            );
        }
        let count = transaction
            .query_row(
                "SELECT COUNT(*) FROM c2_external_carrier_ingress",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap();
        assert_eq!(count, 7);
    }

    #[test]
    fn msg14_revocation_effect_is_durable_replayable_and_resolver_visible() {
        let root = tempdir().unwrap();
        let path = root.path().join("store.sqlite");
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let (request, judgment) = make_revocation_pair(&signing_key);
        let permit = ExternalCarrierVerificationPermitV1::for_test();
        let exact_expectation = expectation_for_test(
            exact_fields_for_test(
                &request.0,
                &judgment.0,
                REVOCATION_EFFECT_REQUIRED_FIELDS_V1,
            ),
            7,
        );
        verify_pair_content_correspondence(&judgment.0, REVOCATION, &request.0, REVOCATION_REQUEST)
            .expect("revocation test pair content");
        verify_expectation(&judgment.0, &request.0, &exact_expectation)
            .expect("revocation test expectation");
        verify_signature_claim(&judgment.0, REVOCATION).expect("revocation test signature");
        let verified =
            verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &judgment,
                &request,
                &exact_expectation,
                &TerminalVerifier(signing_key.verifying_key().to_bytes()),
            )
            .unwrap();
        let facts = derive_revocation_effect_facts_v1(&request.0, &judgment.0).unwrap();

        {
            let mut connection = Connection::open(&path).unwrap();
            connection.execute_batch(crate::SCHEMA).unwrap();
            let transaction = connection.transaction().unwrap();
            let ingress = append_prepared_external_ingress(
                &transaction,
                prepare_revocation_judgment_ingress(&verified),
            )
            .unwrap();
            let effect = apply_verified_revocation_effect_in_transaction_v1(
                &transaction,
                &verified,
                &ingress,
                expectation_for_test(
                    exact_fields_for_test(
                        &request.0,
                        &judgment.0,
                        REVOCATION_EFFECT_REQUIRED_FIELDS_V1,
                    ),
                    7,
                ),
            )
            .unwrap();
            assert_eq!(
                effect.disposition(),
                DurableGovernedEffectDispositionV1::Appended
            );
            assert!(!effect.receipt().canonical_bytes().is_empty());
            transaction.commit().unwrap();
        }

        let mut reopened = Connection::open(&path).unwrap();
        let transaction = reopened.transaction().unwrap();
        let replay_ingress = append_prepared_external_ingress(
            &transaction,
            prepare_revocation_judgment_ingress(&verified),
        )
        .unwrap();
        assert_eq!(
            replay_ingress.disposition,
            DurableExternalIngressDispositionV1::ExactReplay
        );
        let replay = apply_verified_revocation_effect_in_transaction_v1(
            &transaction,
            &verified,
            &replay_ingress,
            expectation_for_test(
                exact_fields_for_test(
                    &request.0,
                    &judgment.0,
                    REVOCATION_EFFECT_REQUIRED_FIELDS_V1,
                ),
                7,
            ),
        )
        .unwrap();
        assert_eq!(
            replay.disposition(),
            DurableGovernedEffectDispositionV1::ExactReplay
        );
        assert!(matches!(
            refuse_if_current_signer_revoked_v1(
                &transaction,
                &facts.physical_generation_identity,
                &facts.lifecycle_root_identity,
                &facts.scope_identity,
                &facts.target_enrollment_identity,
                &facts.target_public_key,
                facts.target_key_generation,
                &facts.target_standing_identity,
            ),
            Err(C2ExternalIngressRefusalV1::CurrentSignerRevoked)
        ));
        let unrelated_standing = format!("sha256:{}", "4".repeat(64));
        refuse_if_current_signer_revoked_v1(
            &transaction,
            &facts.physical_generation_identity,
            &facts.lifecycle_root_identity,
            &facts.scope_identity,
            &facts.target_enrollment_identity,
            &facts.target_public_key,
            facts.target_key_generation,
            &unrelated_standing,
        )
        .unwrap();
    }

    #[test]
    fn msg14_stale_store_projection_refuses_without_effect_write() {
        let signing_key = SigningKey::from_bytes(&[10_u8; 32]);
        let (request, judgment) = make_revocation_pair(&signing_key);
        let permit = ExternalCarrierVerificationPermitV1::for_test();
        let exact_fields = exact_fields_for_test(
            &request.0,
            &judgment.0,
            REVOCATION_EFFECT_REQUIRED_FIELDS_V1,
        );
        let verified =
            verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &judgment,
                &request,
                &expectation_for_test(exact_fields.clone(), 7),
                &TerminalVerifier(signing_key.verifying_key().to_bytes()),
            )
            .unwrap();
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let ingress = append_prepared_external_ingress(
            &transaction,
            prepare_revocation_judgment_ingress(&verified),
        )
        .unwrap();
        let mut stale_fields = exact_fields;
        stale_fields.insert(
            "scope_identity".to_owned(),
            Value::String(format!("sha256:{}", "5".repeat(64))),
        );
        assert!(matches!(
            apply_verified_revocation_effect_in_transaction_v1(
                &transaction,
                &verified,
                &ingress,
                expectation_for_test(stale_fields, 7),
            ),
            Err(C2ExternalIngressRefusalV1::EffectPreconditionMismatch)
        ));
        assert_eq!(
            transaction
                .query_row("SELECT COUNT(*) FROM c2_revocation_effects", [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn msg16_requires_exact_msg13_and_closure_survives_database_reopen() {
        let root = tempdir().unwrap();
        let path = root.path().join("store.sqlite");
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let terminal = TerminalVerifier(signing_key.verifying_key().to_bytes());
        let permit = ExternalCarrierVerificationPermitV1::for_test();
        let (restore_request, restore_authorization) = make_restore_pair(&signing_key);
        let restore_verified =
            verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &restore_authorization,
                &restore_request,
                &transition_expectation_for_test(&restore_request.0, &restore_authorization.0, 11),
                &terminal,
            )
            .unwrap();
        let restore_identity = external_identity_text(restore_authorization.identity());
        let (closure_request, closure_judgment) =
            make_quarantine_pair(&signing_key, &restore_identity);
        let closure_fields = exact_fields_for_test(
            &closure_request.0,
            &closure_judgment.0,
            QUARANTINE_EFFECT_REQUIRED_FIELDS_V1,
        );
        let closure_verified =
            verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                &closure_judgment,
                &closure_request,
                &expectation_for_test(closure_fields.clone(), 13),
                &terminal,
            )
            .unwrap();
        let facts =
            derive_quarantine_closure_effect_facts_v1(&closure_request.0, &closure_judgment.0)
                .unwrap();

        {
            let mut connection = Connection::open(&path).unwrap();
            connection.execute_batch(crate::SCHEMA).unwrap();
            let transaction = connection.transaction().unwrap();
            assert!(matches!(
                verify_restore_quarantine_closed_v1(
                    &transaction,
                    Some(&restore_identity),
                    &facts.physical_generation_identity,
                    &facts.lifecycle_root_identity,
                    &facts.scope_identity,
                    &facts.installation_receipt_identity,
                    &facts.current_enrollment_identity,
                    &facts.current_public_key,
                    facts.current_key_generation,
                    &facts.current_standing_identity,
                ),
                Err(C2ExternalIngressRefusalV1::DurableEvidenceMalformed)
            ));
            append_prepared_external_ingress(
                &transaction,
                prepare_restore_authorization_ingress(&restore_verified),
            )
            .unwrap();
            assert!(matches!(
                verify_restore_quarantine_closed_v1(
                    &transaction,
                    Some(&restore_identity),
                    &facts.physical_generation_identity,
                    &facts.lifecycle_root_identity,
                    &facts.scope_identity,
                    &facts.installation_receipt_identity,
                    &facts.current_enrollment_identity,
                    &facts.current_public_key,
                    facts.current_key_generation,
                    &facts.current_standing_identity,
                ),
                Err(C2ExternalIngressRefusalV1::RestoreQuarantineOpen)
            ));
            let closure_ingress = append_prepared_external_ingress(
                &transaction,
                prepare_quarantine_closure_ingress(&closure_verified),
            )
            .unwrap();
            let closure = apply_verified_quarantine_closure_effect_in_transaction_v1(
                &transaction,
                &closure_verified,
                &closure_ingress,
                expectation_for_test(closure_fields.clone(), 13),
            )
            .unwrap();
            assert_eq!(
                closure.disposition(),
                DurableGovernedEffectDispositionV1::Appended
            );
            assert!(!closure.receipt().canonical_bytes().is_empty());
            transaction.commit().unwrap();
        }

        let mut reopened = Connection::open(&path).unwrap();
        let transaction = reopened.transaction().unwrap();
        verify_restore_quarantine_closed_v1(
            &transaction,
            Some(&restore_identity),
            &facts.physical_generation_identity,
            &facts.lifecycle_root_identity,
            &facts.scope_identity,
            &facts.installation_receipt_identity,
            &facts.current_enrollment_identity,
            &facts.current_public_key,
            facts.current_key_generation,
            &facts.current_standing_identity,
        )
        .unwrap();
        let wrong_generation = format!("sha256:{}", "6".repeat(64));
        assert!(matches!(
            verify_restore_quarantine_closed_v1(
                &transaction,
                Some(&restore_identity),
                &wrong_generation,
                &facts.lifecycle_root_identity,
                &facts.scope_identity,
                &facts.installation_receipt_identity,
                &facts.current_enrollment_identity,
                &facts.current_public_key,
                facts.current_key_generation,
                &facts.current_standing_identity,
            ),
            Err(C2ExternalIngressRefusalV1::RestoreQuarantineOpen)
        ));
        let replay_ingress = append_prepared_external_ingress(
            &transaction,
            prepare_quarantine_closure_ingress(&closure_verified),
        )
        .unwrap();
        let replay = apply_verified_quarantine_closure_effect_in_transaction_v1(
            &transaction,
            &closure_verified,
            &replay_ingress,
            expectation_for_test(closure_fields, 13),
        )
        .unwrap();
        assert_eq!(
            replay.disposition(),
            DurableGovernedEffectDispositionV1::ExactReplay
        );
    }
}
