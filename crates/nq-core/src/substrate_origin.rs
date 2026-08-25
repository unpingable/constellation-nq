//! Proof-bearing substrate-origin prerequisites for one provider acquisition.
//!
//! The carrier is provider-neutral, while each closed origin profile gives its
//! coordinate a narrower proof meaning. Every profile pins the helper issuer
//! and Ed25519 key that authenticates the pre-provider report. The software-key
//! profile proves possession of that key only. The Linode metadata profile
//! additionally binds one logical provider-instance coordinate, subject to its
//! separately qualified locality and routing assumptions. Neither profile is
//! inferred to prove physical hardware or installation identity.

#![allow(missing_docs, clippy::missing_errors_doc)]

use chrono::DateTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nq_protocol::{HelperRequest, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::continuity::{ContinuityAcquisitionBasisV1, ContinuityAcquisitionCarrierV1};
use crate::provider_intake::ProviderIdentityV1;

pub const COORDINATE_SCHEMA_V1: &str = "nq.substrate_coordinate.v1";
pub const ORIGIN_BASIS_SCHEMA_V1: &str = "nq.substrate_origin_acquisition_basis.v1";
pub const ATTESTATION_SCHEMA_V1: &str = "nq.substrate_origin_attestation.v1";
pub const SIGNED_ATTESTATION_SCHEMA_V1: &str = "nq.signed_substrate_origin_attestation.v1";
pub const ORIGIN_INTENT_SCHEMA_V1: &str = "nq.substrate_origin_acquisition_intent.v1";

const ATTESTATION_NONCLAIMS: [&str; 5] = [
    "origin attestation proves possession of the pinned attester key for this exact acquisition basis",
    "origin attestation does not establish bare-metal physical identity",
    "origin attestation does not establish subject continuity or predecessor history",
    "origin attestation does not establish evidence truth, currentness, standing, or authority",
    "attester key custody and runtime co-location remain deployment qualifications",
];

pub const LINODE_INSTANCE_METADATA_PROFILE_V1: &str = "linode_instance_metadata_v1";
pub const LINODE_METADATA_NAMESPACE_V1: &str = "akamai_linode";
pub const LINODE_METADATA_INSTANCE_ENDPOINT_V1: &str = "http://169.254.169.254/v1/instance";
pub const LINODE_METADATA_EVIDENCE_SCHEMA_V1: &str = "nq.linode_instance_metadata_evidence.v1";
const MAX_LINODE_METADATA_BYTES: usize = 16 * 1024;
const LINODE_METADATA_NONCLAIMS: [&str; 6] = [
    "origin attestation proves the pinned helper reported an exact response under the closed Linode metadata profile for this acquisition basis",
    "Linode metadata is instance-local but is not a provider-signed portable identity document",
    "the qualified coordinate identifies one logical Linode instance, not physical host placement",
    "host UUID is supplemental evidence and is not part of the qualified coordinate",
    "origin attestation does not establish installation identity, evidence truth, currentness, standing, or authority",
    "helper isolation, metadata routing, and runtime co-location remain deployment qualifications",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateCoordinateKindV1 {
    /// One runtime incarnation identified by a pinned attestation key.
    AttesterKey,
    /// One logical Akamai/Linode instance reported by the instance-local
    /// metadata service. This is not a physical-host coordinate.
    LinodeInstance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateOriginEvidenceMethodV1 {
    Ed25519AcquisitionChallenge,
    LinodeInstanceMetadataV1,
}

/// Typed content-addressed coordinate whose meaning is bounded by its closed
/// origin profile. DNS, IP, hostname, boot ID, and provider output are absent
/// by construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateCoordinateV1 {
    pub schema: String,
    pub kind: SubstrateCoordinateKindV1,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester_public_key_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linode_instance_id_sha256: Option<Sha256Digest>,
    pub evidence_method: SubstrateOriginEvidenceMethodV1,
    pub coordinate_ref: String,
}

impl SubstrateCoordinateV1 {
    pub fn for_attester_key(
        namespace: String,
        attester_key_id: String,
        key: &VerifyingKey,
    ) -> Result<Self, SubstrateOriginError> {
        require_token("coordinate namespace", &namespace)?;
        require_token("attester key id", &attester_key_id)?;
        let public_key_digest = nq_protocol::sha256_bytes(key.as_bytes());
        let mut coordinate = Self {
            schema: COORDINATE_SCHEMA_V1.into(),
            kind: SubstrateCoordinateKindV1::AttesterKey,
            namespace,
            attester_key_id: Some(attester_key_id),
            attester_public_key_sha256: Some(public_key_digest),
            linode_instance_id_sha256: None,
            evidence_method: SubstrateOriginEvidenceMethodV1::Ed25519AcquisitionChallenge,
            coordinate_ref: String::new(),
        };
        coordinate.coordinate_ref = coordinate.computed_ref()?;
        coordinate.validate()?;
        Ok(coordinate)
    }

    pub fn for_linode_instance_digest(
        instance_id_sha256: Sha256Digest,
    ) -> Result<Self, SubstrateOriginError> {
        let mut coordinate = Self {
            schema: COORDINATE_SCHEMA_V1.into(),
            kind: SubstrateCoordinateKindV1::LinodeInstance,
            namespace: LINODE_METADATA_NAMESPACE_V1.into(),
            attester_key_id: None,
            attester_public_key_sha256: None,
            linode_instance_id_sha256: Some(instance_id_sha256),
            evidence_method: SubstrateOriginEvidenceMethodV1::LinodeInstanceMetadataV1,
            coordinate_ref: String::new(),
        };
        coordinate.coordinate_ref = coordinate.computed_ref()?;
        coordinate.validate()?;
        Ok(coordinate)
    }

    pub fn computed_ref(&self) -> Result<String, SubstrateOriginError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| SubstrateOriginError::Malformed("coordinate is not an object".into()))?
            .remove("coordinate_ref");
        let bytes = nq_protocol::canonical_json_bytes(&value)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        let prefix = match self.kind {
            SubstrateCoordinateKindV1::AttesterKey => "substrate:attester-key:v1",
            SubstrateCoordinateKindV1::LinodeInstance => "substrate:linode-instance:v1",
        };
        Ok(format!("{prefix}:{}", hex_digest(&bytes)))
    }

    pub fn validate(&self) -> Result<(), SubstrateOriginError> {
        if self.schema != COORDINATE_SCHEMA_V1 {
            return Err(SubstrateOriginError::Substitution("coordinate schema"));
        }
        require_token("coordinate namespace", &self.namespace)?;
        match self.kind {
            SubstrateCoordinateKindV1::AttesterKey => {
                if self.evidence_method
                    != SubstrateOriginEvidenceMethodV1::Ed25519AcquisitionChallenge
                    || self.linode_instance_id_sha256.is_some()
                {
                    return Err(SubstrateOriginError::Substitution("coordinate profile"));
                }
                require_token(
                    "attester key id",
                    self.attester_key_id
                        .as_deref()
                        .ok_or(SubstrateOriginError::Substitution(
                            "attester coordinate fields",
                        ))?,
                )?;
                if self.attester_public_key_sha256.is_none() {
                    return Err(SubstrateOriginError::Substitution(
                        "attester coordinate fields",
                    ));
                }
            }
            SubstrateCoordinateKindV1::LinodeInstance => {
                if self.namespace != LINODE_METADATA_NAMESPACE_V1
                    || self.evidence_method
                        != SubstrateOriginEvidenceMethodV1::LinodeInstanceMetadataV1
                    || self.attester_key_id.is_some()
                    || self.attester_public_key_sha256.is_some()
                    || self.linode_instance_id_sha256.is_none()
                {
                    return Err(SubstrateOriginError::Substitution("coordinate profile"));
                }
            }
        }
        if self.coordinate_ref != self.computed_ref()? {
            return Err(SubstrateOriginError::Substitution("coordinate identity"));
        }
        Ok(())
    }
}

/// Exact, signed helper report about one bounded Linode metadata response.
/// The response digest and host UUID are retained as supplemental provenance;
/// only the logical instance-ID digest participates in the coordinate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinodeInstanceMetadataEvidenceV1 {
    pub schema: String,
    pub profile_id: String,
    pub endpoint: String,
    pub instance_id_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_uuid_sha256: Option<Sha256Digest>,
    pub canonical_response_sha256: Sha256Digest,
}

impl LinodeInstanceMetadataEvidenceV1 {
    pub fn from_response(bytes: &[u8]) -> Result<Self, SubstrateOriginError> {
        if bytes.is_empty() || bytes.len() > MAX_LINODE_METADATA_BYTES {
            return Err(SubstrateOriginError::Malformed(
                "Linode metadata response is empty or oversized".into(),
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
            SubstrateOriginError::Malformed(format!("Linode metadata is not JSON: {error}"))
        })?;
        let object = value.as_object().ok_or_else(|| {
            SubstrateOriginError::Malformed("Linode metadata is not an object".into())
        })?;
        let instance_id = object
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                SubstrateOriginError::Malformed(
                    "Linode metadata lacks a positive integer id".into(),
                )
            })?;
        let host_uuid_sha256 = object
            .get("host_uuid")
            .map(|value| {
                let value = value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        SubstrateOriginError::Malformed(
                            "Linode host_uuid is not a non-empty string".into(),
                        )
                    })?;
                Ok(nq_protocol::sha256_bytes(value.as_bytes()))
            })
            .transpose()?;
        let canonical = nq_protocol::canonical_json_bytes(&value)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        Ok(Self {
            schema: LINODE_METADATA_EVIDENCE_SCHEMA_V1.into(),
            profile_id: LINODE_INSTANCE_METADATA_PROFILE_V1.into(),
            endpoint: LINODE_METADATA_INSTANCE_ENDPOINT_V1.into(),
            instance_id_sha256: nq_protocol::sha256_bytes(instance_id.to_string().as_bytes()),
            host_uuid_sha256,
            canonical_response_sha256: nq_protocol::sha256_bytes(&canonical),
        })
    }

    pub fn validate(&self) -> Result<(), SubstrateOriginError> {
        if self.schema != LINODE_METADATA_EVIDENCE_SCHEMA_V1
            || self.profile_id != LINODE_INSTANCE_METADATA_PROFILE_V1
            || self.endpoint != LINODE_METADATA_INSTANCE_ENDPOINT_V1
        {
            return Err(SubstrateOriginError::Substitution(
                "Linode metadata profile",
            ));
        }
        Ok(())
    }

    pub fn coordinate(&self) -> Result<SubstrateCoordinateV1, SubstrateOriginError> {
        self.validate()?;
        SubstrateCoordinateV1::for_linode_instance_digest(self.instance_id_sha256.clone())
    }
}

/// Static challenge basis presented to the independent origin attester before
/// the observed provider is invoked.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAcquisitionBasisV1 {
    pub schema: String,
    pub acquisition_id: String,
    pub watcher_instance_id: String,
    pub watcher_config_digest: String,
    pub subject_ref: String,
    pub expected_coordinate: SubstrateCoordinateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<ContinuityAcquisitionBasisV1>,
}

impl SubstrateOriginAcquisitionBasisV1 {
    pub fn digest(&self) -> Result<String, SubstrateOriginError> {
        self.validate()?;
        let bytes = nq_protocol::canonical_json_bytes(self)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        Ok(hex_digest(&bytes))
    }

    pub fn validate(&self) -> Result<(), SubstrateOriginError> {
        if self.schema != ORIGIN_BASIS_SCHEMA_V1 {
            return Err(SubstrateOriginError::Substitution("origin basis schema"));
        }
        require_token("acquisition id", &self.acquisition_id)?;
        require_token("watcher instance", &self.watcher_instance_id)?;
        require_token("subject ref", &self.subject_ref)?;
        require_hex_digest("watcher config digest", &self.watcher_config_digest)?;
        self.expected_coordinate.validate()?;
        if let Some(continuity) = &self.continuity
            && (continuity.acquisition_id != self.acquisition_id
                || continuity.watcher_instance_id != self.watcher_instance_id
                || continuity.watcher_config_digest != self.watcher_config_digest
                || continuity.edge.subject_ref != self.subject_ref
                || continuity.edge.successor_ref != self.expected_coordinate.coordinate_ref)
        {
            return Err(SubstrateOriginError::Substitution(
                "continuity/origin acquisition basis",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAttestationV1 {
    pub schema: String,
    pub attestation_occurrence_ref: String,
    pub issuer_id: String,
    pub key_id: String,
    pub acquisition_id: String,
    pub acquisition_basis_digest: String,
    pub coordinate: SubstrateCoordinateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linode_metadata: Option<LinodeInstanceMetadataEvidenceV1>,
    /// Evidence only; never the causal or origin proof.
    pub attested_at: String,
    pub replay_identity: String,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSubstrateOriginAttestationV1 {
    pub schema: String,
    pub payload: SubstrateOriginAttestationV1,
    pub payload_digest: String,
    pub signature: String,
}

/// Source invoked by NQ after it has fixed the exact acquisition basis and
/// before it dispatches the observed provider. Production implementations must
/// separately qualify key custody and co-location; tests use a deterministic
/// synthetic implementation.
pub trait SubstrateOriginAttestationSourceV1 {
    fn attest(
        &mut self,
        basis: &SubstrateOriginAcquisitionBasisV1,
    ) -> Result<SignedSubstrateOriginAttestationV1, String>;
}

#[derive(Clone, Debug)]
pub struct SubstrateOriginVerifierV1 {
    expected_issuer_id: String,
    expected_key_id: String,
    expected_coordinate: SubstrateCoordinateV1,
    verifying_key: VerifyingKey,
}

impl SubstrateOriginVerifierV1 {
    pub fn new(
        expected_issuer_id: String,
        expected_key_id: String,
        expected_namespace: String,
        verifying_key: VerifyingKey,
    ) -> Result<Self, SubstrateOriginError> {
        require_token("origin issuer", &expected_issuer_id)?;
        require_token("origin key id", &expected_key_id)?;
        require_token("origin namespace", &expected_namespace)?;
        let expected_coordinate = SubstrateCoordinateV1::for_attester_key(
            expected_namespace,
            expected_key_id.clone(),
            &verifying_key,
        )?;
        Ok(Self {
            expected_issuer_id,
            expected_key_id,
            expected_coordinate,
            verifying_key,
        })
    }

    pub fn for_linode_instance_metadata(
        expected_issuer_id: String,
        expected_key_id: String,
        expected_instance_id_sha256: Sha256Digest,
        verifying_key: VerifyingKey,
    ) -> Result<Self, SubstrateOriginError> {
        require_token("origin issuer", &expected_issuer_id)?;
        require_token("origin key id", &expected_key_id)?;
        Ok(Self {
            expected_issuer_id,
            expected_key_id,
            expected_coordinate: SubstrateCoordinateV1::for_linode_instance_digest(
                expected_instance_id_sha256,
            )?,
            verifying_key,
        })
    }

    pub fn expected_coordinate(&self) -> Result<SubstrateCoordinateV1, SubstrateOriginError> {
        Ok(self.expected_coordinate.clone())
    }

    pub fn verify(
        &self,
        basis: &SubstrateOriginAcquisitionBasisV1,
        signed: &SignedSubstrateOriginAttestationV1,
    ) -> Result<VerifiedSubstrateOriginV1, SubstrateOriginError> {
        basis.validate()?;
        if signed.schema != SIGNED_ATTESTATION_SCHEMA_V1
            || signed.payload.schema != ATTESTATION_SCHEMA_V1
        {
            return Err(SubstrateOriginError::Substitution("attestation schema"));
        }
        if signed.payload.issuer_id != self.expected_issuer_id
            || signed.payload.key_id != self.expected_key_id
            || signed.payload.coordinate != self.expected_coordinate()?
            || signed.payload.coordinate != basis.expected_coordinate
            || signed.payload.acquisition_id != basis.acquisition_id
            || signed.payload.acquisition_basis_digest != basis.digest()?
            || signed.payload.nonclaims != expected_nonclaims(&signed.payload.coordinate)
            || !profile_evidence_matches(&signed.payload)?
        {
            return Err(SubstrateOriginError::Substitution("attestation binding"));
        }
        require_token(
            "attestation occurrence",
            &signed.payload.attestation_occurrence_ref,
        )?;
        require_token(
            "attestation replay identity",
            &signed.payload.replay_identity,
        )?;
        require_hex_digest("attestation payload digest", &signed.payload_digest)?;
        if DateTime::parse_from_rfc3339(&signed.payload.attested_at).is_err() {
            return Err(SubstrateOriginError::Malformed(
                "attested_at is not RFC3339 evidence time".into(),
            ));
        }
        let payload_bytes = nq_protocol::canonical_json_bytes(&signed.payload)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        if hex_digest(&payload_bytes) != signed.payload_digest {
            return Err(SubstrateOriginError::Substitution(
                "attestation payload digest",
            ));
        }
        let signature_bytes: [u8; 64] = hex::decode(&signed.signature)
            .map_err(|_| SubstrateOriginError::Malformed("signature is not hex".into()))?
            .try_into()
            .map_err(|_| SubstrateOriginError::Malformed("signature is not 64 bytes".into()))?;
        let mut preimage =
            Vec::with_capacity(SIGNED_ATTESTATION_SCHEMA_V1.len() + 1 + payload_bytes.len());
        preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&payload_bytes);
        self.verifying_key
            .verify(&preimage, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| SubstrateOriginError::Signature)?;
        Ok(VerifiedSubstrateOriginV1 {
            basis: basis.clone(),
            basis_digest: basis.digest()?,
            attestation: signed.clone(),
        })
    }
}

fn expected_nonclaims(coordinate: &SubstrateCoordinateV1) -> Vec<String> {
    match coordinate.kind {
        SubstrateCoordinateKindV1::AttesterKey => ATTESTATION_NONCLAIMS.map(str::to_owned).to_vec(),
        SubstrateCoordinateKindV1::LinodeInstance => {
            LINODE_METADATA_NONCLAIMS.map(str::to_owned).to_vec()
        }
    }
}

fn profile_evidence_matches(
    payload: &SubstrateOriginAttestationV1,
) -> Result<bool, SubstrateOriginError> {
    match payload.coordinate.kind {
        SubstrateCoordinateKindV1::AttesterKey => Ok(payload.linode_metadata.is_none()),
        SubstrateCoordinateKindV1::LinodeInstance => {
            let Some(evidence) = &payload.linode_metadata else {
                return Ok(false);
            };
            evidence.validate()?;
            Ok(evidence.coordinate()? == payload.coordinate)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSubstrateOriginV1 {
    pub basis: SubstrateOriginAcquisitionBasisV1,
    pub basis_digest: String,
    pub attestation: SignedSubstrateOriginAttestationV1,
}

/// Immutable NQ intent persisted before the observed provider starts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAcquisitionIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub basis: SubstrateOriginAcquisitionBasisV1,
    pub basis_digest: String,
    pub attestation: SignedSubstrateOriginAttestationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_carrier: Option<ContinuityAcquisitionCarrierV1>,
    pub intake_id: String,
    pub attempt_id: String,
    pub run_id: String,
    pub request: HelperRequest,
    pub provider: ProviderIdentityV1,
    pub origin_carrier: String,
    pub checkpoint_contract_digest: String,
}

impl SubstrateOriginAcquisitionIntentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verified: &VerifiedSubstrateOriginV1,
        continuity_carrier: Option<ContinuityAcquisitionCarrierV1>,
        attempt_id: String,
        run_id: String,
        request: HelperRequest,
        provider: ProviderIdentityV1,
        origin_carrier: String,
        checkpoint_contract_digest: String,
    ) -> Result<Self, SubstrateOriginError> {
        let mut value = Self {
            schema: ORIGIN_INTENT_SCHEMA_V1.into(),
            intent_id: String::new(),
            basis: verified.basis.clone(),
            basis_digest: verified.basis_digest.clone(),
            attestation: verified.attestation.clone(),
            continuity_carrier,
            intake_id: verified.basis.acquisition_id.clone(),
            attempt_id,
            run_id,
            request,
            provider,
            origin_carrier,
            checkpoint_contract_digest,
        };
        value.intent_id = value.computed_id()?;
        value.validate()?;
        Ok(value)
    }

    pub fn computed_id(&self) -> Result<String, SubstrateOriginError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                SubstrateOriginError::Malformed("origin intent is not an object".into())
            })?
            .remove("intent_id");
        let bytes = nq_protocol::canonical_json_bytes(&value)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        Ok(format!("sha256:{}", hex_digest(&bytes)))
    }

    pub fn canonical_digest(&self) -> Result<String, SubstrateOriginError> {
        let bytes = nq_protocol::canonical_json_bytes(self)
            .map_err(|error| SubstrateOriginError::Malformed(error.to_string()))?;
        Ok(format!("sha256:{}", hex_digest(&bytes)))
    }

    pub fn validate(&self) -> Result<(), SubstrateOriginError> {
        if self.schema != ORIGIN_INTENT_SCHEMA_V1 {
            return Err(SubstrateOriginError::Substitution("origin intent schema"));
        }
        self.basis.validate()?;
        if self.basis.digest()? != self.basis_digest
            || self.intake_id != self.basis.acquisition_id
            || self.attestation.payload.acquisition_id != self.intake_id
            || self.attestation.payload.acquisition_basis_digest != self.basis_digest
            || self.request.instance_id.as_str() != self.basis.watcher_instance_id
            || self.request.binding.subject.as_str() != self.basis.subject_ref
        {
            return Err(SubstrateOriginError::Substitution("origin intent binding"));
        }
        match (&self.basis.continuity, &self.continuity_carrier) {
            (None, None) => {}
            (Some(basis), Some(carrier))
                if carrier.authority.payload.authority_occurrence_ref
                    == basis.authority_occurrence_ref
                    && carrier.authority.payload_digest == basis.authority_digest
                    && carrier.commitment.payload.acquisition_id == self.intake_id => {}
            _ => {
                return Err(SubstrateOriginError::Substitution(
                    "origin intent continuity carrier",
                ));
            }
        }
        for (name, token) in [
            ("intent id", self.intent_id.as_str()),
            ("intake id", self.intake_id.as_str()),
            ("attempt id", self.attempt_id.as_str()),
            ("run id", self.run_id.as_str()),
            ("origin carrier", self.origin_carrier.as_str()),
        ] {
            require_token(name, token)?;
        }
        if self.intent_id != self.computed_id()? {
            return Err(SubstrateOriginError::Substitution("origin intent identity"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SubstrateOriginError {
    #[error("substrate origin object is malformed: {0}")]
    Malformed(String),
    #[error("substrate origin signature is invalid")]
    Signature,
    #[error("substrate origin substitutes {0}")]
    Substitution(&'static str),
}

fn require_token(name: &str, value: &str) -> Result<(), SubstrateOriginError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        return Err(SubstrateOriginError::Malformed(format!(
            "{name} must be a bounded non-whitespace token"
        )));
    }
    Ok(())
}

fn require_hex_digest(name: &str, value: &str) -> Result<(), SubstrateOriginError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SubstrateOriginError::Malformed(format!(
            "{name} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) mod test_support {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    pub(crate) struct SyntheticLinodeMetadataSourceV1<F>
    where
        F: FnMut() -> Result<Vec<u8>, String>,
    {
        signing_key: SigningKey,
        fetch: F,
    }

    impl<F> SyntheticLinodeMetadataSourceV1<F>
    where
        F: FnMut() -> Result<Vec<u8>, String>,
    {
        pub(crate) fn new(signing_key: SigningKey, fetch: F) -> Self {
            Self { signing_key, fetch }
        }
    }

    impl<F> SubstrateOriginAttestationSourceV1 for SyntheticLinodeMetadataSourceV1<F>
    where
        F: FnMut() -> Result<Vec<u8>, String>,
    {
        fn attest(
            &mut self,
            basis: &SubstrateOriginAcquisitionBasisV1,
        ) -> Result<SignedSubstrateOriginAttestationV1, String> {
            if basis.expected_coordinate.kind != SubstrateCoordinateKindV1::LinodeInstance {
                return Err("Linode metadata source refuses another origin profile".into());
            }
            let evidence = LinodeInstanceMetadataEvidenceV1::from_response(&(self.fetch)()?)
                .map_err(|error| error.to_string())?;
            let coordinate = evidence.coordinate().map_err(|error| error.to_string())?;
            if coordinate != basis.expected_coordinate {
                return Err("Linode metadata instance differs from expected coordinate".into());
            }
            let payload = SubstrateOriginAttestationV1 {
                schema: ATTESTATION_SCHEMA_V1.into(),
                attestation_occurrence_ref: format!("attestation:{}", basis.acquisition_id),
                issuer_id: "origin-helper:test".into(),
                key_id: "origin-helper-key:test".into(),
                acquisition_id: basis.acquisition_id.clone(),
                acquisition_basis_digest: basis.digest().map_err(|error| error.to_string())?,
                nonclaims: expected_nonclaims(&coordinate),
                coordinate,
                linode_metadata: Some(evidence),
                attested_at: "2026-08-24T12:00:00Z".into(),
                replay_identity: format!("origin-replay:{}", basis.acquisition_id),
            };
            let payload_bytes =
                nq_protocol::canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
            let mut preimage = Vec::new();
            preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
            preimage.push(0);
            preimage.extend_from_slice(&payload_bytes);
            Ok(SignedSubstrateOriginAttestationV1 {
                schema: SIGNED_ATTESTATION_SCHEMA_V1.into(),
                payload_digest: hex_digest(&payload_bytes),
                signature: hex::encode(self.signing_key.sign(&preimage).to_bytes()),
                payload,
            })
        }
    }

    pub(crate) struct SyntheticOriginSourceV1 {
        issuer_id: String,
        key_id: String,
        namespace: String,
        signing_key: SigningKey,
        calls: usize,
    }

    impl SyntheticOriginSourceV1 {
        pub(crate) fn new(seed: u8, namespace: &str) -> Self {
            Self {
                issuer_id: "origin-attester:test".into(),
                key_id: format!("origin-key:test-{seed}"),
                namespace: namespace.into(),
                signing_key: SigningKey::from_bytes(&[seed; 32]),
                calls: 0,
            }
        }

        pub(crate) fn verifier(&self) -> SubstrateOriginVerifierV1 {
            SubstrateOriginVerifierV1::new(
                self.issuer_id.clone(),
                self.key_id.clone(),
                self.namespace.clone(),
                self.signing_key.verifying_key(),
            )
            .expect("synthetic verifier")
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls
        }
    }

    impl SubstrateOriginAttestationSourceV1 for SyntheticOriginSourceV1 {
        fn attest(
            &mut self,
            basis: &SubstrateOriginAcquisitionBasisV1,
        ) -> Result<SignedSubstrateOriginAttestationV1, String> {
            self.calls += 1;
            let coordinate = SubstrateCoordinateV1::for_attester_key(
                self.namespace.clone(),
                self.key_id.clone(),
                &self.signing_key.verifying_key(),
            )
            .map_err(|error| error.to_string())?;
            let payload = SubstrateOriginAttestationV1 {
                schema: ATTESTATION_SCHEMA_V1.into(),
                attestation_occurrence_ref: format!("attestation:{}", basis.acquisition_id),
                issuer_id: self.issuer_id.clone(),
                key_id: self.key_id.clone(),
                acquisition_id: basis.acquisition_id.clone(),
                acquisition_basis_digest: basis.digest().map_err(|error| error.to_string())?,
                coordinate,
                linode_metadata: None,
                attested_at: "2026-08-24T12:00:00Z".into(),
                replay_identity: format!("origin-replay:{}", basis.acquisition_id),
                nonclaims: ATTESTATION_NONCLAIMS.map(str::to_owned).to_vec(),
            };
            let payload_bytes =
                nq_protocol::canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
            let payload_digest = hex_digest(&payload_bytes);
            let mut preimage = Vec::new();
            preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
            preimage.push(0);
            preimage.extend_from_slice(&payload_bytes);
            Ok(SignedSubstrateOriginAttestationV1 {
                schema: SIGNED_ATTESTATION_SCHEMA_V1.into(),
                payload,
                payload_digest,
                signature: hex::encode(self.signing_key.sign(&preimage).to_bytes()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::test_support::{SyntheticLinodeMetadataSourceV1, SyntheticOriginSourceV1};
    use super::*;

    fn basis(verifier: &SubstrateOriginVerifierV1) -> SubstrateOriginAcquisitionBasisV1 {
        SubstrateOriginAcquisitionBasisV1 {
            schema: ORIGIN_BASIS_SCHEMA_V1.into(),
            acquisition_id: "origin-acquisition:test".into(),
            watcher_instance_id: "watcher:test".into(),
            watcher_config_digest: "a".repeat(64),
            subject_ref: "observer:test-office".into(),
            expected_coordinate: verifier.expected_coordinate().expect("coordinate"),
            continuity: None,
        }
    }

    #[test]
    fn exact_attester_key_origin_verifies_and_replay_converges() {
        let mut source = SyntheticOriginSourceV1::new(7, "substrate:test");
        let verifier = source.verifier();
        let basis = basis(&verifier);
        let first = source.attest(&basis).expect("attestation");
        let second = source.attest(&basis).expect("exact replay attestation");
        assert_eq!(first, second);
        assert_eq!(source.calls(), 2);
        let verification = verifier.verify(&basis, &first).expect("origin verifies");
        assert_eq!(verification.basis, basis);
        assert_eq!(verification.attestation, first);
    }

    #[test]
    fn self_declared_or_wrong_attester_origin_cannot_substitute() {
        let source = SyntheticOriginSourceV1::new(7, "substrate:test");
        let verifier = source.verifier();
        let basis = basis(&verifier);
        let mut attacker = SyntheticOriginSourceV1::new(8, "substrate:test");
        let forged = attacker.attest(&basis).expect("attacker can make bytes");
        assert_eq!(
            verifier.verify(&basis, &forged),
            Err(SubstrateOriginError::Substitution("attestation binding"))
        );
    }

    #[test]
    fn coordinate_contract_contains_no_boot_network_or_configured_identity_fields() {
        let source = SyntheticOriginSourceV1::new(7, "substrate:test");
        let coordinate = source.verifier().expected_coordinate().expect("coordinate");
        let value = serde_json::to_value(coordinate).expect("json");
        for forbidden in [
            "boot_id",
            "machine_id",
            "hostname",
            "dns",
            "ip",
            "subject_ref",
        ] {
            assert!(value.get(forbidden).is_none(), "forbidden {forbidden}");
        }
    }

    fn linode_response(id: u64, host_uuid: &str) -> Vec<u8> {
        format!(
            r#"{{"id":{id},"host_uuid":"{host_uuid}","label":"mutable-name","region":"ca-central","type":"g6-dedicated-4","tags":[],"specs":{{"vcpus":8,"memory":16384,"disk":327680,"transfer":8000,"gpus":0}},"backups":{{"enabled":false,"status":null}},"account_euuid":"supplemental","image":{{"id":"linode/ubuntu22.04","label":"Ubuntu"}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn linode_metadata_profile_binds_logical_instance_not_host_uuid() {
        let response = linode_response(42, "physical-host-a");
        let evidence = LinodeInstanceMetadataEvidenceV1::from_response(&response).unwrap();
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let verifier = SubstrateOriginVerifierV1::for_linode_instance_metadata(
            "origin-helper:test".into(),
            "origin-helper-key:test".into(),
            evidence.instance_id_sha256.clone(),
            signing_key.verifying_key(),
        )
        .unwrap();
        let basis = basis(&verifier);
        let mut source = SyntheticLinodeMetadataSourceV1::new(signing_key, {
            let response = response.clone();
            move || Ok(response.clone())
        });
        let signed = source.attest(&basis).unwrap();
        verifier.verify(&basis, &signed).unwrap();

        let moved_host = LinodeInstanceMetadataEvidenceV1::from_response(&linode_response(
            42,
            "physical-host-b",
        ))
        .unwrap();
        assert_eq!(
            evidence.coordinate().unwrap(),
            moved_host.coordinate().unwrap()
        );
        assert_ne!(evidence.host_uuid_sha256, moved_host.host_uuid_sha256);
        assert_ne!(
            evidence.canonical_response_sha256,
            moved_host.canonical_response_sha256
        );
    }

    #[test]
    fn linode_metadata_wrong_instance_and_profile_substitution_refuse() {
        let expected = LinodeInstanceMetadataEvidenceV1::from_response(&linode_response(
            42,
            "physical-host-a",
        ))
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let verifier = SubstrateOriginVerifierV1::for_linode_instance_metadata(
            "origin-helper:test".into(),
            "origin-helper-key:test".into(),
            expected.instance_id_sha256.clone(),
            signing_key.verifying_key(),
        )
        .unwrap();
        let basis = basis(&verifier);
        let mut wrong = SyntheticLinodeMetadataSourceV1::new(signing_key, || {
            Ok(linode_response(43, "physical-host-a"))
        });
        assert_eq!(
            wrong.attest(&basis).unwrap_err(),
            "Linode metadata instance differs from expected coordinate"
        );

        let software = SyntheticOriginSourceV1::new(7, "substrate:test");
        assert_ne!(
            software.verifier().expected_coordinate().unwrap().kind,
            basis.expected_coordinate.kind
        );
    }

    #[test]
    fn linode_metadata_parser_refuses_malformed_missing_and_oversized_responses() {
        assert!(LinodeInstanceMetadataEvidenceV1::from_response(b"not-json").is_err());
        assert!(LinodeInstanceMetadataEvidenceV1::from_response(br#"{"label":"x"}"#).is_err());
        assert!(
            LinodeInstanceMetadataEvidenceV1::from_response(&vec![
                b' ';
                MAX_LINODE_METADATA_BYTES + 1
            ])
            .is_err()
        );
    }
}
