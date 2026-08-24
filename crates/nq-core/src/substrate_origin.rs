//! Proof-bearing substrate-origin prerequisites for one provider acquisition.
//!
//! The contract is provider-neutral but deliberately not verifier-neutral: an
//! origin profile pins one attester issuer and Ed25519 key.  The coordinate
//! identifies the attester-key-scoped runtime incarnation.  Whether custody of
//! that key is strong enough to represent a VM, host installation, or hardware
//! platform remains a deployment qualification, never an inference made here.

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateCoordinateKindV1 {
    /// One runtime incarnation identified by a pinned attestation key.
    AttesterKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateOriginEvidenceMethodV1 {
    Ed25519AcquisitionChallenge,
}

/// Typed content-addressed coordinate for one attester-key-scoped substrate
/// incarnation.  DNS, IP, hostname, boot ID, and provider output are absent by
/// construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateCoordinateV1 {
    pub schema: String,
    pub kind: SubstrateCoordinateKindV1,
    pub namespace: String,
    pub attester_key_id: String,
    pub attester_public_key_sha256: Sha256Digest,
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
            attester_key_id,
            attester_public_key_sha256: public_key_digest,
            evidence_method: SubstrateOriginEvidenceMethodV1::Ed25519AcquisitionChallenge,
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
        Ok(format!("substrate:attester-key:v1:{}", hex_digest(&bytes)))
    }

    pub fn validate(&self) -> Result<(), SubstrateOriginError> {
        if self.schema != COORDINATE_SCHEMA_V1 {
            return Err(SubstrateOriginError::Substitution("coordinate schema"));
        }
        require_token("coordinate namespace", &self.namespace)?;
        require_token("attester key id", &self.attester_key_id)?;
        if self.coordinate_ref != self.computed_ref()? {
            return Err(SubstrateOriginError::Substitution("coordinate identity"));
        }
        Ok(())
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
    expected_namespace: String,
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
        Ok(Self {
            expected_issuer_id,
            expected_key_id,
            expected_namespace,
            verifying_key,
        })
    }

    pub fn expected_coordinate(&self) -> Result<SubstrateCoordinateV1, SubstrateOriginError> {
        SubstrateCoordinateV1::for_attester_key(
            self.expected_namespace.clone(),
            self.expected_key_id.clone(),
            &self.verifying_key,
        )
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
            || signed.payload.nonclaims != ATTESTATION_NONCLAIMS.map(str::to_owned).to_vec()
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
    use super::test_support::SyntheticOriginSourceV1;
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
}
