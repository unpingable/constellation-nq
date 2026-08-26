//! Proof-bearing Standing continuity prerequisites for one NQ acquisition.
//!
//! The carrier proves only that Standing issued an exact permission warrant and
//! committed it to the exact NQ acquisition before provider invocation. It
//! does not prove that the transition occurred, that the successor claim is
//! truthful, or that Nightshift should rely on the observation.

#![allow(missing_docs, clippy::missing_errors_doc)]

use chrono::DateTime;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::config::WatcherConfig;
use crate::provider_intake::ProviderIdentityV1;
use nq_protocol::HelperRequest;

/// Closed continuity relation supported by this campaign.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityRelationV1 {
    /// Succession between two opaque substrate incarnations.
    SubstrateIncarnation,
}

/// Exact edge for which Standing grants bounded continuity eligibility.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityEdgeV1 {
    pub subject_ref: String,
    pub relation: ContinuityRelationV1,
    pub predecessor_ref: String,
    pub successor_ref: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityNonclaimV1 {
    TransitionOccurred,
    EvidenceTruth,
    CurrentAttribution,
    RoutineReliance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentNonclaimV1 {
    ProviderInvoked,
    ObservationProduced,
    EvidenceTruth,
    CurrentAttribution,
}

fn authority_nonclaims() -> Vec<AuthorityNonclaimV1> {
    vec![
        AuthorityNonclaimV1::TransitionOccurred,
        AuthorityNonclaimV1::EvidenceTruth,
        AuthorityNonclaimV1::CurrentAttribution,
        AuthorityNonclaimV1::RoutineReliance,
    ]
}

fn commitment_nonclaims() -> Vec<CommitmentNonclaimV1> {
    vec![
        CommitmentNonclaimV1::ProviderInvoked,
        CommitmentNonclaimV1::ObservationProduced,
        CommitmentNonclaimV1::EvidenceTruth,
        CommitmentNonclaimV1::CurrentAttribution,
    ]
}

/// Standing-owned immutable continuity-authority payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAuthorityV1 {
    pub schema: String,
    pub authority_occurrence_ref: String,
    pub issuance_request_id: String,
    pub standing_instance: String,
    pub edge: ContinuityEdgeV1,
    pub nq_audience: String,
    pub issuer_principal: String,
    pub standing_basis_digest: String,
    pub replay_identity: String,
    /// Evidence time only; never used as causal proof.
    pub issued_at: String,
    pub nonclaims: Vec<AuthorityNonclaimV1>,
}

/// Asymmetric Standing export of one authority occurrence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContinuityAuthorityV1 {
    pub schema: String,
    pub key_id: String,
    pub payload: ContinuityAuthorityV1,
    pub payload_digest: String,
    pub signature: String,
}

/// Standing-owned commitment of an authority to one exact NQ acquisition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionCommitmentV1 {
    pub schema: String,
    pub commitment_occurrence_ref: String,
    pub request_id: String,
    pub standing_instance: String,
    pub authority_occurrence_ref: String,
    pub authority_payload_digest: String,
    /// Preallocated NQ provider-intake/acquisition identity.
    pub acquisition_id: String,
    /// Digest of the exact NQ-owned static acquisition basis.
    pub acquisition_basis_digest: String,
    pub nq_audience: String,
    pub replay_identity: String,
    /// Evidence time only; never used as causal proof.
    pub committed_at: String,
    pub nonclaims: Vec<CommitmentNonclaimV1>,
}

/// Asymmetric Standing export of one pre-acquisition commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContinuityAcquisitionCommitmentV1 {
    pub schema: String,
    pub key_id: String,
    pub payload: ContinuityAcquisitionCommitmentV1,
    pub payload_digest: String,
    pub signature: String,
}

/// Exact authenticated carrier consumed before provider invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionCarrierV1 {
    pub schema: String,
    pub authority: SignedContinuityAuthorityV1,
    pub commitment: SignedContinuityAcquisitionCommitmentV1,
}

/// Static NQ-owned acquisition basis committed by Standing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionBasisV1 {
    pub schema: String,
    pub acquisition_id: String,
    pub nq_audience: String,
    pub watcher_instance_id: String,
    pub watcher_config_digest: String,
    pub authority_occurrence_ref: String,
    pub authority_digest: String,
    pub edge: ContinuityEdgeV1,
}

/// Operator/process-boundary export of the exact basis and the canonical
/// digest Standing must commit. The digest is over `basis`, not over this
/// wrapper or incidental file bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionBasisExportV1 {
    pub schema: String,
    pub basis: ContinuityAcquisitionBasisV1,
    pub basis_digest: String,
}

/// Verified carrier and the exact basis it authorizes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedContinuityCarrierV1 {
    pub carrier: ContinuityAcquisitionCarrierV1,
    pub basis: ContinuityAcquisitionBasisV1,
    pub basis_digest: String,
}

/// Exact NQ intent durably committed before the bound provider starts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAcquisitionIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub basis: ContinuityAcquisitionBasisV1,
    pub basis_digest: String,
    pub carrier: ContinuityAcquisitionCarrierV1,
    pub intake_id: String,
    pub attempt_id: String,
    pub run_id: String,
    pub request: HelperRequest,
    pub provider: ProviderIdentityV1,
    pub origin_carrier: String,
    pub checkpoint_contract_digest: String,
}

/// Verification failures at the cross-office boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContinuityCarrierError {
    #[error("continuity carrier is malformed: {0}")]
    Malformed(String),
    #[error("continuity carrier signature is invalid")]
    Signature,
    #[error("continuity carrier substitutes {0}")]
    Substitution(&'static str),
}

const AUTHORITY_SCHEMA: &str = "standing.continuity_authority.v1";
const SIGNED_AUTHORITY_SCHEMA: &str = "standing.signed_continuity_authority.v1";
const COMMITMENT_SCHEMA: &str = "standing.continuity_acquisition_commitment.v1";
const SIGNED_COMMITMENT_SCHEMA: &str = "standing.signed_continuity_acquisition_commitment.v1";
const CARRIER_SCHEMA: &str = "standing.continuity_acquisition_bundle.v1";
const BASIS_SCHEMA: &str = "nq.continuity_acquisition_basis.v1";
const BASIS_EXPORT_SCHEMA: &str = "nq.continuity_acquisition_basis_export.v1";
const INTENT_SCHEMA: &str = "nq.provider_acquisition_intent.v1";

fn require_token(name: &str, value: &str) -> Result<(), ContinuityCarrierError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        return Err(ContinuityCarrierError::Malformed(format!(
            "{name} must be a bounded non-whitespace token"
        )));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), ContinuityCarrierError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContinuityCarrierError::Malformed(format!(
            "{name} must be 64 lowercase SHA-256 hex characters"
        )));
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ContinuityCarrierError> {
    nq_protocol::canonical_json_bytes(value)
        .map_err(|error| ContinuityCarrierError::Malformed(error.to_string()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn identity_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_bytes(bytes))
}

fn signature_bytes(value: &str) -> Result<[u8; 64], ContinuityCarrierError> {
    let bytes = hex::decode(value)
        .map_err(|_| ContinuityCarrierError::Malformed("signature is not hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| ContinuityCarrierError::Malformed("signature is not 64 bytes".into()))
}

#[allow(clippy::too_many_arguments)]
fn verify_signed<T: Serialize>(
    schema: &str,
    expected_schema: &str,
    key_id: &str,
    expected_key_id: &str,
    payload: &T,
    payload_digest: &str,
    signature: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), ContinuityCarrierError> {
    if schema != expected_schema {
        return Err(ContinuityCarrierError::Substitution("signed schema"));
    }
    if key_id != expected_key_id {
        return Err(ContinuityCarrierError::Substitution(
            "Standing key identity",
        ));
    }
    let bytes = canonical(payload)?;
    if digest_bytes(&bytes) != payload_digest {
        return Err(ContinuityCarrierError::Substitution("payload digest"));
    }
    let mut preimage = Vec::with_capacity(expected_schema.len() + 1 + bytes.len());
    preimage.extend_from_slice(expected_schema.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&bytes);
    verifying_key
        .verify(
            &preimage,
            &Signature::from_bytes(&signature_bytes(signature)?),
        )
        .map_err(|_| ContinuityCarrierError::Signature)
}

fn validate_edge(edge: &ContinuityEdgeV1) -> Result<(), ContinuityCarrierError> {
    require_token("edge.subject_ref", &edge.subject_ref)?;
    require_token("edge.predecessor_ref", &edge.predecessor_ref)?;
    require_token("edge.successor_ref", &edge.successor_ref)?;
    if edge.predecessor_ref == edge.successor_ref {
        return Err(ContinuityCarrierError::Malformed(
            "continuity edge predecessor and successor must differ".into(),
        ));
    }
    Ok(())
}

impl ContinuityAcquisitionBasisV1 {
    /// Build the static basis from one watcher and authenticated authority.
    pub fn for_watcher(
        watcher: &WatcherConfig,
        acquisition_id: String,
        authority: &SignedContinuityAuthorityV1,
    ) -> Result<Self, ContinuityCarrierError> {
        Ok(Self {
            schema: BASIS_SCHEMA.into(),
            acquisition_id,
            nq_audience: authority.payload.nq_audience.clone(),
            watcher_instance_id: watcher.instance_id.clone(),
            watcher_config_digest: digest_bytes(&canonical(watcher)?),
            authority_occurrence_ref: authority.payload.authority_occurrence_ref.clone(),
            authority_digest: authority.payload_digest.clone(),
            edge: authority.payload.edge.clone(),
        })
    }

    /// Canonical content digest committed by Standing.
    pub fn digest(&self) -> Result<String, ContinuityCarrierError> {
        Ok(digest_bytes(&canonical(self)?))
    }

    /// Pair the basis with the canonical digest a Standing commitment must
    /// bind, so callers never substitute a file-byte or pretty-JSON hash.
    pub fn export(&self) -> Result<ContinuityAcquisitionBasisExportV1, ContinuityCarrierError> {
        self.validate()?;
        Ok(ContinuityAcquisitionBasisExportV1 {
            schema: BASIS_EXPORT_SCHEMA.into(),
            basis: self.clone(),
            basis_digest: self.digest()?,
        })
    }

    fn validate(&self) -> Result<(), ContinuityCarrierError> {
        if self.schema != BASIS_SCHEMA {
            return Err(ContinuityCarrierError::Substitution("basis schema"));
        }
        for (name, value) in [
            ("acquisition_id", &self.acquisition_id),
            ("nq_audience", &self.nq_audience),
            ("watcher_instance_id", &self.watcher_instance_id),
            ("authority_occurrence_ref", &self.authority_occurrence_ref),
        ] {
            require_token(name, value)?;
        }
        require_digest("watcher_config_digest", &self.watcher_config_digest)?;
        require_digest("authority_digest", &self.authority_digest)?;
        validate_edge(&self.edge)
    }
}

impl ContinuityAcquisitionCarrierV1 {
    /// Verify signatures and every authority/commitment/basis binding.
    pub fn verify_for_watcher(
        &self,
        watcher: &WatcherConfig,
        expected_standing_instance: &str,
        expected_nq_audience: &str,
        expected_key_id: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<VerifiedContinuityCarrierV1, ContinuityCarrierError> {
        if self.schema != CARRIER_SCHEMA {
            return Err(ContinuityCarrierError::Substitution("carrier schema"));
        }
        let authority = &self.authority;
        authority.verify_for_watcher(
            watcher,
            expected_standing_instance,
            expected_nq_audience,
            expected_key_id,
            verifying_key,
        )?;
        let commitment = &self.commitment;
        if commitment.payload.schema != COMMITMENT_SCHEMA {
            return Err(ContinuityCarrierError::Substitution("commitment schema"));
        }
        for (name, value) in [
            (
                "commitment occurrence",
                &commitment.payload.commitment_occurrence_ref,
            ),
            ("commitment request", &commitment.payload.request_id),
            (
                "commitment replay identity",
                &commitment.payload.replay_identity,
            ),
            ("acquisition_id", &commitment.payload.acquisition_id),
        ] {
            require_token(name, value)?;
        }
        for (name, value) in [
            (
                "commitment occurrence",
                &commitment.payload.commitment_occurrence_ref,
            ),
            ("commitment request", &commitment.payload.request_id),
            (
                "commitment authority occurrence",
                &commitment.payload.authority_occurrence_ref,
            ),
        ] {
            uuid::Uuid::parse_str(value)
                .map_err(|_| ContinuityCarrierError::Malformed(format!("{name} is not a UUID")))?;
        }
        if DateTime::parse_from_rfc3339(&commitment.payload.committed_at).is_err() {
            return Err(ContinuityCarrierError::Malformed(
                "commitment committed_at is not RFC3339 evidence time".into(),
            ));
        }
        require_digest(
            "commitment acquisition_basis_digest",
            &commitment.payload.acquisition_basis_digest,
        )?;
        if commitment.payload.nonclaims != commitment_nonclaims() {
            return Err(ContinuityCarrierError::Substitution("commitment nonclaims"));
        }
        if commitment.payload.standing_instance != authority.payload.standing_instance
            || commitment.payload.authority_occurrence_ref
                != authority.payload.authority_occurrence_ref
            || commitment.payload.authority_payload_digest != authority.payload_digest
            || commitment.payload.nq_audience != authority.payload.nq_audience
            || commitment.key_id != authority.key_id
        {
            return Err(ContinuityCarrierError::Substitution(
                "authority/commitment binding",
            ));
        }
        verify_signed(
            &commitment.schema,
            SIGNED_COMMITMENT_SCHEMA,
            &commitment.key_id,
            expected_key_id,
            &commitment.payload,
            &commitment.payload_digest,
            &commitment.signature,
            verifying_key,
        )?;

        let basis = ContinuityAcquisitionBasisV1::for_watcher(
            watcher,
            commitment.payload.acquisition_id.clone(),
            authority,
        )?;
        basis.validate()?;
        let basis_digest = basis.digest()?;
        if basis_digest != commitment.payload.acquisition_basis_digest {
            return Err(ContinuityCarrierError::Substitution("acquisition basis"));
        }
        Ok(VerifiedContinuityCarrierV1 {
            carrier: self.clone(),
            basis,
            basis_digest,
        })
    }
}

impl SignedContinuityAuthorityV1 {
    /// Verify one authority against pinned Standing identity and exact watcher subject.
    pub fn verify_for_watcher(
        &self,
        watcher: &WatcherConfig,
        expected_standing_instance: &str,
        expected_nq_audience: &str,
        expected_key_id: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ContinuityCarrierError> {
        let authority = self;
        if authority.payload.schema != AUTHORITY_SCHEMA {
            return Err(ContinuityCarrierError::Substitution("authority schema"));
        }
        validate_edge(&authority.payload.edge)?;
        for (name, value) in [
            (
                "authority occurrence",
                &authority.payload.authority_occurrence_ref,
            ),
            ("issuance request", &authority.payload.issuance_request_id),
            ("Standing instance", &authority.payload.standing_instance),
            ("NQ audience", &authority.payload.nq_audience),
            ("issuer principal", &authority.payload.issuer_principal),
            (
                "authority replay identity",
                &authority.payload.replay_identity,
            ),
        ] {
            require_token(name, value)?;
        }
        for (name, value) in [
            (
                "authority occurrence",
                &authority.payload.authority_occurrence_ref,
            ),
            ("issuance request", &authority.payload.issuance_request_id),
        ] {
            uuid::Uuid::parse_str(value)
                .map_err(|_| ContinuityCarrierError::Malformed(format!("{name} is not a UUID")))?;
        }
        require_digest("Standing instance", &authority.payload.standing_instance)?;
        require_digest(
            "standing_basis_digest",
            &authority.payload.standing_basis_digest,
        )?;
        if authority.payload.nonclaims != authority_nonclaims() {
            return Err(ContinuityCarrierError::Substitution("authority nonclaims"));
        }
        if authority.payload.standing_instance != expected_standing_instance {
            return Err(ContinuityCarrierError::Substitution("Standing instance"));
        }
        require_token("expected NQ audience", expected_nq_audience)?;
        if authority.payload.nq_audience != expected_nq_audience {
            return Err(ContinuityCarrierError::Substitution("NQ audience"));
        }
        if authority.payload.edge.subject_ref != watcher.subject {
            return Err(ContinuityCarrierError::Substitution("subject"));
        }
        if DateTime::parse_from_rfc3339(&authority.payload.issued_at).is_err() {
            return Err(ContinuityCarrierError::Malformed(
                "authority issued_at is not RFC3339 evidence time".into(),
            ));
        }
        verify_signed(
            &authority.schema,
            SIGNED_AUTHORITY_SCHEMA,
            &authority.key_id,
            expected_key_id,
            &authority.payload,
            &authority.payload_digest,
            &authority.signature,
            verifying_key,
        )
    }
}

impl ProviderAcquisitionIntentV1 {
    /// Seal and validate one exact pre-invocation intent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verified: &VerifiedContinuityCarrierV1,
        attempt_id: String,
        run_id: String,
        request: HelperRequest,
        provider: ProviderIdentityV1,
        origin_carrier: String,
        checkpoint_contract_digest: String,
    ) -> Result<Self, ContinuityCarrierError> {
        let mut intent = Self {
            schema: INTENT_SCHEMA.into(),
            intent_id: String::new(),
            basis: verified.basis.clone(),
            basis_digest: verified.basis_digest.clone(),
            carrier: verified.carrier.clone(),
            intake_id: verified.basis.acquisition_id.clone(),
            attempt_id,
            run_id,
            request,
            provider,
            origin_carrier,
            checkpoint_contract_digest,
        };
        intent.intent_id = intent.computed_id()?;
        intent.validate()?;
        Ok(intent)
    }

    /// Canonical identity excluding the identity field itself.
    pub fn computed_id(&self) -> Result<String, ContinuityCarrierError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| ContinuityCarrierError::Malformed(error.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| ContinuityCarrierError::Malformed("intent is not an object".into()))?
            .remove("intent_id");
        Ok(identity_bytes(&canonical(&value)?))
    }

    /// Strictly validate all duplicated coordinates.
    pub fn validate(&self) -> Result<(), ContinuityCarrierError> {
        if self.schema != INTENT_SCHEMA {
            return Err(ContinuityCarrierError::Substitution("intent schema"));
        }
        self.basis.validate()?;
        if self.basis.digest()? != self.basis_digest
            || self.intake_id != self.basis.acquisition_id
            || self.carrier.commitment.payload.acquisition_id != self.intake_id
            || self.carrier.commitment.payload.acquisition_basis_digest != self.basis_digest
            || self.carrier.authority.payload.authority_occurrence_ref
                != self.basis.authority_occurrence_ref
            || self.carrier.authority.payload_digest != self.basis.authority_digest
        {
            return Err(ContinuityCarrierError::Substitution("intent prerequisite"));
        }
        for (name, value) in [
            ("intent_id", &self.intent_id),
            ("intake_id", &self.intake_id),
            ("attempt_id", &self.attempt_id),
            ("run_id", &self.run_id),
            ("origin_carrier", &self.origin_carrier),
        ] {
            require_token(name, value)?;
        }
        let checkpoint_hex = self
            .checkpoint_contract_digest
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                ContinuityCarrierError::Malformed(
                    "checkpoint_contract_digest lacks sha256 prefix".into(),
                )
            })?;
        require_digest("checkpoint_contract_digest", checkpoint_hex)?;
        if self.request.instance_id.as_str() != self.basis.watcher_instance_id
            || self.request.binding.subject.as_str() != self.basis.edge.subject_ref
        {
            return Err(ContinuityCarrierError::Substitution("provider request"));
        }
        if self.intent_id != self.computed_id()? {
            return Err(ContinuityCarrierError::Substitution("intent identity"));
        }
        Ok(())
    }

    /// Digest of the complete canonical document, including its self identity.
    pub fn canonical_digest(&self) -> Result<String, ContinuityCarrierError> {
        Ok(identity_bytes(&canonical(self)?))
    }
}

/// Parse a raw 32-byte lowercase-hex Standing verification key.
pub fn parse_verifying_key(value: &str) -> Result<VerifyingKey, ContinuityCarrierError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| ContinuityCarrierError::Malformed("verification key is not hex".into()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        ContinuityCarrierError::Malformed("verification key is not 32 bytes".into())
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ContinuityCarrierError::Malformed("verification key is invalid".into()))
}

#[cfg(test)]
pub(crate) fn verified_fixture_carrier(
    watcher: &WatcherConfig,
    acquisition_id: &str,
) -> VerifiedContinuityCarrierV1 {
    use ed25519_dalek::{Signer as _, SigningKey};

    fn fixture_sign<T: Serialize>(schema: &str, payload: &T, key: &SigningKey) -> (String, String) {
        let bytes = canonical(payload).expect("fixture canonical payload");
        let mut preimage = Vec::new();
        preimage.extend_from_slice(schema.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        (
            digest_bytes(&bytes),
            hex::encode(key.sign(&preimage).to_bytes()),
        )
    }

    let key = SigningKey::from_bytes(&[42; 32]);
    let payload = ContinuityAuthorityV1 {
        schema: AUTHORITY_SCHEMA.into(),
        authority_occurrence_ref: uuid::Uuid::from_u128(1).to_string(),
        issuance_request_id: uuid::Uuid::from_u128(2).to_string(),
        standing_instance: "1".repeat(64),
        edge: ContinuityEdgeV1 {
            subject_ref: watcher.subject.clone(),
            relation: ContinuityRelationV1::SubstrateIncarnation,
            predecessor_ref: "substrate:test-a".into(),
            successor_ref: "substrate:test-b".into(),
        },
        nq_audience: "wl:nq:test".into(),
        issuer_principal: "standing:test-operator".into(),
        standing_basis_digest: "2".repeat(64),
        replay_identity: "authority-replay-fixture".into(),
        issued_at: "2099-01-01T00:00:00Z".into(),
        nonclaims: authority_nonclaims(),
    };
    let (payload_digest, signature) = fixture_sign(SIGNED_AUTHORITY_SCHEMA, &payload, &key);
    let authority = SignedContinuityAuthorityV1 {
        schema: SIGNED_AUTHORITY_SCHEMA.into(),
        key_id: "standing.test.v1".into(),
        payload,
        payload_digest,
        signature,
    };
    let basis =
        ContinuityAcquisitionBasisV1::for_watcher(watcher, acquisition_id.to_owned(), &authority)
            .expect("fixture basis");
    let commitment_payload = ContinuityAcquisitionCommitmentV1 {
        schema: COMMITMENT_SCHEMA.into(),
        commitment_occurrence_ref: uuid::Uuid::from_u128(3).to_string(),
        request_id: uuid::Uuid::from_u128(4).to_string(),
        standing_instance: authority.payload.standing_instance.clone(),
        authority_occurrence_ref: authority.payload.authority_occurrence_ref.clone(),
        authority_payload_digest: authority.payload_digest.clone(),
        acquisition_id: acquisition_id.into(),
        acquisition_basis_digest: basis.digest().expect("fixture basis digest"),
        nq_audience: authority.payload.nq_audience.clone(),
        replay_identity: "commitment-replay-fixture".into(),
        committed_at: "2000-01-01T00:00:00Z".into(),
        nonclaims: commitment_nonclaims(),
    };
    let (commitment_digest, commitment_signature) =
        fixture_sign(SIGNED_COMMITMENT_SCHEMA, &commitment_payload, &key);
    ContinuityAcquisitionCarrierV1 {
        schema: CARRIER_SCHEMA.into(),
        authority,
        commitment: SignedContinuityAcquisitionCommitmentV1 {
            schema: SIGNED_COMMITMENT_SCHEMA.into(),
            key_id: "standing.test.v1".into(),
            payload: commitment_payload,
            payload_digest: commitment_digest,
            signature: commitment_signature,
        },
    }
    .verify_for_watcher(
        watcher,
        &"1".repeat(64),
        "wl:nq:test",
        "standing.test.v1",
        &key.verifying_key(),
    )
    .expect("fixture carrier verifies")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::config::{
        Carrier, CheckpointPolicy, CommandConfig, ProfileSelection, ResourceLimits, ScheduleConfig,
        ScopeConfig, VantageConfig,
    };

    use super::*;

    fn watcher(subject: &str) -> WatcherConfig {
        WatcherConfig {
            instance_id: "fixture.primary".into(),
            command: CommandConfig {
                executable: PathBuf::from("/bin/false"),
                args: Vec::new(),
                env: BTreeMap::new(),
                execution_account: "65534".into(),
                allow_same_identity_in_debug: false,
                working_directory: PathBuf::from("/"),
            },
            carrier: Carrier::Stdio,
            profile: ProfileSelection {
                id: "nq.conformance".into(),
                version: 1,
            },
            subject: subject.into(),
            scope: ScopeConfig {
                kind: "fixture".into(),
                value: serde_json::json!({"id": "local"}),
            },
            vantage: VantageConfig {
                kind: "local".into(),
                value: serde_json::json!({}),
            },
            capability_ceiling: BTreeSet::new(),
            schedule: ScheduleConfig::default(),
            resources: ResourceLimits::default(),
            checkpoint_policy: CheckpointPolicy::Disabled,
            passive_host_load_sample: None,
        }
    }

    fn sign<T: Serialize>(schema: &str, payload: &T, key: &SigningKey) -> (String, String) {
        let bytes = canonical(payload).unwrap();
        let mut preimage = Vec::new();
        preimage.extend_from_slice(schema.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        (
            digest_bytes(&bytes),
            hex::encode(key.sign(&preimage).to_bytes()),
        )
    }

    fn authority(key: &SigningKey, occurrence: u128) -> SignedContinuityAuthorityV1 {
        let payload = ContinuityAuthorityV1 {
            schema: AUTHORITY_SCHEMA.into(),
            authority_occurrence_ref: uuid::Uuid::from_u128(occurrence).to_string(),
            issuance_request_id: uuid::Uuid::from_u128(occurrence + 100).to_string(),
            standing_instance: "1".repeat(64),
            edge: ContinuityEdgeV1 {
                subject_ref: "observer:test-office".into(),
                relation: ContinuityRelationV1::SubstrateIncarnation,
                predecessor_ref: "substrate:test-a".into(),
                successor_ref: "substrate:test-b".into(),
            },
            nq_audience: "nq:fixture.primary".into(),
            issuer_principal: "standing:operator".into(),
            standing_basis_digest: "2".repeat(64),
            replay_identity: format!("replay-{occurrence}"),
            issued_at: "2099-01-01T00:00:00Z".into(),
            nonclaims: authority_nonclaims(),
        };
        let (payload_digest, signature) = sign(SIGNED_AUTHORITY_SCHEMA, &payload, key);
        SignedContinuityAuthorityV1 {
            schema: SIGNED_AUTHORITY_SCHEMA.into(),
            key_id: "standing.test.v1".into(),
            payload,
            payload_digest,
            signature,
        }
    }

    fn carrier(key: &SigningKey) -> ContinuityAcquisitionCarrierV1 {
        let authority = authority(key, 1);
        let basis = ContinuityAcquisitionBasisV1::for_watcher(
            &watcher("observer:test-office"),
            "acquisition-a".into(),
            &authority,
        )
        .unwrap();
        let payload = ContinuityAcquisitionCommitmentV1 {
            schema: COMMITMENT_SCHEMA.into(),
            commitment_occurrence_ref: uuid::Uuid::from_u128(3).to_string(),
            request_id: uuid::Uuid::from_u128(4).to_string(),
            standing_instance: authority.payload.standing_instance.clone(),
            authority_occurrence_ref: authority.payload.authority_occurrence_ref.clone(),
            authority_payload_digest: authority.payload_digest.clone(),
            acquisition_id: basis.acquisition_id.clone(),
            acquisition_basis_digest: basis.digest().unwrap(),
            nq_audience: authority.payload.nq_audience.clone(),
            replay_identity: "commit-replay-a".into(),
            committed_at: "2000-01-01T00:00:00Z".into(),
            nonclaims: commitment_nonclaims(),
        };
        let (payload_digest, signature) = sign(SIGNED_COMMITMENT_SCHEMA, &payload, key);
        ContinuityAcquisitionCarrierV1 {
            schema: CARRIER_SCHEMA.into(),
            authority,
            commitment: SignedContinuityAcquisitionCommitmentV1 {
                schema: SIGNED_COMMITMENT_SCHEMA.into(),
                key_id: "standing.test.v1".into(),
                payload,
                payload_digest,
                signature,
            },
        }
    }

    #[test]
    fn exact_signed_edge_and_basis_verify_without_timestamp_ordering() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let verified = carrier(&key)
            .verify_for_watcher(
                &watcher("observer:test-office"),
                &"1".repeat(64),
                "nq:fixture.primary",
                "standing.test.v1",
                &key.verifying_key(),
            )
            .unwrap();
        assert_eq!(verified.basis.acquisition_id, "acquisition-a");
        assert_eq!(
            verified.basis.edge.relation,
            ContinuityRelationV1::SubstrateIncarnation
        );
        let export = verified.basis.export().unwrap();
        assert_eq!(export.schema, BASIS_EXPORT_SCHEMA);
        assert_eq!(export.basis_digest, verified.basis_digest);
        // issued_at is deliberately later than committed_at. Signatures and
        // structural prerequisite binding, never these asserted times, prove causality.
        assert!(
            verified.carrier.authority.payload.issued_at
                > verified.carrier.commitment.payload.committed_at
        );
    }

    #[test]
    fn wrong_subject_edge_and_backdated_reseal_refuse() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let original = carrier(&key);
        assert!(matches!(
            original.verify_for_watcher(
                &watcher("observer:other"),
                &"1".repeat(64),
                "nq:fixture.primary",
                "standing.test.v1",
                &key.verifying_key(),
            ),
            Err(ContinuityCarrierError::Substitution("subject"))
        ));

        let mut substituted = original.clone();
        substituted.authority.payload.edge.successor_ref = "substrate:test-c".into();
        assert!(
            substituted
                .verify_for_watcher(
                    &watcher("observer:test-office"),
                    &"1".repeat(64),
                    "nq:fixture.primary",
                    "standing.test.v1",
                    &key.verifying_key(),
                )
                .is_err()
        );

        let mut backdated = original;
        backdated.authority.payload.issued_at = "1900-01-01T00:00:00Z".into();
        assert_eq!(
            backdated.verify_for_watcher(
                &watcher("observer:test-office"),
                &"1".repeat(64),
                "nq:fixture.primary",
                "standing.test.v1",
                &key.verifying_key(),
            ),
            Err(ContinuityCarrierError::Substitution("payload digest"))
        );
    }

    #[test]
    fn deliberate_same_edge_authorities_remain_distinct() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let first = authority(&key, 1);
        let second = authority(&key, 2);
        assert_eq!(first.payload.edge, second.payload.edge);
        assert_ne!(
            first.payload.authority_occurrence_ref,
            second.payload.authority_occurrence_ref
        );
        assert_ne!(first.payload_digest, second.payload_digest);
    }

    #[test]
    fn arbitrary_relation_and_mutable_authorized_flag_are_closed() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let value = serde_json::to_value(carrier(&key)).unwrap();
        let mut wrong_relation = value.clone();
        wrong_relation["authority"]["payload"]["edge"]["relation"] =
            serde_json::json!("hostname_similarity");
        assert!(serde_json::from_value::<ContinuityAcquisitionCarrierV1>(wrong_relation).is_err());
        let mut flag = value;
        flag["authority"]["payload"]["continuity_authorized"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ContinuityAcquisitionCarrierV1>(flag).is_err());
    }
}
