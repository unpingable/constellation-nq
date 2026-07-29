//! Exact restart dependencies and independently admitted authority inputs.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use nq_host_role_contract::{
    CatalogSnapshot, IdentityCatalog, IdentityKind, IdentityRef, RecordRef, RuntimeRecordSet,
    RuntimeSchema, Timestamp,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};

use crate::{Result, RuntimeError};

/// Local persistence schema for exact off-ledger dependency custody.
pub const EXTERNAL_DEPENDENCY_SNAPSHOT_SCHEMA: &str =
    "nq.host_role_external_dependency_snapshot.v1";
/// Local persistence schema for independently admitted authority inputs.
pub const AUTHORITY_ADMISSION_SNAPSHOT_SCHEMA: &str =
    "nq.host_role_authority_admission_snapshot.v1";
/// Bootstrap carrier for one immutable Ed25519 dependency-admission anchor.
pub const ED25519_TRUST_ANCHOR_SCHEMA: &str = "nq.host_role_ed25519_trust_anchor.v1";
/// Signed, closed admission-receipt set for one dependency generation.
pub const ADMISSION_RECEIPT_SET_SCHEMA: &str = "nq.host_role_admission_receipt_set.v1";
/// Exact generation carrier binding every restart dependency and trust input.
pub const RUNTIME_DEPENDENCY_GENERATION_SCHEMA: &str =
    "nq.host_role_runtime_dependency_generation.v1";
/// Exact local custody carrier for one historical dependency generation.
pub const RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA: &str =
    "nq.host_role_runtime_dependency_generation_custody.v1";

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";

/// First concrete signature adapter for dependency admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionSignatureAlgorithm {
    /// RFC 8032 Ed25519 verification using a 32-byte public key and a
    /// 64-byte signature.
    Ed25519V1,
}

/// Exact immutable bootstrap trust anchor.
///
/// Construction is intentionally limited to exact canonical bytes. On first
/// bootstrap the store must persist those exact bytes and their
/// [`Self::anchor_id`]. Every later open must load the persisted carrier and
/// compare it to the independently configured expected anchor identity before
/// calling [`RuntimeDependencies::decode_authenticated`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519TrustAnchor {
    schema: String,
    algorithm: AdmissionSignatureAlgorithm,
    key_generation: IdentityRef,
    trust_policy: IdentityRef,
    verifier_generation: IdentityRef,
    public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ed25519TrustAnchorCarrier {
    schema: String,
    algorithm: AdmissionSignatureAlgorithm,
    key_generation: IdentityRef,
    trust_policy: IdentityRef,
    verifier_generation: IdentityRef,
    public_key_hex: String,
}

impl Ed25519TrustAnchor {
    /// Decodes exact RFC 8785 canonical anchor bytes.
    ///
    /// This is the explicit first-bootstrap boundary. Possessing arbitrary
    /// anchor bytes does not authorize replacing an anchor already sealed in
    /// a store.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical bytes, incorrect identity kinds, an unknown
    /// schema, or a malformed Ed25519 key.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let carrier: Ed25519TrustAnchorCarrier = serde_json::from_slice(bytes)?;
        let anchor = Self {
            schema: carrier.schema,
            algorithm: carrier.algorithm,
            key_generation: carrier.key_generation,
            trust_policy: carrier.trust_policy,
            verifier_generation: carrier.verifier_generation,
            public_key_hex: carrier.public_key_hex,
        };
        anchor.validate()?;
        if canonical_json_bytes(&anchor)? != bytes {
            return Err(RuntimeError::NonCanonicalDependencyTrustAnchor);
        }
        Ok(anchor)
    }

    /// Decodes an anchor and requires its exact identity to match a separately
    /// retained expected identity.
    ///
    /// This is the restart/open boundary. It prevents caller-supplied anchor
    /// bytes from silently replacing the store's bootstrap root.
    ///
    /// # Errors
    ///
    /// Refuses every condition from [`Self::decode_canonical`] plus identity
    /// substitution.
    pub fn decode_expected(bytes: &[u8], expected_anchor_id: &Sha256Digest) -> Result<Self> {
        let anchor = Self::decode_canonical(bytes)?;
        let observed = anchor.anchor_id()?;
        if &observed != expected_anchor_id {
            return Err(RuntimeError::DependencyTrustAnchorSubstitution {
                expected: expected_anchor_id.clone(),
                observed,
            });
        }
        Ok(anchor)
    }

    /// Returns exact canonical bootstrap bytes.
    ///
    /// # Errors
    ///
    /// Refuses invalid anchor content or canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Returns the exact immutable anchor identity.
    ///
    /// # Errors
    ///
    /// Refuses invalid anchor content or canonicalization failure.
    pub fn anchor_id(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(semantic_digest(self)?)
    }

    /// Returns the admitted key-generation identity.
    #[must_use]
    pub const fn key_generation(&self) -> &IdentityRef {
        &self.key_generation
    }

    /// Returns the admission-policy identity.
    #[must_use]
    pub const fn trust_policy(&self) -> &IdentityRef {
        &self.trust_policy
    }

    /// Returns the exact verifier-generation identity.
    #[must_use]
    pub const fn verifier_generation(&self) -> &IdentityRef {
        &self.verifier_generation
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = decode_exact_hex::<32>(&self.public_key_hex, || {
            RuntimeError::DependencyTrustAnchorPublicKeyMalformed
        })?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| RuntimeError::DependencyTrustAnchorPublicKeyMalformed)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != ED25519_TRUST_ANCHOR_SCHEMA {
            return Err(RuntimeError::UnknownDependencyTrustAnchorSchema(
                self.schema.clone(),
            ));
        }
        self.key_generation.require_kind(
            IdentityKind::KeyGeneration,
            "dependency_anchor.key_generation",
        )?;
        self.trust_policy
            .require_kind(IdentityKind::Policy, "dependency_anchor.trust_policy")?;
        self.verifier_generation.require_kind(
            IdentityKind::Evaluator,
            "dependency_anchor.verifier_generation",
        )?;
        let _ = self.verifying_key()?;
        Ok(())
    }

    #[cfg(test)]
    fn fixture(
        key_generation: IdentityRef,
        trust_policy: IdentityRef,
        verifier_generation: IdentityRef,
        public_key: &VerifyingKey,
    ) -> Result<Self> {
        let anchor = Self {
            schema: ED25519_TRUST_ANCHOR_SCHEMA.to_owned(),
            algorithm: AdmissionSignatureAlgorithm::Ed25519V1,
            key_generation,
            trust_policy,
            verifier_generation,
            public_key_hex: hex::encode(public_key.as_bytes()),
        };
        anchor.validate()?;
        Ok(anchor)
    }
}

/// Closed purpose of one signed dependency-admission receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyAdmissionKind {
    /// Exact bytes admitted into the external dependency closure.
    ExternalDependency,
    /// One operation-authorization record independently authenticated.
    OperationAuthorization,
    /// One invocation authentication-evidence record independently verified.
    InvocationAuthentication,
}

/// One verifier-produced admission receipt covered by the anchor signature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyAdmissionReceipt {
    /// Exact admitted input.
    pub reference: RecordRef,
    /// Closed admission purpose.
    pub kind: DependencyAdmissionKind,
    /// Verifier that made this exact admission.
    pub admitted_by: IdentityRef,
    /// Exact admission time.
    pub admitted_at: Timestamp,
}

impl DependencyAdmissionReceipt {
    /// Returns the identity named by the corresponding dependency snapshot.
    ///
    /// # Errors
    ///
    /// Returns only if canonicalization fails.
    pub fn receipt_id(&self) -> Result<Sha256Digest> {
        Ok(semantic_digest(self)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionReceiptSetUnsigned<'a> {
    schema: &'a str,
    dependency_generation_id: &'a Sha256Digest,
    trust_anchor_id: &'a Sha256Digest,
    trust_policy: &'a IdentityRef,
    verifier_generation: &'a IdentityRef,
    signed_at: &'a Timestamp,
    receipts: &'a [DependencyAdmissionReceipt],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionReceiptManifest<'a> {
    schema: &'a str,
    trust_anchor_id: &'a Sha256Digest,
    trust_policy: &'a IdentityRef,
    verifier_generation: &'a IdentityRef,
    signed_at: &'a Timestamp,
    receipts: &'a [DependencyAdmissionReceipt],
}

/// Exact signed, closed receipt set authenticating one dependency generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmissionReceiptSet {
    schema: String,
    dependency_generation_id: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    trust_policy: IdentityRef,
    verifier_generation: IdentityRef,
    signed_at: Timestamp,
    receipts: Vec<DependencyAdmissionReceipt>,
    signature_hex: String,
}

impl SignedAdmissionReceiptSet {
    /// Decodes exact canonical signed receipt-set bytes.
    ///
    /// Structural validation occurs here. Cryptographic verification is
    /// performed by [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Refuses noncanonical content, duplicate receipts, an unknown schema, or
    /// a malformed signature.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let receipt_set: Self = serde_json::from_slice(bytes)?;
        receipt_set.validate()?;
        if canonical_json_bytes(&receipt_set)? != bytes {
            return Err(RuntimeError::NonCanonicalAdmissionReceiptSet);
        }
        Ok(receipt_set)
    }

    /// Returns exact canonical bytes, including the signature.
    ///
    /// # Errors
    ///
    /// Refuses invalid content or canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Returns the exact generation authenticated by this set.
    #[must_use]
    pub const fn dependency_generation_id(&self) -> &Sha256Digest {
        &self.dependency_generation_id
    }

    /// Returns the closed admitted receipts.
    #[must_use]
    pub fn receipts(&self) -> &[DependencyAdmissionReceipt] {
        &self.receipts
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(&AdmissionReceiptSetUnsigned {
            schema: &self.schema,
            dependency_generation_id: &self.dependency_generation_id,
            trust_anchor_id: &self.trust_anchor_id,
            trust_policy: &self.trust_policy,
            verifier_generation: &self.verifier_generation,
            signed_at: &self.signed_at,
            receipts: &self.receipts,
        })?)
    }

    fn manifest_digest(&self) -> Result<Sha256Digest> {
        Ok(semantic_digest(&AdmissionReceiptManifest {
            schema: &self.schema,
            trust_anchor_id: &self.trust_anchor_id,
            trust_policy: &self.trust_policy,
            verifier_generation: &self.verifier_generation,
            signed_at: &self.signed_at,
            receipts: &self.receipts,
        })?)
    }

    fn verify(
        &self,
        anchor: &Ed25519TrustAnchor,
        generation: &RuntimeDependencyGeneration,
    ) -> Result<()> {
        self.validate()?;
        let anchor_id = anchor.anchor_id()?;
        if self.dependency_generation_id != generation.generation_id()?
            || self.trust_anchor_id != anchor_id
            || self.trust_policy != anchor.trust_policy
            || self.verifier_generation != anchor.verifier_generation
        {
            return Err(RuntimeError::AdmissionReceiptSetBindingMismatch);
        }
        let signature_bytes = decode_exact_hex::<64>(&self.signature_hex, || {
            RuntimeError::AdmissionReceiptSetSignatureMalformed
        })?;
        let signature = Signature::from_bytes(&signature_bytes);
        anchor
            .verifying_key()?
            .verify_strict(&self.unsigned_bytes()?, &signature)
            .map_err(|_| RuntimeError::AdmissionReceiptSetSignatureInvalid)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != ADMISSION_RECEIPT_SET_SCHEMA {
            return Err(RuntimeError::UnknownAdmissionReceiptSetSchema(
                self.schema.clone(),
            ));
        }
        self.trust_policy
            .require_kind(IdentityKind::Policy, "admission_receipts.trust_policy")?;
        self.verifier_generation.require_kind(
            IdentityKind::Evaluator,
            "admission_receipts.verifier_generation",
        )?;
        let mut previous: Option<&DependencyAdmissionReceipt> = None;
        let mut receipt_ids = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.admitted_by.require_kind(
                IdentityKind::Evaluator,
                "admission_receipts.receipts.admitted_by",
            )?;
            if previous.is_some_and(|prior| prior >= receipt) {
                return Err(RuntimeError::AdmissionReceiptSetNotCanonical);
            }
            if !receipt_ids.insert(receipt.receipt_id()?) {
                return Err(RuntimeError::AdmissionReceiptReplay);
            }
            previous = Some(receipt);
        }
        let _ = decode_exact_hex::<64>(&self.signature_hex, || {
            RuntimeError::AdmissionReceiptSetSignatureMalformed
        })?;
        Ok(())
    }

    #[cfg(test)]
    fn fixture_manifest_digest(
        anchor: &Ed25519TrustAnchor,
        signed_at: &Timestamp,
        receipts: &[DependencyAdmissionReceipt],
    ) -> Result<Sha256Digest> {
        let mut receipts = receipts.to_vec();
        receipts.sort();
        Ok(semantic_digest(&AdmissionReceiptManifest {
            schema: ADMISSION_RECEIPT_SET_SCHEMA,
            trust_anchor_id: &anchor.anchor_id()?,
            trust_policy: &anchor.trust_policy,
            verifier_generation: &anchor.verifier_generation,
            signed_at,
            receipts: &receipts,
        })?)
    }

    #[cfg(test)]
    fn fixture_signed(
        generation: &RuntimeDependencyGeneration,
        anchor: &Ed25519TrustAnchor,
        signed_at: Timestamp,
        mut receipts: Vec<DependencyAdmissionReceipt>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use ed25519_dalek::Signer;

        receipts.sort();
        let mut receipt_set = Self {
            schema: ADMISSION_RECEIPT_SET_SCHEMA.to_owned(),
            dependency_generation_id: generation.generation_id()?,
            trust_anchor_id: anchor.anchor_id()?,
            trust_policy: anchor.trust_policy.clone(),
            verifier_generation: anchor.verifier_generation.clone(),
            signed_at,
            receipts,
            signature_hex: hex::encode([0_u8; 64]),
        };
        receipt_set.signature_hex =
            hex::encode(signing_key.sign(&receipt_set.unsigned_bytes()?).to_bytes());
        receipt_set.validate()?;
        Ok(receipt_set)
    }
}

/// Availability of the exact signed receipt-set carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionReceiptSetAvailability {
    /// Exact signed bytes are directly available.
    Online,
    /// Exact signed bytes were retrieved and verified from archive.
    ArchivedRetrieved,
    /// Custody is committed but exact signed bytes cannot currently be read.
    CommittedUnavailable,
}

/// Exact custody state for the signed dependency-admission receipt set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionReceiptSetCustody {
    availability: AdmissionReceiptSetAvailability,
    committed_bytes_digest: Sha256Digest,
    exact_bytes: Option<Vec<u8>>,
}

impl AdmissionReceiptSetCustody {
    /// Admits directly available or archive-retrieved exact receipt-set bytes.
    ///
    /// # Errors
    ///
    /// Refuses `committed_unavailable`, which must use
    /// [`Self::committed_unavailable`].
    pub fn available(
        availability: AdmissionReceiptSetAvailability,
        exact_bytes: Vec<u8>,
    ) -> Result<Self> {
        let committed_bytes_digest = sha256_bytes(&exact_bytes);
        Self::retrieved(availability, exact_bytes, committed_bytes_digest)
    }

    /// Reopens retrieved exact bytes against their previously committed
    /// digest.
    ///
    /// # Errors
    ///
    /// Refuses unavailable state, byte substitution, or an availability/bytes
    /// mismatch.
    pub fn retrieved(
        availability: AdmissionReceiptSetAvailability,
        exact_bytes: Vec<u8>,
        committed_bytes_digest: Sha256Digest,
    ) -> Result<Self> {
        if availability == AdmissionReceiptSetAvailability::CommittedUnavailable {
            return Err(RuntimeError::AdmissionReceiptSetAvailabilityMismatch);
        }
        let custody = Self {
            availability,
            committed_bytes_digest,
            exact_bytes: Some(exact_bytes),
        };
        let _ = custody.exact_bytes()?;
        Ok(custody)
    }

    /// Represents a committed receipt set whose exact bytes cannot currently
    /// be retrieved.
    #[must_use]
    pub const fn committed_unavailable(committed_bytes_digest: Sha256Digest) -> Self {
        Self {
            availability: AdmissionReceiptSetAvailability::CommittedUnavailable,
            committed_bytes_digest,
            exact_bytes: None,
        }
    }

    /// Returns the committed exact-byte digest.
    #[must_use]
    pub const fn committed_bytes_digest(&self) -> &Sha256Digest {
        &self.committed_bytes_digest
    }

    /// Returns the exact current availability mode.
    #[must_use]
    pub const fn availability(&self) -> AdmissionReceiptSetAvailability {
        self.availability
    }

    fn exact_bytes(&self) -> Result<&[u8]> {
        match (self.availability, self.exact_bytes.as_deref()) {
            (
                AdmissionReceiptSetAvailability::Online
                | AdmissionReceiptSetAvailability::ArchivedRetrieved,
                Some(bytes),
            ) if sha256_bytes(bytes) == self.committed_bytes_digest => Ok(bytes),
            (
                AdmissionReceiptSetAvailability::Online
                | AdmissionReceiptSetAvailability::ArchivedRetrieved,
                Some(_),
            ) => Err(RuntimeError::AdmissionReceiptSetByteSubstitution),
            (AdmissionReceiptSetAvailability::CommittedUnavailable, None) => {
                Err(RuntimeError::AdmissionReceiptSetUnavailable)
            }
            _ => Err(RuntimeError::AdmissionReceiptSetAvailabilityMismatch),
        }
    }
}

/// Availability of exact externally retained bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDependencyAvailability {
    /// Exact bytes are directly available.
    Online,
    /// Exact bytes were retrieved and verified from archive for this opening.
    ArchivedRetrieved,
    /// Custody is committed but the exact bytes cannot currently be retrieved.
    CommittedUnavailable,
}

/// One exact externally retained dependency plus its admission receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactExternalDependency {
    /// Exact reference used by the runtime graph.
    pub reference: RecordRef,
    /// Exact bytes encoded as canonical lowercase hexadecimal.
    ///
    /// This is absent only for `committed_unavailable`.
    pub exact_bytes_hex: Option<String>,
    /// Current availability for graph qualification.
    pub availability: ExternalDependencyAvailability,
    /// Independent admission receipt identity.
    pub admission_receipt_id: Sha256Digest,
    /// Exact admitted verifier identity.
    pub admitted_by: IdentityRef,
    /// Time at which that verifier admitted the dependency.
    pub admitted_at: Timestamp,
}

impl ExactExternalDependency {
    fn validate(&self) -> Result<()> {
        let bytes = match (&self.exact_bytes_hex, self.availability) {
            (
                Some(encoded),
                ExternalDependencyAvailability::Online
                | ExternalDependencyAvailability::ArchivedRetrieved,
            ) => {
                let bytes = hex::decode(encoded)
                    .map_err(|_| RuntimeError::ExternalDependencyBytesMalformed)?;
                if hex::encode(&bytes) != *encoded {
                    return Err(RuntimeError::ExternalDependencyBytesMalformed);
                }
                bytes
            }
            (None, ExternalDependencyAvailability::CommittedUnavailable) => return Ok(()),
            _ => return Err(RuntimeError::ExternalDependencyAvailabilityMismatch),
        };
        if sha256_bytes(&bytes) != self.reference.bytes_digest {
            return Err(RuntimeError::ExternalDependencyByteSubstitution(
                self.reference.record_id.to_string(),
            ));
        }
        Ok(())
    }

    fn is_available(&self) -> bool {
        !matches!(
            self.availability,
            ExternalDependencyAvailability::CommittedUnavailable
        )
    }
}

/// Exact dependency closure admitted outside the runtime ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalDependencySnapshot {
    /// Exact local carrier schema.
    pub schema: String,
    /// Strictly ordered, unique exact dependencies.
    pub dependencies: Vec<ExactExternalDependency>,
}

impl ExternalDependencySnapshot {
    /// Constructs a canonical snapshot.
    ///
    /// # Errors
    ///
    /// Refuses runtime-owned records, duplicate references or receipts, and
    /// unavailable/substituted bytes.
    pub fn new(mut dependencies: Vec<ExactExternalDependency>) -> Result<Self> {
        dependencies.sort_by(|left, right| left.reference.cmp(&right.reference));
        let snapshot = Self {
            schema: EXTERNAL_DEPENDENCY_SNAPSHOT_SCHEMA.to_owned(),
            dependencies,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Decodes exact RFC 8785 canonical bytes.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical or semantically invalid bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        snapshot.validate()?;
        if canonical_json_bytes(&snapshot)? != bytes {
            return Err(RuntimeError::NonCanonicalExternalDependencySnapshot);
        }
        Ok(snapshot)
    }

    /// Returns exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Refuses invalid snapshot content.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Returns the exact snapshot identity.
    ///
    /// # Errors
    ///
    /// Refuses invalid snapshot content.
    pub fn semantic_digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(semantic_digest(self)?)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != EXTERNAL_DEPENDENCY_SNAPSHOT_SCHEMA {
            return Err(RuntimeError::UnknownExternalDependencySnapshotSchema(
                self.schema.clone(),
            ));
        }
        let mut previous: Option<&RecordRef> = None;
        let mut receipts = BTreeSet::new();
        for dependency in &self.dependencies {
            if previous.is_some_and(|prior| prior >= &dependency.reference) {
                return Err(RuntimeError::ExternalDependencySnapshotNotCanonical);
            }
            if dependency.reference.schema.as_str() == PROVIDER_INTAKE_SCHEMA {
                return Err(RuntimeError::ProviderIntakeOffLedger);
            }
            if RuntimeSchema::parse(dependency.reference.schema.as_str()).is_ok() {
                return Err(RuntimeError::MaterializedRuntimeRecordOffLedger(
                    dependency.reference.schema.to_string(),
                ));
            }
            if !receipts.insert(&dependency.admission_receipt_id) {
                return Err(RuntimeError::ExternalDependencyReceiptReplay);
            }
            dependency.validate()?;
            previous = Some(&dependency.reference);
        }
        Ok(())
    }
}

/// Purpose for which one exact authority-bearing input was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAdmissionKind {
    /// A materialized `nq.operation_authorization.v1` was authenticated and
    /// admitted by an independent authority verifier.
    OperationAuthorization,
    /// The external authentication evidence named by one invocation request
    /// was independently verified for that request boundary.
    InvocationAuthentication,
}

/// One exact, independently supplied authority admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAdmission {
    /// Exact authority-bearing input admitted.
    pub reference: RecordRef,
    /// Closed admission purpose.
    pub kind: AuthorityAdmissionKind,
    /// Independent receipt identity.
    pub admission_receipt_id: Sha256Digest,
    /// Verifier that produced the admission.
    pub admitted_by: IdentityRef,
    /// Admission time.
    pub admitted_at: Timestamp,
}

/// Independently pinned authority-admission closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAdmissionSnapshot {
    /// Exact local carrier schema.
    pub schema: String,
    /// Strictly ordered exact admissions.
    pub admissions: Vec<AuthorityAdmission>,
}

impl AuthorityAdmissionSnapshot {
    /// Constructs a canonical authority snapshot.
    ///
    /// # Errors
    ///
    /// Refuses duplicates, unknown schemas, or purpose/schema mismatch.
    pub fn new(mut admissions: Vec<AuthorityAdmission>) -> Result<Self> {
        admissions.sort_by(|left, right| {
            left.reference
                .cmp(&right.reference)
                .then_with(|| admission_kind_rank(left.kind).cmp(&admission_kind_rank(right.kind)))
        });
        let snapshot = Self {
            schema: AUTHORITY_ADMISSION_SNAPSHOT_SCHEMA.to_owned(),
            admissions,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Decodes exact RFC 8785 canonical bytes.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical or semantically invalid bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        snapshot.validate()?;
        if canonical_json_bytes(&snapshot)? != bytes {
            return Err(RuntimeError::NonCanonicalAuthorityAdmissionSnapshot);
        }
        Ok(snapshot)
    }

    /// Returns exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Refuses invalid snapshot content.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Returns the exact snapshot identity.
    ///
    /// # Errors
    ///
    /// Refuses invalid snapshot content.
    pub fn semantic_digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(semantic_digest(self)?)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != AUTHORITY_ADMISSION_SNAPSHOT_SCHEMA {
            return Err(RuntimeError::UnknownAuthorityAdmissionSnapshotSchema(
                self.schema.clone(),
            ));
        }
        let mut previous: Option<(&RecordRef, u8)> = None;
        let mut receipts = BTreeSet::new();
        for admission in &self.admissions {
            let rank = admission_kind_rank(admission.kind);
            if previous.is_some_and(|(reference, previous_rank)| {
                (reference, previous_rank) >= (&admission.reference, rank)
            }) {
                return Err(RuntimeError::AuthorityAdmissionSnapshotNotCanonical);
            }
            let schema = admission.reference.schema.as_str();
            if (admission.kind == AuthorityAdmissionKind::OperationAuthorization
                && schema != RuntimeSchema::OperationAuthorizationV1.as_str())
                || (admission.kind == AuthorityAdmissionKind::InvocationAuthentication
                    && (RuntimeSchema::parse(schema).is_ok() || schema == PROVIDER_INTAKE_SCHEMA))
            {
                return Err(RuntimeError::AuthorityAdmissionKindMismatch);
            }
            if !receipts.insert(&admission.admission_receipt_id) {
                return Err(RuntimeError::AuthorityAdmissionReceiptReplay);
            }
            previous = Some((&admission.reference, rank));
        }
        Ok(())
    }
}

const fn admission_kind_rank(kind: AuthorityAdmissionKind) -> u8 {
    match kind {
        AuthorityAdmissionKind::OperationAuthorization => 0,
        AuthorityAdmissionKind::InvocationAuthentication => 1,
    }
}

/// Exact immutable identity of one complete runtime dependency generation.
///
/// The signed receipt set authenticates this carrier's semantic digest. The
/// carrier in turn binds every exact catalog/snapshot digest and the complete
/// verifier trust identity, avoiding a signature/generation digest cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDependencyGeneration {
    schema: String,
    identity_catalog_snapshot_digest: Sha256Digest,
    external_dependency_snapshot_digest: Sha256Digest,
    authority_admission_snapshot_digest: Sha256Digest,
    admission_receipt_manifest_digest: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    key_generation: IdentityRef,
    trust_policy: IdentityRef,
    verifier_generation: IdentityRef,
}

impl RuntimeDependencyGeneration {
    fn derive(
        catalog_snapshot: &CatalogSnapshot,
        external_snapshot: &ExternalDependencySnapshot,
        authority_snapshot: &AuthorityAdmissionSnapshot,
        anchor: &Ed25519TrustAnchor,
        admission_receipt_manifest_digest: Sha256Digest,
    ) -> Result<Self> {
        let generation = Self {
            schema: RUNTIME_DEPENDENCY_GENERATION_SCHEMA.to_owned(),
            identity_catalog_snapshot_digest: catalog_snapshot.semantic_digest()?,
            external_dependency_snapshot_digest: external_snapshot.semantic_digest()?,
            authority_admission_snapshot_digest: authority_snapshot.semantic_digest()?,
            admission_receipt_manifest_digest,
            trust_anchor_id: anchor.anchor_id()?,
            key_generation: anchor.key_generation.clone(),
            trust_policy: anchor.trust_policy.clone(),
            verifier_generation: anchor.verifier_generation.clone(),
        };
        generation.validate()?;
        Ok(generation)
    }

    /// Decodes exact canonical generation bytes.
    ///
    /// # Errors
    ///
    /// Refuses an unknown schema, wrong identity kinds, or noncanonical bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let generation: Self = serde_json::from_slice(bytes)?;
        generation.validate()?;
        if canonical_json_bytes(&generation)? != bytes {
            return Err(RuntimeError::NonCanonicalRuntimeDependencyGeneration);
        }
        Ok(generation)
    }

    /// Returns exact canonical generation bytes.
    ///
    /// # Errors
    ///
    /// Refuses invalid content or canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Returns the identity bound into runtime checkpoints.
    ///
    /// # Errors
    ///
    /// Refuses invalid content or canonicalization failure.
    pub fn generation_id(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(semantic_digest(self)?)
    }

    /// Returns the immutable bootstrap trust-anchor identity.
    #[must_use]
    pub const fn trust_anchor_id(&self) -> &Sha256Digest {
        &self.trust_anchor_id
    }

    /// Returns the exact verifier generation.
    #[must_use]
    pub const fn verifier_generation(&self) -> &IdentityRef {
        &self.verifier_generation
    }

    /// Returns the exact trust policy.
    #[must_use]
    pub const fn trust_policy(&self) -> &IdentityRef {
        &self.trust_policy
    }

    fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_DEPENDENCY_GENERATION_SCHEMA {
            return Err(RuntimeError::UnknownRuntimeDependencyGenerationSchema(
                self.schema.clone(),
            ));
        }
        self.key_generation.require_kind(
            IdentityKind::KeyGeneration,
            "dependency_generation.key_generation",
        )?;
        self.trust_policy
            .require_kind(IdentityKind::Policy, "dependency_generation.trust_policy")?;
        self.verifier_generation.require_kind(
            IdentityKind::Evaluator,
            "dependency_generation.verifier_generation",
        )?;
        Ok(())
    }
}

/// Cloneable exact custody closure sufficient to reopen one historical
/// dependency generation without consulting mutable current dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDependencyGenerationCustody {
    generation_id: Sha256Digest,
    generation_canonical_bytes: Vec<u8>,
    identity_catalog_canonical_bytes: Vec<u8>,
    external_dependency_canonical_bytes: Vec<u8>,
    authority_admission_canonical_bytes: Vec<u8>,
    trust_anchor_canonical_bytes: Vec<u8>,
    admission_receipt_set_canonical_bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDependencyGenerationCustodyCarrier {
    schema: String,
    generation_id: Sha256Digest,
    generation_canonical_bytes: String,
    identity_catalog_canonical_bytes: String,
    external_dependency_canonical_bytes: String,
    authority_admission_canonical_bytes: String,
    trust_anchor_canonical_bytes: String,
    admission_receipt_set_canonical_bytes: String,
}

impl RuntimeDependencyGenerationCustody {
    /// Decodes one exact canonical historical custody closure.
    ///
    /// Cryptographic authentication is deliberately deferred to
    /// [`Self::reopen`], which requires the separately persisted store
    /// bootstrap-root identity rather than the anchor selected by this
    /// closure or a caller's current generation.
    ///
    /// # Errors
    ///
    /// Refuses an unknown schema, noncanonical carrier, malformed hex, or
    /// generation/anchor substitution.
    pub fn decode_canonical_closure(bytes: &[u8]) -> Result<Self> {
        let carrier: RuntimeDependencyGenerationCustodyCarrier = serde_json::from_slice(bytes)?;
        if carrier.schema != RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA {
            return Err(
                RuntimeError::UnknownRuntimeDependencyGenerationCustodySchema(carrier.schema),
            );
        }
        let decode = |encoded: String| -> Result<Vec<u8>> {
            let decoded = hex::decode(&encoded)
                .map_err(|_| RuntimeError::RuntimeDependencyGenerationCustodyMalformed)?;
            if hex::encode(&decoded) != encoded {
                return Err(RuntimeError::RuntimeDependencyGenerationCustodyMalformed);
            }
            Ok(decoded)
        };
        let custody = Self {
            generation_id: carrier.generation_id,
            generation_canonical_bytes: decode(carrier.generation_canonical_bytes)?,
            identity_catalog_canonical_bytes: decode(carrier.identity_catalog_canonical_bytes)?,
            external_dependency_canonical_bytes: decode(
                carrier.external_dependency_canonical_bytes,
            )?,
            authority_admission_canonical_bytes: decode(
                carrier.authority_admission_canonical_bytes,
            )?,
            trust_anchor_canonical_bytes: decode(carrier.trust_anchor_canonical_bytes)?,
            admission_receipt_set_canonical_bytes: decode(
                carrier.admission_receipt_set_canonical_bytes,
            )?,
        };
        if custody.canonical_closure_bytes()? != bytes {
            return Err(RuntimeError::NonCanonicalRuntimeDependencyGenerationCustody);
        }
        let generation =
            RuntimeDependencyGeneration::decode_canonical(&custody.generation_canonical_bytes)?;
        if generation.generation_id()? != custody.generation_id
            || generation.trust_anchor_id() != &custody.trust_anchor_id()?
        {
            return Err(RuntimeError::RuntimeDependencyGenerationSubstitution);
        }
        Ok(custody)
    }

    /// Returns the immutable generation identity bound into checkpoints.
    #[must_use]
    pub const fn generation_id(&self) -> &Sha256Digest {
        &self.generation_id
    }

    /// Returns the exact generation carrier.
    #[must_use]
    pub fn generation_canonical_bytes(&self) -> &[u8] {
        &self.generation_canonical_bytes
    }

    /// Returns the exact identity-catalog carrier.
    #[must_use]
    pub fn identity_catalog_canonical_bytes(&self) -> &[u8] {
        &self.identity_catalog_canonical_bytes
    }

    /// Returns the exact external-dependency carrier.
    #[must_use]
    pub fn external_dependency_canonical_bytes(&self) -> &[u8] {
        &self.external_dependency_canonical_bytes
    }

    /// Returns the exact authority-admission carrier.
    #[must_use]
    pub fn authority_admission_canonical_bytes(&self) -> &[u8] {
        &self.authority_admission_canonical_bytes
    }

    /// Returns the exact immutable trust-anchor carrier.
    #[must_use]
    pub fn trust_anchor_canonical_bytes(&self) -> &[u8] {
        &self.trust_anchor_canonical_bytes
    }

    /// Returns the exact signed admission-receipt set.
    #[must_use]
    pub fn admission_receipt_set_canonical_bytes(&self) -> &[u8] {
        &self.admission_receipt_set_canonical_bytes
    }

    /// Returns the exact canonical closure carrier retained at every governed
    /// execution checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error only when canonicalization fails.
    pub fn canonical_closure_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(&serde_json::json!({
            "schema": RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA,
            "generation_id": self.generation_id,
            "generation_canonical_bytes": hex::encode(&self.generation_canonical_bytes),
            "identity_catalog_canonical_bytes": hex::encode(&self.identity_catalog_canonical_bytes),
            "external_dependency_canonical_bytes": hex::encode(&self.external_dependency_canonical_bytes),
            "authority_admission_canonical_bytes": hex::encode(&self.authority_admission_canonical_bytes),
            "trust_anchor_canonical_bytes": hex::encode(&self.trust_anchor_canonical_bytes),
            "admission_receipt_set_canonical_bytes": hex::encode(&self.admission_receipt_set_canonical_bytes),
        }))?)
    }

    /// Returns the exact byte commitment to the complete historical closure.
    ///
    /// # Errors
    ///
    /// Returns an error only when canonicalization fails.
    pub fn custody_digest(&self) -> Result<Sha256Digest> {
        Ok(sha256_bytes(&self.canonical_closure_bytes()?))
    }

    /// Returns the immutable trust-anchor identity carried by this closure.
    ///
    /// # Errors
    ///
    /// Refuses malformed or substituted generation bytes.
    pub fn trust_anchor_id(&self) -> Result<Sha256Digest> {
        let generation =
            RuntimeDependencyGeneration::decode_canonical(&self.generation_canonical_bytes)?;
        if generation.generation_id()? != self.generation_id {
            return Err(RuntimeError::RuntimeDependencyGenerationSubstitution);
        }
        Ok(generation.trust_anchor_id().clone())
    }

    /// Revalidates the complete exact closure against an independently retained
    /// expected trust-anchor identity.
    ///
    /// This is the historical checkpoint reopen boundary. It requires no
    /// mutable "current dependencies" input.
    ///
    /// # Errors
    ///
    /// Refuses any byte, identity, signature, receipt, or generation
    /// substitution.
    pub fn reopen(&self, expected_trust_anchor_id: &Sha256Digest) -> Result<RuntimeDependencies> {
        let anchor = Ed25519TrustAnchor::decode_expected(
            &self.trust_anchor_canonical_bytes,
            expected_trust_anchor_id,
        )?;
        let receipt_custody = AdmissionReceiptSetCustody {
            availability: AdmissionReceiptSetAvailability::Online,
            committed_bytes_digest: sha256_bytes(&self.admission_receipt_set_canonical_bytes),
            exact_bytes: Some(self.admission_receipt_set_canonical_bytes.clone()),
        };
        let dependencies = RuntimeDependencies::decode_authenticated(
            &self.identity_catalog_canonical_bytes,
            &self.external_dependency_canonical_bytes,
            &self.authority_admission_canonical_bytes,
            &anchor,
            &receipt_custody,
        )?;
        if dependencies.generation_id() != &self.generation_id
            || dependencies.generation.canonical_bytes()? != self.generation_canonical_bytes
        {
            return Err(RuntimeError::RuntimeDependencyGenerationSubstitution);
        }
        Ok(dependencies)
    }
}

/// Reopened, exact dependency closure used by the runtime.
#[derive(Debug, Clone)]
pub struct RuntimeDependencies {
    catalog_snapshot: CatalogSnapshot,
    external_snapshot: ExternalDependencySnapshot,
    authority_snapshot: AuthorityAdmissionSnapshot,
    generation: RuntimeDependencyGeneration,
    custody: RuntimeDependencyGenerationCustody,
    identity_catalog: IdentityCatalog,
    external_by_ref: BTreeMap<RecordRef, ExactExternalDependency>,
    authority_admissions: BTreeSet<(RecordRef, u8)>,
    binding_digest: Sha256Digest,
}

impl RuntimeDependencies {
    /// Authenticates and reopens one exact dependency generation.
    ///
    /// The supplied anchor is valid only as an explicit bootstrap input or
    /// after its identity has been checked against the separately persisted
    /// store bootstrap root. Existing stores must first use
    /// [`Ed25519TrustAnchor::decode_expected`]; callers may not select a fresh
    /// key while opening an existing ledger.
    ///
    /// # Errors
    ///
    /// Refuses unavailable signed receipts before parsing any caller snapshot
    /// or attempting cryptographic verification, then refuses noncanonical
    /// content, signature or receipt
    /// substitution, incomplete receipt coverage, unadmitted verifier
    /// identities, and invalid catalogs.
    pub fn decode_authenticated(
        identity_catalog_bytes: &[u8],
        external_dependency_bytes: &[u8],
        authority_admission_bytes: &[u8],
        trust_anchor: &Ed25519TrustAnchor,
        receipt_custody: &AdmissionReceiptSetCustody,
    ) -> Result<Self> {
        let receipt_set_bytes = receipt_custody.exact_bytes()?;
        let catalog_snapshot = CatalogSnapshot::decode_canonical(identity_catalog_bytes)?;
        let external_snapshot =
            ExternalDependencySnapshot::decode_canonical(external_dependency_bytes)?;
        let authority_snapshot =
            AuthorityAdmissionSnapshot::decode_canonical(authority_admission_bytes)?;
        let identity_catalog = IdentityCatalog::from_snapshot(&catalog_snapshot)?;
        identity_catalog.resolve(trust_anchor.key_generation())?;
        identity_catalog.resolve(trust_anchor.trust_policy())?;
        identity_catalog.resolve(trust_anchor.verifier_generation())?;
        for dependency in &external_snapshot.dependencies {
            identity_catalog.resolve(&dependency.admitted_by)?;
        }
        for admission in &authority_snapshot.admissions {
            identity_catalog.resolve(&admission.admitted_by)?;
        }
        let receipt_set = SignedAdmissionReceiptSet::decode_canonical(receipt_set_bytes)?;
        let generation = RuntimeDependencyGeneration::derive(
            &catalog_snapshot,
            &external_snapshot,
            &authority_snapshot,
            trust_anchor,
            receipt_set.manifest_digest()?,
        )?;
        receipt_set.verify(trust_anchor, &generation)?;
        for receipt in receipt_set.receipts() {
            identity_catalog.resolve(&receipt.admitted_by)?;
        }
        verify_receipt_coverage(&external_snapshot, &authority_snapshot, &receipt_set)?;

        let external_by_ref = external_snapshot
            .dependencies
            .iter()
            .cloned()
            .map(|dependency| (dependency.reference.clone(), dependency))
            .collect();
        let authority_admissions = authority_snapshot
            .admissions
            .iter()
            .map(|admission| {
                (
                    admission.reference.clone(),
                    admission_kind_rank(admission.kind),
                )
            })
            .collect();
        let generation_canonical_bytes = generation.canonical_bytes()?;
        let binding_digest = generation.generation_id()?;
        let custody = RuntimeDependencyGenerationCustody {
            generation_id: binding_digest.clone(),
            generation_canonical_bytes,
            identity_catalog_canonical_bytes: identity_catalog_bytes.to_vec(),
            external_dependency_canonical_bytes: external_dependency_bytes.to_vec(),
            authority_admission_canonical_bytes: authority_admission_bytes.to_vec(),
            trust_anchor_canonical_bytes: trust_anchor.canonical_bytes()?,
            admission_receipt_set_canonical_bytes: receipt_set_bytes.to_vec(),
        };
        Ok(Self {
            catalog_snapshot,
            external_snapshot,
            authority_snapshot,
            generation,
            custody,
            identity_catalog,
            external_by_ref,
            authority_admissions,
            binding_digest,
        })
    }

    /// Returns the complete immutable dependency-generation identity.
    #[must_use]
    pub const fn generation_id(&self) -> &Sha256Digest {
        &self.binding_digest
    }

    /// Returns the exact dependency-generation carrier.
    #[must_use]
    pub const fn generation(&self) -> &RuntimeDependencyGeneration {
        &self.generation
    }

    /// Returns exact custody sufficient for historical reopen.
    #[must_use]
    pub const fn custody(&self) -> &RuntimeDependencyGenerationCustody {
        &self.custody
    }

    /// Returns the combined dependency identity.
    #[must_use]
    pub const fn binding_digest(&self) -> &Sha256Digest {
        &self.binding_digest
    }

    /// Returns the admitted identity catalog carrier.
    #[must_use]
    pub const fn catalog_snapshot(&self) -> &CatalogSnapshot {
        &self.catalog_snapshot
    }

    /// Returns exact external dependency custody.
    #[must_use]
    pub const fn external_dependency_snapshot(&self) -> &ExternalDependencySnapshot {
        &self.external_snapshot
    }

    /// Returns independently admitted authority inputs.
    #[must_use]
    pub const fn authority_admission_snapshot(&self) -> &AuthorityAdmissionSnapshot {
        &self.authority_snapshot
    }

    pub(crate) fn validate_graph_dependencies(&self, records: &RuntimeRecordSet) -> Result<()> {
        for record in records.records() {
            let value = record.record().as_value();
            let mut references = Vec::new();
            let mut identities = Vec::new();
            collect_record_references(value, &mut references)?;
            collect_identity_references(value, &mut identities)?;
            for identity in identities {
                self.identity_catalog.resolve(&identity)?;
            }
            for reference in references {
                if RuntimeSchema::parse(reference.schema.as_str()).is_ok()
                    || reference.schema.as_str() == PROVIDER_INTAKE_SCHEMA
                {
                    continue;
                }
                match self.external_by_ref.get(&reference) {
                    Some(dependency) if dependency.is_available() => {}
                    Some(_) => {
                        return Err(RuntimeError::ExternalDependencyUnavailable(
                            reference.record_id.to_string(),
                        ));
                    }
                    None => {
                        return Err(RuntimeError::ExternalDependencyMissing(
                            reference.record_id.to_string(),
                        ));
                    }
                }
            }
            if record.schema() == RuntimeSchema::OperationAuthorizationV1
                && !self.authority_admissions.contains(&(
                    record.exact_reference(),
                    admission_kind_rank(AuthorityAdmissionKind::OperationAuthorization),
                ))
            {
                return Err(RuntimeError::AuthorityRecordNotAdmitted(
                    record.record_id().to_string(),
                ));
            }
            if record.schema() == RuntimeSchema::DiagnosticInvocationRequestV1 {
                let authentication: RecordRef =
                    serde_json::from_value(value["authentication_evidence"].clone())?;
                if !self.authority_admissions.contains(&(
                    authentication.clone(),
                    admission_kind_rank(AuthorityAdmissionKind::InvocationAuthentication),
                )) {
                    return Err(RuntimeError::AuthenticationEvidenceNotAdmitted(
                        authentication.record_id.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn verify_receipt_coverage(
    external_snapshot: &ExternalDependencySnapshot,
    authority_snapshot: &AuthorityAdmissionSnapshot,
    receipt_set: &SignedAdmissionReceiptSet,
) -> Result<()> {
    let mut receipts_by_id = BTreeMap::new();
    for receipt in receipt_set.receipts() {
        let receipt_id = receipt.receipt_id()?;
        if receipts_by_id.insert(receipt_id, receipt).is_some() {
            return Err(RuntimeError::AdmissionReceiptReplay);
        }
    }

    let mut matched = BTreeSet::new();
    for dependency in &external_snapshot.dependencies {
        let receipt = receipts_by_id
            .get(&dependency.admission_receipt_id)
            .ok_or(RuntimeError::DependencyAdmissionReceiptMissing)?;
        if receipt.reference != dependency.reference
            || receipt.kind != DependencyAdmissionKind::ExternalDependency
            || receipt.admitted_by != dependency.admitted_by
            || receipt.admitted_at != dependency.admitted_at
        {
            return Err(RuntimeError::DependencyAdmissionReceiptSubstitution);
        }
        matched.insert(dependency.admission_receipt_id.clone());
    }
    for admission in &authority_snapshot.admissions {
        let receipt = receipts_by_id
            .get(&admission.admission_receipt_id)
            .ok_or(RuntimeError::DependencyAdmissionReceiptMissing)?;
        let expected_kind = match admission.kind {
            AuthorityAdmissionKind::OperationAuthorization => {
                DependencyAdmissionKind::OperationAuthorization
            }
            AuthorityAdmissionKind::InvocationAuthentication => {
                DependencyAdmissionKind::InvocationAuthentication
            }
        };
        if receipt.reference != admission.reference
            || receipt.kind != expected_kind
            || receipt.admitted_by != admission.admitted_by
            || receipt.admitted_at != admission.admitted_at
        {
            return Err(RuntimeError::DependencyAdmissionReceiptSubstitution);
        }
        matched.insert(admission.admission_receipt_id.clone());
    }
    if matched.len() != receipts_by_id.len() {
        return Err(RuntimeError::ExtraneousDependencyAdmissionReceipt);
    }
    Ok(())
}

fn decode_exact_hex<const N: usize>(
    encoded: &str,
    malformed: impl Fn() -> RuntimeError,
) -> Result<[u8; N]> {
    let bytes = hex::decode(encoded).map_err(|_| malformed())?;
    if bytes.len() != N || hex::encode(&bytes) != encoded {
        return Err(malformed());
    }
    bytes.try_into().map_err(|_| malformed())
}

fn collect_identity_references(
    value: &serde_json::Value,
    identities: &mut Vec<IdentityRef>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                identities.push(serde_json::from_value(value.clone())?);
            } else {
                for child in object.values() {
                    collect_identity_references(child, identities)?;
                }
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                collect_identity_references(child, identities)?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

fn collect_record_references(
    value: &serde_json::Value,
    references: &mut Vec<RecordRef>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                references.push(serde_json::from_value(value.clone())?);
            } else {
                for child in object.values() {
                    collect_record_references(child, references)?;
                }
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                collect_record_references(child, references)?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use nq_host_role_contract::{
        Generation, IdentityCatalog, IdentityId, IdentityVersion, NamespaceId, NamespaceSnapshot,
        NamespaceVersion, Token,
    };

    use super::*;

    pub(crate) struct Fixture {
        anchor: Ed25519TrustAnchor,
        catalog_bytes: Vec<u8>,
        external_bytes: Vec<u8>,
        authority_bytes: Vec<u8>,
        receipt_set: SignedAdmissionReceiptSet,
    }

    impl Fixture {
        pub(crate) fn decode(&self) -> Result<RuntimeDependencies> {
            RuntimeDependencies::decode_authenticated(
                &self.catalog_bytes,
                &self.external_bytes,
                &self.authority_bytes,
                &self.anchor,
                &AdmissionReceiptSetCustody::available(
                    AdmissionReceiptSetAvailability::Online,
                    self.receipt_set.canonical_bytes()?,
                )?,
            )
        }
    }

    fn identity(kind: IdentityKind, id: &str) -> IdentityRef {
        IdentityRef {
            kind,
            id: IdentityId::parse(id).expect("fixture identity"),
            version: IdentityVersion::parse("v1").expect("fixture version"),
            descriptor_digest: sha256_bytes(format!("{kind:?}:{id}:v1").as_bytes()),
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        Timestamp::parse(value).expect("fixture timestamp")
    }

    fn record_ref(schema: &str, bytes: &[u8]) -> RecordRef {
        RecordRef {
            schema: Token::parse(schema).expect("fixture schema"),
            record_id: semantic_digest(&serde_json::json!({
                "schema": schema,
                "payload": hex::encode(bytes),
            }))
            .expect("fixture record identity"),
            bytes_digest: sha256_bytes(bytes),
        }
    }

    #[allow(clippy::too_many_lines)] // One closed cryptographic fixture is easier to audit in one place.
    pub(crate) fn fixture(seed: u8) -> Fixture {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let key_generation = identity(IdentityKind::KeyGeneration, "key/dependency-root");
        let trust_policy = identity(IdentityKind::Policy, "policy/dependency-admission");
        let verifier_generation = identity(IdentityKind::Evaluator, "evaluator/admission-primary");
        let alternate_verifier = identity(IdentityKind::Evaluator, "evaluator/admission-alternate");
        let anchor = Ed25519TrustAnchor::fixture(
            key_generation.clone(),
            trust_policy.clone(),
            verifier_generation.clone(),
            &signing_key.verifying_key(),
        )
        .expect("fixture anchor");

        let mut identities = IdentityCatalog::new();
        for admitted in [
            key_generation,
            trust_policy,
            verifier_generation.clone(),
            alternate_verifier,
        ] {
            identities.insert(admitted).expect("fixture catalog");
        }
        let catalog = identities.snapshot(NamespaceSnapshot {
            namespace_id: NamespaceId::Production,
            namespace_version: NamespaceVersion::V1,
            catalog_generation: Generation::parse("1").expect("fixture generation"),
            catalog_id: sha256_bytes(b"fixture catalog generation one"),
        });

        let admitted_at = timestamp("2026-07-29T17:00:00-04:00");
        let external_bytes = b"exact external diagnostic input";
        let external_reference = record_ref("example.external_observation.v1", external_bytes);
        let external_receipt = DependencyAdmissionReceipt {
            reference: external_reference.clone(),
            kind: DependencyAdmissionKind::ExternalDependency,
            admitted_by: verifier_generation.clone(),
            admitted_at: admitted_at.clone(),
        };
        let external_snapshot = ExternalDependencySnapshot::new(vec![ExactExternalDependency {
            reference: external_reference,
            exact_bytes_hex: Some(hex::encode(external_bytes)),
            availability: ExternalDependencyAvailability::Online,
            admission_receipt_id: external_receipt
                .receipt_id()
                .expect("external receipt identity"),
            admitted_by: verifier_generation.clone(),
            admitted_at: admitted_at.clone(),
        }])
        .expect("external snapshot");

        let operation_reference = record_ref(
            RuntimeSchema::OperationAuthorizationV1.as_str(),
            b"exact operation authorization",
        );
        let operation_receipt = DependencyAdmissionReceipt {
            reference: operation_reference.clone(),
            kind: DependencyAdmissionKind::OperationAuthorization,
            admitted_by: verifier_generation.clone(),
            admitted_at: admitted_at.clone(),
        };
        let authentication_reference = record_ref(
            "example.invocation_authentication.v1",
            b"exact authentication",
        );
        let authentication_receipt = DependencyAdmissionReceipt {
            reference: authentication_reference.clone(),
            kind: DependencyAdmissionKind::InvocationAuthentication,
            admitted_by: verifier_generation.clone(),
            admitted_at: admitted_at.clone(),
        };
        let authority_snapshot = AuthorityAdmissionSnapshot::new(vec![
            AuthorityAdmission {
                reference: operation_reference,
                kind: AuthorityAdmissionKind::OperationAuthorization,
                admission_receipt_id: operation_receipt
                    .receipt_id()
                    .expect("operation receipt identity"),
                admitted_by: verifier_generation.clone(),
                admitted_at: admitted_at.clone(),
            },
            AuthorityAdmission {
                reference: authentication_reference,
                kind: AuthorityAdmissionKind::InvocationAuthentication,
                admission_receipt_id: authentication_receipt
                    .receipt_id()
                    .expect("authentication receipt identity"),
                admitted_by: verifier_generation,
                admitted_at,
            },
        ])
        .expect("authority snapshot");

        let signed_at = timestamp("2026-07-29T17:01:00-04:00");
        let receipts = vec![external_receipt, operation_receipt, authentication_receipt];
        let receipt_manifest_digest =
            SignedAdmissionReceiptSet::fixture_manifest_digest(&anchor, &signed_at, &receipts)
                .expect("receipt manifest");
        let generation = RuntimeDependencyGeneration::derive(
            &catalog,
            &external_snapshot,
            &authority_snapshot,
            &anchor,
            receipt_manifest_digest,
        )
        .expect("dependency generation");
        let receipt_set = SignedAdmissionReceiptSet::fixture_signed(
            &generation,
            &anchor,
            signed_at,
            receipts,
            &signing_key,
        )
        .expect("signed receipt set");

        Fixture {
            anchor,
            catalog_bytes: catalog.canonical_bytes().expect("catalog bytes"),
            external_bytes: external_snapshot.canonical_bytes().expect("external bytes"),
            authority_bytes: authority_snapshot
                .canonical_bytes()
                .expect("authority bytes"),
            receipt_set,
        }
    }

    #[allow(clippy::too_many_lines)] // One signed closed-set fixture is easier to audit in one place.
    pub(crate) fn authenticated_runtime_fixture(
        seed: u8,
        mut runtime_identities: Vec<IdentityRef>,
        external_inputs: Vec<(RecordRef, Vec<u8>)>,
        operation_authorizations: Vec<RecordRef>,
        invocation_authentication: Vec<RecordRef>,
    ) -> RuntimeDependencies {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let key_generation = identity(IdentityKind::KeyGeneration, "key/runtime-fixture-root");
        let trust_policy = identity(IdentityKind::Policy, "policy/runtime-fixture-admission");
        let verifier_generation = identity(
            IdentityKind::Evaluator,
            "evaluator/runtime-fixture-admission",
        );
        let anchor = Ed25519TrustAnchor::fixture(
            key_generation.clone(),
            trust_policy.clone(),
            verifier_generation.clone(),
            &signing_key.verifying_key(),
        )
        .expect("runtime fixture anchor");
        runtime_identities.extend([key_generation, trust_policy, verifier_generation.clone()]);
        runtime_identities.sort();
        runtime_identities.dedup();
        let mut identity_catalog = IdentityCatalog::new();
        for identity in runtime_identities {
            identity_catalog
                .insert(identity)
                .expect("runtime fixture identity");
        }
        let catalog = identity_catalog.snapshot(NamespaceSnapshot {
            namespace_id: NamespaceId::Production,
            namespace_version: NamespaceVersion::V1,
            catalog_generation: Generation::parse("1").expect("fixture generation"),
            catalog_id: sha256_bytes(b"runtime fixture catalog"),
        });
        let admitted_at = timestamp("2026-07-29T17:00:00-04:00");

        let mut receipts = Vec::new();
        let external = external_inputs
            .into_iter()
            .map(|(reference, exact_bytes)| {
                let receipt = DependencyAdmissionReceipt {
                    reference: reference.clone(),
                    kind: DependencyAdmissionKind::ExternalDependency,
                    admitted_by: verifier_generation.clone(),
                    admitted_at: admitted_at.clone(),
                };
                receipts.push(receipt.clone());
                ExactExternalDependency {
                    reference,
                    exact_bytes_hex: Some(hex::encode(exact_bytes)),
                    availability: ExternalDependencyAvailability::Online,
                    admission_receipt_id: receipt.receipt_id().expect("receipt identity"),
                    admitted_by: verifier_generation.clone(),
                    admitted_at: admitted_at.clone(),
                }
            })
            .collect();
        let external_snapshot =
            ExternalDependencySnapshot::new(external).expect("runtime external snapshot");

        let mut admissions = Vec::new();
        for (reference, kind, receipt_kind) in operation_authorizations
            .into_iter()
            .map(|reference| {
                (
                    reference,
                    AuthorityAdmissionKind::OperationAuthorization,
                    DependencyAdmissionKind::OperationAuthorization,
                )
            })
            .chain(invocation_authentication.into_iter().map(|reference| {
                (
                    reference,
                    AuthorityAdmissionKind::InvocationAuthentication,
                    DependencyAdmissionKind::InvocationAuthentication,
                )
            }))
        {
            let receipt = DependencyAdmissionReceipt {
                reference: reference.clone(),
                kind: receipt_kind,
                admitted_by: verifier_generation.clone(),
                admitted_at: admitted_at.clone(),
            };
            receipts.push(receipt.clone());
            admissions.push(AuthorityAdmission {
                reference,
                kind,
                admission_receipt_id: receipt.receipt_id().expect("receipt identity"),
                admitted_by: verifier_generation.clone(),
                admitted_at: admitted_at.clone(),
            });
        }
        let authority_snapshot =
            AuthorityAdmissionSnapshot::new(admissions).expect("runtime authority snapshot");
        let signed_at = timestamp("2026-07-29T17:00:01-04:00");
        let manifest_digest =
            SignedAdmissionReceiptSet::fixture_manifest_digest(&anchor, &signed_at, &receipts)
                .expect("runtime manifest");
        let generation = RuntimeDependencyGeneration::derive(
            &catalog,
            &external_snapshot,
            &authority_snapshot,
            &anchor,
            manifest_digest,
        )
        .expect("runtime generation");
        let receipt_set = SignedAdmissionReceiptSet::fixture_signed(
            &generation,
            &anchor,
            signed_at,
            receipts,
            &signing_key,
        )
        .expect("runtime receipts");
        RuntimeDependencies::decode_authenticated(
            &catalog.canonical_bytes().expect("catalog bytes"),
            &external_snapshot.canonical_bytes().expect("external bytes"),
            &authority_snapshot
                .canonical_bytes()
                .expect("authority bytes"),
            &anchor,
            &AdmissionReceiptSetCustody::available(
                AdmissionReceiptSetAvailability::Online,
                receipt_set.canonical_bytes().expect("receipt bytes"),
            )
            .expect("receipt custody"),
        )
        .expect("authenticated runtime dependencies")
    }

    #[test]
    fn authenticated_dependencies_reopen_from_exact_generation_custody() {
        let fixture = fixture(7);
        let dependencies = fixture.decode().expect("authenticated dependencies");
        let generation_id = dependencies.generation_id().clone();
        let custody = dependencies.custody().clone();

        let reopened = custody
            .reopen(&fixture.anchor.anchor_id().expect("anchor identity"))
            .expect("historical exact reopen");

        assert_eq!(reopened.generation_id(), &generation_id);
        assert_eq!(reopened.custody(), &custody);
        assert_eq!(
            RuntimeDependencyGeneration::decode_canonical(custody.generation_canonical_bytes())
                .expect("generation carrier")
                .generation_id()
                .expect("generation identity"),
            generation_id
        );
    }

    #[test]
    fn attacker_self_signed_catalog_and_pin_cannot_replace_stored_anchor() {
        let legitimate = fixture(7);
        let attacker = fixture(19);
        let expected_anchor_id = legitimate.anchor.anchor_id().expect("legitimate anchor");

        let error = Ed25519TrustAnchor::decode_expected(
            &attacker
                .anchor
                .canonical_bytes()
                .expect("attacker anchor bytes"),
            &expected_anchor_id,
        )
        .expect_err("another self-issued root must not open an existing store");
        assert!(matches!(
            error,
            RuntimeError::DependencyTrustAnchorSubstitution { .. }
        ));

        let attacker_receipts = AdmissionReceiptSetCustody::available(
            AdmissionReceiptSetAvailability::Online,
            attacker
                .receipt_set
                .canonical_bytes()
                .expect("attacker receipt bytes"),
        )
        .expect("attacker receipt custody");
        let error = RuntimeDependencies::decode_authenticated(
            &legitimate.catalog_bytes,
            &legitimate.external_bytes,
            &legitimate.authority_bytes,
            &legitimate.anchor,
            &attacker_receipts,
        )
        .expect_err("self-derived pin and receipt set cannot replace signed trust");
        assert!(matches!(
            error,
            RuntimeError::AdmissionReceiptSetBindingMismatch
                | RuntimeError::AdmissionReceiptSetSignatureInvalid
        ));
    }

    #[test]
    fn receipt_reference_verifier_and_time_substitution_all_fail_authentication() {
        let fixture = fixture(7);
        let alternate_verifier = identity(IdentityKind::Evaluator, "evaluator/admission-alternate");

        let mut hostile_sets = Vec::new();

        let mut changed_reference = fixture.receipt_set.clone();
        changed_reference.receipts[0].reference =
            record_ref("example.external_observation.v1", b"substituted input");
        changed_reference.receipts.sort();
        hostile_sets.push(changed_reference);

        let mut changed_verifier = fixture.receipt_set.clone();
        changed_verifier.receipts[0].admitted_by = alternate_verifier;
        changed_verifier.receipts.sort();
        hostile_sets.push(changed_verifier);

        let mut changed_time = fixture.receipt_set.clone();
        changed_time.receipts[0].admitted_at = timestamp("2026-07-29T17:00:01-04:00");
        changed_time.receipts.sort();
        hostile_sets.push(changed_time);

        for hostile in hostile_sets {
            let custody = AdmissionReceiptSetCustody::available(
                AdmissionReceiptSetAvailability::Online,
                hostile.canonical_bytes().expect("canonical hostile bytes"),
            )
            .expect("hostile custody");
            let error = RuntimeDependencies::decode_authenticated(
                &fixture.catalog_bytes,
                &fixture.external_bytes,
                &fixture.authority_bytes,
                &fixture.anchor,
                &custody,
            )
            .expect_err("changing any signed receipt field must fail");
            assert!(matches!(
                error,
                RuntimeError::AdmissionReceiptSetBindingMismatch
                    | RuntimeError::AdmissionReceiptSetSignatureInvalid
            ));
        }
    }

    #[test]
    fn unavailable_receipt_custody_refuses_before_parsing_or_verifying() {
        let fixture = fixture(7);
        let custody =
            AdmissionReceiptSetCustody::committed_unavailable(sha256_bytes(b"sealed elsewhere"));
        let error = RuntimeDependencies::decode_authenticated(
            b"not a catalog",
            b"not external dependencies",
            b"not authority admissions",
            &fixture.anchor,
            &custody,
        )
        .expect_err("unavailable signed evidence must refuse first");
        assert!(matches!(
            error,
            RuntimeError::AdmissionReceiptSetUnavailable
        ));
    }

    #[test]
    fn retrieved_receipt_bytes_must_match_committed_custody_digest() {
        let fixture = fixture(7);
        let error = AdmissionReceiptSetCustody::retrieved(
            AdmissionReceiptSetAvailability::ArchivedRetrieved,
            fixture
                .receipt_set
                .canonical_bytes()
                .expect("fixture receipt bytes"),
            sha256_bytes(b"another committed object"),
        )
        .expect_err("retrieval substitution must refuse before decode");
        assert!(matches!(
            error,
            RuntimeError::AdmissionReceiptSetByteSubstitution
        ));
    }

    #[test]
    fn receipt_set_cannot_be_extended_after_signature() {
        let fixture = fixture(7);
        let mut hostile = fixture.receipt_set.clone();
        let extra = DependencyAdmissionReceipt {
            reference: record_ref("example.extra.v1", b"extra"),
            kind: DependencyAdmissionKind::ExternalDependency,
            admitted_by: fixture.anchor.verifier_generation().clone(),
            admitted_at: timestamp("2026-07-29T17:00:02-04:00"),
        };
        hostile.receipts.push(extra);
        hostile.receipts.sort();
        let custody = AdmissionReceiptSetCustody::available(
            AdmissionReceiptSetAvailability::Online,
            hostile.canonical_bytes().expect("canonical hostile bytes"),
        )
        .expect("hostile custody");
        let error = RuntimeDependencies::decode_authenticated(
            &fixture.catalog_bytes,
            &fixture.external_bytes,
            &fixture.authority_bytes,
            &fixture.anchor,
            &custody,
        )
        .expect_err("closed set extension must fail");
        assert!(matches!(
            error,
            RuntimeError::AdmissionReceiptSetBindingMismatch
                | RuntimeError::AdmissionReceiptSetSignatureInvalid
        ));
    }

    #[test]
    fn even_validly_signed_extraneous_receipt_is_not_in_the_closed_snapshots() {
        let fixture = fixture(7);
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let catalog =
            CatalogSnapshot::decode_canonical(&fixture.catalog_bytes).expect("fixture catalog");
        let external = ExternalDependencySnapshot::decode_canonical(&fixture.external_bytes)
            .expect("fixture external snapshot");
        let authority = AuthorityAdmissionSnapshot::decode_canonical(&fixture.authority_bytes)
            .expect("fixture authority snapshot");
        let signed_at = timestamp("2026-07-29T17:01:00-04:00");
        let mut receipts = fixture.receipt_set.receipts.clone();
        receipts.push(DependencyAdmissionReceipt {
            reference: record_ref("example.extra.v1", b"extra"),
            kind: DependencyAdmissionKind::ExternalDependency,
            admitted_by: fixture.anchor.verifier_generation().clone(),
            admitted_at: timestamp("2026-07-29T17:00:02-04:00"),
        });
        receipts.sort();
        let manifest = SignedAdmissionReceiptSet::fixture_manifest_digest(
            &fixture.anchor,
            &signed_at,
            &receipts,
        )
        .expect("hostile manifest");
        let generation = RuntimeDependencyGeneration::derive(
            &catalog,
            &external,
            &authority,
            &fixture.anchor,
            manifest,
        )
        .expect("hostile generation");
        let signed = SignedAdmissionReceiptSet::fixture_signed(
            &generation,
            &fixture.anchor,
            signed_at,
            receipts,
            &signing_key,
        )
        .expect("valid hostile signature");
        let custody = AdmissionReceiptSetCustody::available(
            AdmissionReceiptSetAvailability::Online,
            signed.canonical_bytes().expect("hostile bytes"),
        )
        .expect("hostile custody");

        let error = RuntimeDependencies::decode_authenticated(
            &fixture.catalog_bytes,
            &fixture.external_bytes,
            &fixture.authority_bytes,
            &fixture.anchor,
            &custody,
        )
        .expect_err("signed receipts remain a closed snapshot closure");
        assert!(matches!(
            error,
            RuntimeError::ExtraneousDependencyAdmissionReceipt
        ));
    }

    #[test]
    fn wrong_key_cannot_sign_the_legitimate_generation() {
        let fixture = fixture(7);
        let dependencies = fixture.decode().expect("authenticated dependencies");
        let attacker_key = SigningKey::from_bytes(&[19; 32]);
        let attacker_set = SignedAdmissionReceiptSet::fixture_signed(
            dependencies.generation(),
            &fixture.anchor,
            timestamp("2026-07-29T17:01:00-04:00"),
            fixture.receipt_set.receipts.clone(),
            &attacker_key,
        )
        .expect("structurally valid attacker set");
        let custody = AdmissionReceiptSetCustody::available(
            AdmissionReceiptSetAvailability::Online,
            attacker_set.canonical_bytes().expect("attacker bytes"),
        )
        .expect("attacker custody");
        let error = RuntimeDependencies::decode_authenticated(
            &fixture.catalog_bytes,
            &fixture.external_bytes,
            &fixture.authority_bytes,
            &fixture.anchor,
            &custody,
        )
        .expect_err("wrong key cannot mint receipts under stored anchor");
        assert!(matches!(
            error,
            RuntimeError::AdmissionReceiptSetSignatureInvalid
        ));
    }
}
