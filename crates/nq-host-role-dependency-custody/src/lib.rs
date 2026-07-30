#![forbid(unsafe_code)]

//! Pure authentication and exact-source resolution for retained host-role
//! dependency custody.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use nq_host_role_contract::{
    CatalogSnapshot, IdentityCatalog, IdentityKind, IdentityRef, RecordRef, RuntimeRecordSet,
    RuntimeSchema, Timestamp,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};

use thiserror::Error;

/// Result returned by the pure dependency-custody boundary.
pub type Result<T> = std::result::Result<T, DependencyCustodyError>;

/// Closed refusal vocabulary for exact dependency-custody authentication and
/// source resolution.
#[derive(Debug, Error)]
pub enum DependencyCustodyError {
    /// A contract-owned identity, record, or catalog refused the input.
    #[error("host-role contract refusal: {0}")]
    Contract(#[from] nq_host_role_contract::ContractError),
    /// JSON decoding failed at an exact custody boundary.
    #[error("invalid dependency-custody JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Canonical JSON construction failed.
    #[error("dependency-custody canonicalization failed: {0}")]
    Canonicalization(#[from] nq_protocol::CanonicalizationError),
    /// External-dependency snapshot bytes were not canonical.
    #[error("external-dependency snapshot bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalExternalDependencySnapshot,
    /// External-dependency snapshot schema was unsupported.
    #[error("unsupported external-dependency snapshot schema {0}")]
    UnknownExternalDependencySnapshotSchema(String),
    /// External dependencies were not unique and strictly ordered.
    #[error("external-dependency snapshot is not in strict canonical order")]
    ExternalDependencySnapshotNotCanonical,
    /// Authority-admission snapshot bytes were not canonical.
    #[error("authority-admission snapshot bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalAuthorityAdmissionSnapshot,
    /// Authority-admission snapshot schema was unsupported.
    #[error("unsupported authority-admission snapshot schema {0}")]
    UnknownAuthorityAdmissionSnapshotSchema(String),
    /// Authority admissions were not unique and strictly ordered.
    #[error("authority-admission snapshot is not in strict canonical order")]
    AuthorityAdmissionSnapshotNotCanonical,
    /// A runtime record was incorrectly placed in the external closure.
    #[error("contract runtime record {0} must be materialized in the runtime ledger")]
    MaterializedRuntimeRecordOffLedger(String),
    /// Provider intake was incorrectly placed in the external closure.
    #[error("nq.provider_intake.v1 must be materialized in the runtime ledger")]
    ProviderIntakeOffLedger,
    /// Exact dependency bytes were malformed or noncanonical hex.
    #[error("external dependency exact bytes are not canonical lowercase hexadecimal")]
    ExternalDependencyBytesMalformed,
    /// Availability and exact-byte presence disagreed.
    #[error("external dependency availability disagrees with exact-byte custody")]
    ExternalDependencyAvailabilityMismatch,
    /// Exact bytes disagreed with their reference.
    #[error("external dependency {0} exact bytes differ from its reference")]
    ExternalDependencyByteSubstitution(String),
    /// An external admission receipt was replayed.
    #[error("external dependency admission receipt was replayed")]
    ExternalDependencyReceiptReplay,
    /// A required external dependency was absent.
    #[error("external dependency {0} is absent from the pinned closure")]
    ExternalDependencyMissing(String),
    /// A required dependency was committed but unavailable.
    #[error("external dependency {0} exact bytes are currently unavailable")]
    ExternalDependencyUnavailable(String),
    /// An authority admission purpose did not match its record schema.
    #[error("authority admission purpose does not match its record schema")]
    AuthorityAdmissionKindMismatch,
    /// An authority admission receipt was replayed.
    #[error("authority admission receipt was replayed")]
    AuthorityAdmissionReceiptReplay,
    /// An operation authorization lacked its exact admission.
    #[error("operation authorization {0} was not independently admitted")]
    AuthorityRecordNotAdmitted(String),
    /// Invocation authentication evidence lacked its exact admission.
    #[error("invocation authentication evidence {0} was not independently admitted")]
    AuthenticationEvidenceNotAdmitted(String),
    /// Trust-anchor bytes were not canonical.
    #[error("dependency trust-anchor bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalDependencyTrustAnchor,
    /// The trust-anchor schema was unsupported.
    #[error("unsupported dependency trust-anchor schema {0}")]
    UnknownDependencyTrustAnchorSchema(String),
    /// The Ed25519 public key was malformed.
    #[error("dependency trust-anchor Ed25519 public key is malformed")]
    DependencyTrustAnchorPublicKeyMalformed,
    /// The custody-selected root differed from the expected root.
    #[error("dependency trust anchor differs: expected {expected}, observed {observed}")]
    DependencyTrustAnchorSubstitution {
        /// Independently required trust root.
        expected: Sha256Digest,
        /// Trust root observed in custody.
        observed: Sha256Digest,
    },
    /// Signed receipt-set bytes were not canonical.
    #[error("admission receipt-set bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalAdmissionReceiptSet,
    /// The receipt-set schema was unsupported.
    #[error("unsupported admission receipt-set schema {0}")]
    UnknownAdmissionReceiptSetSchema(String),
    /// Admission receipts were duplicated or unordered.
    #[error("admission receipt set is not in strict canonical order")]
    AdmissionReceiptSetNotCanonical,
    /// A signed admission receipt identity was replayed.
    #[error("dependency admission receipt was replayed")]
    AdmissionReceiptReplay,
    /// Signed receipt bytes were committed but unavailable.
    #[error("signed dependency admission receipt set is committed but unavailable")]
    AdmissionReceiptSetUnavailable,
    /// Signed receipt availability and bytes disagreed.
    #[error("signed dependency admission receipt availability disagrees with exact byte custody")]
    AdmissionReceiptSetAvailabilityMismatch,
    /// Retrieved receipt bytes differed from committed custody.
    #[error("signed dependency admission receipt bytes differ from committed custody")]
    AdmissionReceiptSetByteSubstitution,
    /// Receipt-set signature bytes were malformed.
    #[error("dependency admission receipt-set Ed25519 signature is malformed")]
    AdmissionReceiptSetSignatureMalformed,
    /// Receipt-set signature verification failed.
    #[error("dependency admission receipt-set signature is invalid")]
    AdmissionReceiptSetSignatureInvalid,
    /// Receipt-set generation or trust binding differed.
    #[error("dependency admission receipt set is bound to another trust or dependency generation")]
    AdmissionReceiptSetBindingMismatch,
    /// A snapshot receipt was absent from the signed set.
    #[error("dependency admission receipt is absent from the signed closed set")]
    DependencyAdmissionReceiptMissing,
    /// A signed receipt differed from its admitted dependency.
    #[error("dependency admission receipt differs from its admitted dependency")]
    DependencyAdmissionReceiptSubstitution,
    /// The signed set contained an unused receipt.
    #[error("signed dependency admission receipt set contains an extraneous receipt")]
    ExtraneousDependencyAdmissionReceipt,
    /// Dependency-generation bytes were not canonical.
    #[error("runtime dependency-generation bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalRuntimeDependencyGeneration,
    /// Historical custody bytes were not canonical.
    #[error("runtime dependency-generation custody is not exact RFC 8785 canonical JSON")]
    NonCanonicalRuntimeDependencyGenerationCustody,
    /// Historical custody schema was unsupported.
    #[error("unsupported runtime dependency-generation custody schema {0}")]
    UnknownRuntimeDependencyGenerationCustodySchema(String),
    /// Historical custody contained malformed exact bytes.
    #[error("runtime dependency-generation custody contains malformed exact bytes")]
    RuntimeDependencyGenerationCustodyMalformed,
    /// Dependency-generation schema was unsupported.
    #[error("unsupported runtime dependency-generation schema {0}")]
    UnknownRuntimeDependencyGenerationSchema(String),
    /// Dependency generation, content, or binding was substituted.
    #[error("runtime dependency-generation custody differs from its authenticated generation")]
    RuntimeDependencyGenerationSubstitution,
    /// A bound reopen cannot require an empty custody carrier.
    #[error("dependency-custody binding length must be positive")]
    CustodyBindingLengthZero,
    /// Custody length could not be represented in the binding domain.
    #[error("dependency-custody byte length exceeds u64")]
    CustodyLengthOverflow,
    /// Exact custody length differed from the immutable binding.
    #[error("dependency-custody length differs: expected {expected}, observed {observed}")]
    CustodyLengthMismatch {
        /// Required byte length.
        expected: u64,
        /// Observed byte length.
        observed: u64,
    },
    /// Exact custody digest differed from the immutable binding.
    #[error("dependency-custody digest differs: expected {expected}, observed {observed}")]
    CustodyDigestMismatch {
        /// Required byte digest.
        expected: Sha256Digest,
        /// Observed byte digest.
        observed: Sha256Digest,
    },
    /// An external-source purpose was paired with an ineligible reference.
    #[error("external-source requirement is incompatible with its exact reference")]
    ExternalSourceRequirementInvalid,
    /// An authority purpose was paired with an ineligible reference.
    #[error("authority-source requirement is incompatible with its exact reference")]
    AuthoritySourceRequirementInvalid,
    /// An exact external source requirement was repeated.
    #[error("external-source requirement was duplicated")]
    DuplicateExternalSourceRequirement,
    /// An exact authority requirement was repeated.
    #[error("authority-source requirement was duplicated")]
    DuplicateAuthoritySourceRequirement,
}

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
/// calling [`AuthenticatedRuntimeDependencyClosure::decode_authenticated`].
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
            return Err(DependencyCustodyError::NonCanonicalDependencyTrustAnchor);
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
            return Err(DependencyCustodyError::DependencyTrustAnchorSubstitution {
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
            DependencyCustodyError::DependencyTrustAnchorPublicKeyMalformed
        })?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| DependencyCustodyError::DependencyTrustAnchorPublicKeyMalformed)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != ED25519_TRUST_ANCHOR_SCHEMA {
            return Err(DependencyCustodyError::UnknownDependencyTrustAnchorSchema(
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

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn fixture(
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
    /// Structural validation occurs here. The authenticated closure performs
    /// cryptographic verification after the exact generation is derived.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical content, duplicate receipts, an unknown schema, or
    /// a malformed signature.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let receipt_set: Self = serde_json::from_slice(bytes)?;
        receipt_set.validate()?;
        if canonical_json_bytes(&receipt_set)? != bytes {
            return Err(DependencyCustodyError::NonCanonicalAdmissionReceiptSet);
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
            return Err(DependencyCustodyError::AdmissionReceiptSetBindingMismatch);
        }
        let signature_bytes = decode_exact_hex::<64>(&self.signature_hex, || {
            DependencyCustodyError::AdmissionReceiptSetSignatureMalformed
        })?;
        let signature = Signature::from_bytes(&signature_bytes);
        anchor
            .verifying_key()?
            .verify_strict(&self.unsigned_bytes()?, &signature)
            .map_err(|_| DependencyCustodyError::AdmissionReceiptSetSignatureInvalid)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != ADMISSION_RECEIPT_SET_SCHEMA {
            return Err(DependencyCustodyError::UnknownAdmissionReceiptSetSchema(
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
                return Err(DependencyCustodyError::AdmissionReceiptSetNotCanonical);
            }
            if !receipt_ids.insert(receipt.receipt_id()?) {
                return Err(DependencyCustodyError::AdmissionReceiptReplay);
            }
            previous = Some(receipt);
        }
        let _ = decode_exact_hex::<64>(&self.signature_hex, || {
            DependencyCustodyError::AdmissionReceiptSetSignatureMalformed
        })?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn fixture_manifest_digest(
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

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn fixture_signed(
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
            return Err(DependencyCustodyError::AdmissionReceiptSetAvailabilityMismatch);
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
            ) => Err(DependencyCustodyError::AdmissionReceiptSetByteSubstitution),
            (AdmissionReceiptSetAvailability::CommittedUnavailable, None) => {
                Err(DependencyCustodyError::AdmissionReceiptSetUnavailable)
            }
            _ => Err(DependencyCustodyError::AdmissionReceiptSetAvailabilityMismatch),
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
                    .map_err(|_| DependencyCustodyError::ExternalDependencyBytesMalformed)?;
                if hex::encode(&bytes) != *encoded {
                    return Err(DependencyCustodyError::ExternalDependencyBytesMalformed);
                }
                bytes
            }
            (None, ExternalDependencyAvailability::CommittedUnavailable) => return Ok(()),
            _ => return Err(DependencyCustodyError::ExternalDependencyAvailabilityMismatch),
        };
        if sha256_bytes(&bytes) != self.reference.bytes_digest {
            return Err(DependencyCustodyError::ExternalDependencyByteSubstitution(
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
    /// Refuses runtime-owned records, duplicate references or receipts,
    /// availability/byte-shape mismatch, and substituted available bytes.
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
            return Err(DependencyCustodyError::NonCanonicalExternalDependencySnapshot);
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
            return Err(
                DependencyCustodyError::UnknownExternalDependencySnapshotSchema(
                    self.schema.clone(),
                ),
            );
        }
        let mut previous: Option<&RecordRef> = None;
        let mut receipts = BTreeSet::new();
        for dependency in &self.dependencies {
            if previous.is_some_and(|prior| prior >= &dependency.reference) {
                return Err(DependencyCustodyError::ExternalDependencySnapshotNotCanonical);
            }
            if dependency.reference.schema.as_str() == PROVIDER_INTAKE_SCHEMA {
                return Err(DependencyCustodyError::ProviderIntakeOffLedger);
            }
            if RuntimeSchema::parse(dependency.reference.schema.as_str()).is_ok() {
                return Err(DependencyCustodyError::MaterializedRuntimeRecordOffLedger(
                    dependency.reference.schema.to_string(),
                ));
            }
            if !receipts.insert(&dependency.admission_receipt_id) {
                return Err(DependencyCustodyError::ExternalDependencyReceiptReplay);
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
            return Err(DependencyCustodyError::NonCanonicalAuthorityAdmissionSnapshot);
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
            return Err(
                DependencyCustodyError::UnknownAuthorityAdmissionSnapshotSchema(
                    self.schema.clone(),
                ),
            );
        }
        let mut previous: Option<(&RecordRef, u8)> = None;
        let mut receipts = BTreeSet::new();
        for admission in &self.admissions {
            let rank = admission_kind_rank(admission.kind);
            if previous.is_some_and(|(reference, previous_rank)| {
                (reference, previous_rank) >= (&admission.reference, rank)
            }) {
                return Err(DependencyCustodyError::AuthorityAdmissionSnapshotNotCanonical);
            }
            let schema = admission.reference.schema.as_str();
            if (admission.kind == AuthorityAdmissionKind::OperationAuthorization
                && schema != RuntimeSchema::OperationAuthorizationV1.as_str())
                || (admission.kind == AuthorityAdmissionKind::InvocationAuthentication
                    && (RuntimeSchema::parse(schema).is_ok() || schema == PROVIDER_INTAKE_SCHEMA))
            {
                return Err(DependencyCustodyError::AuthorityAdmissionKindMismatch);
            }
            if !receipts.insert(&admission.admission_receipt_id) {
                return Err(DependencyCustodyError::AuthorityAdmissionReceiptReplay);
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
    pub(crate) fn derive(
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
            return Err(DependencyCustodyError::NonCanonicalRuntimeDependencyGeneration);
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
            return Err(
                DependencyCustodyError::UnknownRuntimeDependencyGenerationSchema(
                    self.schema.clone(),
                ),
            );
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

/// Immutable store/checkpoint binding for one exact dependency-custody
/// carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactDependencyCustodyBinding {
    dependency_generation_id: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    custody_digest: Sha256Digest,
    custody_length: u64,
}

impl ExactDependencyCustodyBinding {
    /// Constructs one complete exact-byte binding.
    ///
    /// # Errors
    ///
    /// Refuses a zero-length carrier. A caller must never use an empty byte
    /// string as a sentinel for unavailable custody.
    pub fn new(
        dependency_generation_id: Sha256Digest,
        trust_anchor_id: Sha256Digest,
        custody_digest: Sha256Digest,
        custody_length: u64,
    ) -> Result<Self> {
        if custody_length == 0 {
            return Err(DependencyCustodyError::CustodyBindingLengthZero);
        }
        Ok(Self {
            dependency_generation_id,
            trust_anchor_id,
            custody_digest,
            custody_length,
        })
    }

    /// Returns the exact dependency-generation identity.
    #[must_use]
    pub const fn dependency_generation_id(&self) -> &Sha256Digest {
        &self.dependency_generation_id
    }

    /// Returns the independently retained trust-anchor identity.
    #[must_use]
    pub const fn trust_anchor_id(&self) -> &Sha256Digest {
        &self.trust_anchor_id
    }

    /// Returns the exact carrier-byte digest.
    #[must_use]
    pub const fn custody_digest(&self) -> &Sha256Digest {
        &self.custody_digest
    }

    /// Returns the exact carrier-byte length.
    #[must_use]
    pub const fn custody_length(&self) -> u64 {
        self.custody_length
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
                DependencyCustodyError::UnknownRuntimeDependencyGenerationCustodySchema(
                    carrier.schema,
                ),
            );
        }
        let decode = |encoded: String| -> Result<Vec<u8>> {
            let decoded = hex::decode(&encoded)
                .map_err(|_| DependencyCustodyError::RuntimeDependencyGenerationCustodyMalformed)?;
            if hex::encode(&decoded) != encoded {
                return Err(DependencyCustodyError::RuntimeDependencyGenerationCustodyMalformed);
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
            return Err(DependencyCustodyError::NonCanonicalRuntimeDependencyGenerationCustody);
        }
        let generation =
            RuntimeDependencyGeneration::decode_canonical(&custody.generation_canonical_bytes)?;
        if generation.generation_id()? != custody.generation_id
            || generation.trust_anchor_id() != &custody.trust_anchor_id()?
        {
            return Err(DependencyCustodyError::RuntimeDependencyGenerationSubstitution);
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
            return Err(DependencyCustodyError::RuntimeDependencyGenerationSubstitution);
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
    pub fn reopen(
        &self,
        expected_trust_anchor_id: &Sha256Digest,
    ) -> Result<AuthenticatedRuntimeDependencyClosure> {
        let anchor = Ed25519TrustAnchor::decode_expected(
            &self.trust_anchor_canonical_bytes,
            expected_trust_anchor_id,
        )?;
        let receipt_custody = AdmissionReceiptSetCustody {
            availability: AdmissionReceiptSetAvailability::Online,
            committed_bytes_digest: sha256_bytes(&self.admission_receipt_set_canonical_bytes),
            exact_bytes: Some(self.admission_receipt_set_canonical_bytes.clone()),
        };
        let dependencies = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            &self.identity_catalog_canonical_bytes,
            &self.external_dependency_canonical_bytes,
            &self.authority_admission_canonical_bytes,
            &anchor,
            &receipt_custody,
        )?;
        if dependencies.generation_id() != &self.generation_id
            || dependencies.generation.canonical_bytes()? != self.generation_canonical_bytes
        {
            return Err(DependencyCustodyError::RuntimeDependencyGenerationSubstitution);
        }
        Ok(dependencies)
    }
}

/// Reopened, exact dependency closure used by the runtime.
///
/// External callers cannot mint a closure by filling fields:
///
/// ```compile_fail
/// use nq_host_role_dependency_custody::AuthenticatedRuntimeDependencyClosure;
///
/// let forged = AuthenticatedRuntimeDependencyClosure {};
/// ```
///
/// The signed fixture constructor is not a public production API, even when
/// downstream qualification support is enabled:
///
/// ```compile_fail
/// use nq_host_role_dependency_custody::SignedAdmissionReceiptSet;
///
/// let signer = SignedAdmissionReceiptSet::fixture_signed;
/// ```
///
/// The default production feature surface does not export downstream fixture
/// construction:
///
/// ```compile_fail
/// #[cfg(not(feature = "test-support"))]
/// use nq_host_role_dependency_custody::test_support::authenticated_runtime_fixture;
///
/// #[cfg(feature = "test-support")]
/// compile_error!("this compile-fail example specifies the default feature surface");
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedRuntimeDependencyClosure {
    catalog_snapshot: CatalogSnapshot,
    external_snapshot: ExternalDependencySnapshot,
    authority_snapshot: AuthorityAdmissionSnapshot,
    generation: RuntimeDependencyGeneration,
    custody: RuntimeDependencyGenerationCustody,
    identity_catalog: IdentityCatalog,
    external_by_ref: BTreeMap<RecordRef, ExactExternalDependency>,
    external_exact_bytes_by_ref: BTreeMap<RecordRef, Vec<u8>>,
    authority_admissions: BTreeMap<(RecordRef, u8), AuthorityAdmission>,
    binding_digest: Sha256Digest,
}

/// Compatibility name retained for host-runtime callers while the shared
/// crate becomes the canonical owner.
pub type RuntimeDependencies = AuthenticatedRuntimeDependencyClosure;

/// Closed purpose for resolving one exact external dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExternalSourcePurpose {
    /// Exact admitted bytes occupying the invocation-authentication input
    /// role. Their presence does not establish an authority admission.
    InvocationAuthentication,
    /// Exact admitted bytes occupying the generation-match input role. The
    /// resolver does not decide whether the bytes establish a match.
    GenerationMatch,
    /// Exact admitted bytes occupying the capability input role. The resolver
    /// does not decide capability sufficiency.
    Capability,
    /// Exact admitted bytes occupying the custody-reservation-commit input
    /// role. The resolver does not decide capacity or commitment validity.
    CustodyReservationCommit,
}

/// One purpose-bound exact external-source requirement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExternalSourceRequirement {
    purpose: ExternalSourcePurpose,
    reference: RecordRef,
}

impl ExternalSourceRequirement {
    fn new(purpose: ExternalSourcePurpose, reference: RecordRef) -> Result<Self> {
        validate_external_source_reference(&reference)?;
        Ok(Self { purpose, reference })
    }

    /// Requires exact invocation-authentication evidence.
    ///
    /// # Errors
    ///
    /// Refuses runtime-ledger and provider-intake references.
    pub fn invocation_authentication(reference: RecordRef) -> Result<Self> {
        Self::new(ExternalSourcePurpose::InvocationAuthentication, reference)
    }

    /// Requires exact bytes for the generation-match input role.
    ///
    /// # Errors
    ///
    /// Refuses runtime-ledger and provider-intake references.
    pub fn generation_match(reference: RecordRef) -> Result<Self> {
        Self::new(ExternalSourcePurpose::GenerationMatch, reference)
    }

    /// Requires exact bytes for the capability input role.
    ///
    /// # Errors
    ///
    /// Refuses runtime-ledger and provider-intake references.
    pub fn capability(reference: RecordRef) -> Result<Self> {
        Self::new(ExternalSourcePurpose::Capability, reference)
    }

    /// Requires exact bytes for the custody-reservation-commit input role.
    ///
    /// # Errors
    ///
    /// Refuses runtime-ledger and provider-intake references.
    pub fn custody_reservation_commit(reference: RecordRef) -> Result<Self> {
        Self::new(ExternalSourcePurpose::CustodyReservationCommit, reference)
    }

    /// Returns the closed resolution purpose.
    #[must_use]
    pub const fn purpose(&self) -> ExternalSourcePurpose {
        self.purpose
    }

    /// Returns the exact required record.
    #[must_use]
    pub const fn reference(&self) -> &RecordRef {
        &self.reference
    }
}

/// Closed purpose for resolving one independently admitted authority input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthoritySourcePurpose {
    /// Independent admission of invocation-authentication evidence.
    InvocationAuthentication,
    /// Independent admission of a materialized operation authorization.
    OperationAuthorization,
}

/// One purpose-bound exact authority-source requirement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthoritySourceRequirement {
    purpose: AuthoritySourcePurpose,
    reference: RecordRef,
}

impl AuthoritySourceRequirement {
    /// Requires the separate authority admission for invocation-authentication
    /// evidence.
    ///
    /// # Errors
    ///
    /// Refuses runtime-ledger, provider-intake, and otherwise ineligible
    /// references.
    pub fn invocation_authentication(reference: RecordRef) -> Result<Self> {
        validate_external_source_reference(&reference)?;
        Ok(Self {
            purpose: AuthoritySourcePurpose::InvocationAuthentication,
            reference,
        })
    }

    /// Requires independent admission of one exact materialized operation
    /// authorization.
    ///
    /// # Errors
    ///
    /// Refuses every reference whose schema is not exactly
    /// `nq.operation_authorization.v1`.
    pub fn operation_authorization(reference: RecordRef) -> Result<Self> {
        if reference.schema.as_str() != RuntimeSchema::OperationAuthorizationV1.as_str() {
            return Err(DependencyCustodyError::AuthoritySourceRequirementInvalid);
        }
        Ok(Self {
            purpose: AuthoritySourcePurpose::OperationAuthorization,
            reference,
        })
    }

    /// Returns the closed admission purpose.
    #[must_use]
    pub const fn purpose(&self) -> AuthoritySourcePurpose {
        self.purpose
    }

    /// Returns the exact required authority-bearing record.
    #[must_use]
    pub const fn reference(&self) -> &RecordRef {
        &self.reference
    }
}

/// Exact resolved state for one external-source requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSourceState<'a> {
    /// Exact authenticated bytes are available in the reopened closure.
    Available {
        /// Whether bytes were online or retrieved from archive before reopen.
        availability: ExternalDependencyAvailability,
        /// Exact authenticated bytes.
        exact_bytes: &'a [u8],
        /// Independent admission receipt identity.
        admission_receipt_id: &'a Sha256Digest,
        /// Verifier that admitted the exact bytes.
        admitted_by: &'a IdentityRef,
        /// Time of exact-byte admission.
        admitted_at: &'a Timestamp,
    },
    /// The exact reference is absent from the closed dependency generation.
    Missing,
    /// Custody is committed but exact bytes are not currently retrievable.
    CommittedUnavailable {
        /// Independent admission receipt identity.
        admission_receipt_id: &'a Sha256Digest,
        /// Verifier that admitted the committed bytes.
        admitted_by: &'a IdentityRef,
        /// Time of exact-byte admission.
        admitted_at: &'a Timestamp,
    },
}

/// Purpose-bound result for one exact external source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSourceResult<'a> {
    requirement: ExternalSourceRequirement,
    state: ExternalSourceState<'a>,
}

impl<'a> ExternalSourceResult<'a> {
    /// Returns the exact closed requirement.
    #[must_use]
    pub const fn requirement(&self) -> &ExternalSourceRequirement {
        &self.requirement
    }

    /// Returns the exact resolution state.
    #[must_use]
    pub const fn state(&self) -> &ExternalSourceState<'a> {
        &self.state
    }
}

/// Exact resolved state for one authority-source requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoritySourceState<'a> {
    /// The exact reference and purpose were independently admitted.
    Admitted {
        /// Independent admission receipt identity.
        admission_receipt_id: &'a Sha256Digest,
        /// Verifier that admitted the authority-bearing input.
        admitted_by: &'a IdentityRef,
        /// Admission time.
        admitted_at: &'a Timestamp,
    },
    /// No exact admission exists for the required reference and purpose.
    RequiredAdmissionMissing,
}

/// Purpose-bound result for one exact authority input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySourceResult<'a> {
    requirement: AuthoritySourceRequirement,
    state: AuthoritySourceState<'a>,
}

impl<'a> AuthoritySourceResult<'a> {
    /// Returns the exact closed requirement.
    #[must_use]
    pub const fn requirement(&self) -> &AuthoritySourceRequirement {
        &self.requirement
    }

    /// Returns the exact resolution state.
    #[must_use]
    pub const fn state(&self) -> &AuthoritySourceState<'a> {
        &self.state
    }
}

/// Borrowed, non-deserializable resolution over one authenticated closure.
///
/// The result cannot outlive or be detached from the closure whose exact
/// bytes and admissions it exposes.
///
/// ```compile_fail
/// use nq_host_role_dependency_custody::AuthenticatedSourceResolution;
///
/// let detached: AuthenticatedSourceResolution<'static> =
///     serde_json::from_slice(b"{}").unwrap();
/// ```
///
/// External callers also cannot fill the borrowed result carrier directly:
///
/// ```compile_fail
/// use nq_host_role_dependency_custody::AuthenticatedSourceResolution;
///
/// let forged = AuthenticatedSourceResolution {
///     external: Vec::new(),
///     authority: Vec::new(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSourceResolution<'a> {
    external: Vec<ExternalSourceResult<'a>>,
    authority: Vec<AuthoritySourceResult<'a>>,
}

impl<'a> AuthenticatedSourceResolution<'a> {
    /// Returns ordered external-source results.
    #[must_use]
    pub fn external(&self) -> &[ExternalSourceResult<'a>] {
        &self.external
    }

    /// Returns ordered authority-source results.
    #[must_use]
    pub fn authority(&self) -> &[AuthoritySourceResult<'a>] {
        &self.authority
    }
}

impl AuthenticatedRuntimeDependencyClosure {
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
            .collect::<BTreeMap<_, _>>();
        let external_exact_bytes_by_ref = external_snapshot
            .dependencies
            .iter()
            .filter_map(|dependency| {
                dependency.exact_bytes_hex.as_ref().map(|encoded| {
                    hex::decode(encoded)
                        .map(|bytes| (dependency.reference.clone(), bytes))
                        .map_err(|_| DependencyCustodyError::ExternalDependencyBytesMalformed)
                })
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let authority_admissions = authority_snapshot
            .admissions
            .iter()
            .cloned()
            .map(|admission| {
                (
                    (
                        admission.reference.clone(),
                        admission_kind_rank(admission.kind),
                    ),
                    admission,
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
            external_exact_bytes_by_ref,
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

    /// Validates every graph reference against this exact authenticated
    /// closure.
    ///
    /// # Errors
    ///
    /// Refuses missing, unavailable, unauthenticated, or identity-incompatible
    /// graph dependencies.
    pub fn validate_graph_dependencies(&self, records: &RuntimeRecordSet) -> Result<()> {
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
                        return Err(DependencyCustodyError::ExternalDependencyUnavailable(
                            reference.record_id.to_string(),
                        ));
                    }
                    None => {
                        return Err(DependencyCustodyError::ExternalDependencyMissing(
                            reference.record_id.to_string(),
                        ));
                    }
                }
            }
            if record.schema() == RuntimeSchema::OperationAuthorizationV1
                && !self.authority_admissions.contains_key(&(
                    record.exact_reference(),
                    admission_kind_rank(AuthorityAdmissionKind::OperationAuthorization),
                ))
            {
                return Err(DependencyCustodyError::AuthorityRecordNotAdmitted(
                    record.record_id().to_string(),
                ));
            }
            if record.schema() == RuntimeSchema::DiagnosticInvocationRequestV1 {
                let authentication: RecordRef =
                    serde_json::from_value(value["authentication_evidence"].clone())?;
                if !self.authority_admissions.contains_key(&(
                    authentication.clone(),
                    admission_kind_rank(AuthorityAdmissionKind::InvocationAuthentication),
                )) {
                    return Err(DependencyCustodyError::AuthenticationEvidenceNotAdmitted(
                        authentication.record_id.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Reopens one exact authenticated closure under a complete immutable
    /// custody binding.
    ///
    /// Length and digest are checked before any carrier is decoded. The
    /// carrier's generation and root are then checked before and after full
    /// receipt/signature authentication.
    ///
    /// # Errors
    ///
    /// Refuses any byte-length, byte-digest, generation, trust-root,
    /// canonicalization, signature, receipt, or admission substitution.
    pub fn reopen_bound(
        canonical_custody: &[u8],
        binding: &ExactDependencyCustodyBinding,
    ) -> Result<Self> {
        let observed_length = u64::try_from(canonical_custody.len())
            .map_err(|_| DependencyCustodyError::CustodyLengthOverflow)?;
        if observed_length != binding.custody_length {
            return Err(DependencyCustodyError::CustodyLengthMismatch {
                expected: binding.custody_length,
                observed: observed_length,
            });
        }
        let observed_digest = sha256_bytes(canonical_custody);
        if observed_digest != binding.custody_digest {
            return Err(DependencyCustodyError::CustodyDigestMismatch {
                expected: binding.custody_digest.clone(),
                observed: observed_digest,
            });
        }
        let custody =
            RuntimeDependencyGenerationCustody::decode_canonical_closure(canonical_custody)?;
        if custody.generation_id() != &binding.dependency_generation_id {
            return Err(DependencyCustodyError::RuntimeDependencyGenerationSubstitution);
        }
        let observed_trust_anchor = custody.trust_anchor_id()?;
        if observed_trust_anchor != binding.trust_anchor_id {
            return Err(DependencyCustodyError::DependencyTrustAnchorSubstitution {
                expected: binding.trust_anchor_id.clone(),
                observed: observed_trust_anchor,
            });
        }
        let reopened = custody.reopen(&binding.trust_anchor_id)?;
        if reopened.generation_id() != &binding.dependency_generation_id {
            return Err(DependencyCustodyError::RuntimeDependencyGenerationSubstitution);
        }
        Ok(reopened)
    }

    /// Resolves a closed, purpose-specific set of exact external and authority
    /// requirements without contacting mutable storage or external systems.
    ///
    /// Requirements are sorted into canonical order. Duplicate exact
    /// requirements are refused rather than double-counted.
    ///
    /// # Errors
    ///
    /// Refuses duplicate requirements. Purpose/reference compatibility has
    /// already been enforced by the public constructors.
    ///
    /// A caller cannot inject a resolver callback:
    ///
    /// ```compile_fail
    /// # use nq_host_role_dependency_custody::{
    /// #     AuthenticatedRuntimeDependencyClosure, AuthoritySourceRequirement,
    /// #     ExternalSourceRequirement,
    /// # };
    /// # fn inject(
    /// #     closure: &AuthenticatedRuntimeDependencyClosure,
    /// #     external: &[ExternalSourceRequirement],
    /// #     authority: &[AuthoritySourceRequirement],
    /// # ) {
    /// let _ = closure.resolve_sources(external, authority, |_reference| None);
    /// # }
    /// ```
    pub fn resolve_sources<'a>(
        &'a self,
        external_requirements: &[ExternalSourceRequirement],
        authority_requirements: &[AuthoritySourceRequirement],
    ) -> Result<AuthenticatedSourceResolution<'a>> {
        let mut external_requirements = external_requirements.to_vec();
        external_requirements.sort();
        if external_requirements
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(DependencyCustodyError::DuplicateExternalSourceRequirement);
        }
        let external = external_requirements
            .into_iter()
            .map(|requirement| {
                let state = match self.external_by_ref.get(&requirement.reference) {
                    None => ExternalSourceState::Missing,
                    Some(dependency)
                        if dependency.availability
                            == ExternalDependencyAvailability::CommittedUnavailable =>
                    {
                        ExternalSourceState::CommittedUnavailable {
                            admission_receipt_id: &dependency.admission_receipt_id,
                            admitted_by: &dependency.admitted_by,
                            admitted_at: &dependency.admitted_at,
                        }
                    }
                    Some(dependency) => ExternalSourceState::Available {
                        availability: dependency.availability,
                        exact_bytes: self
                            .external_exact_bytes_by_ref
                            .get(&requirement.reference)
                            .ok_or(
                                DependencyCustodyError::ExternalDependencyAvailabilityMismatch,
                            )?,
                        admission_receipt_id: &dependency.admission_receipt_id,
                        admitted_by: &dependency.admitted_by,
                        admitted_at: &dependency.admitted_at,
                    },
                };
                Ok(ExternalSourceResult { requirement, state })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut authority_requirements = authority_requirements.to_vec();
        authority_requirements.sort();
        if authority_requirements
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(DependencyCustodyError::DuplicateAuthoritySourceRequirement);
        }
        let authority = authority_requirements
            .into_iter()
            .map(|requirement| {
                let kind = match requirement.purpose {
                    AuthoritySourcePurpose::InvocationAuthentication => {
                        AuthorityAdmissionKind::InvocationAuthentication
                    }
                    AuthoritySourcePurpose::OperationAuthorization => {
                        AuthorityAdmissionKind::OperationAuthorization
                    }
                };
                let state = self
                    .authority_admissions
                    .get(&(requirement.reference.clone(), admission_kind_rank(kind)))
                    .map_or(
                        AuthoritySourceState::RequiredAdmissionMissing,
                        |admission| AuthoritySourceState::Admitted {
                            admission_receipt_id: &admission.admission_receipt_id,
                            admitted_by: &admission.admitted_by,
                            admitted_at: &admission.admitted_at,
                        },
                    );
                AuthoritySourceResult { requirement, state }
            })
            .collect();

        Ok(AuthenticatedSourceResolution {
            external,
            authority,
        })
    }
}

fn validate_external_source_reference(reference: &RecordRef) -> Result<()> {
    if RuntimeSchema::parse(reference.schema.as_str()).is_ok()
        || reference.schema.as_str() == PROVIDER_INTAKE_SCHEMA
    {
        return Err(DependencyCustodyError::ExternalSourceRequirementInvalid);
    }
    Ok(())
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
            return Err(DependencyCustodyError::AdmissionReceiptReplay);
        }
    }

    let mut matched = BTreeSet::new();
    for dependency in &external_snapshot.dependencies {
        let receipt = receipts_by_id
            .get(&dependency.admission_receipt_id)
            .ok_or(DependencyCustodyError::DependencyAdmissionReceiptMissing)?;
        if receipt.reference != dependency.reference
            || receipt.kind != DependencyAdmissionKind::ExternalDependency
            || receipt.admitted_by != dependency.admitted_by
            || receipt.admitted_at != dependency.admitted_at
        {
            return Err(DependencyCustodyError::DependencyAdmissionReceiptSubstitution);
        }
        matched.insert(dependency.admission_receipt_id.clone());
    }
    for admission in &authority_snapshot.admissions {
        let receipt = receipts_by_id
            .get(&admission.admission_receipt_id)
            .ok_or(DependencyCustodyError::DependencyAdmissionReceiptMissing)?;
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
            return Err(DependencyCustodyError::DependencyAdmissionReceiptSubstitution);
        }
        matched.insert(admission.admission_receipt_id.clone());
    }
    if matched.len() != receipts_by_id.len() {
        return Err(DependencyCustodyError::ExtraneousDependencyAdmissionReceipt);
    }
    Ok(())
}

fn decode_exact_hex<const N: usize>(
    encoded: &str,
    malformed: impl Fn() -> DependencyCustodyError,
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

/// Qualification fixtures for downstream tests.
///
/// This module is unavailable in the default production feature set.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    #![cfg_attr(not(test), allow(dead_code))]

    use ed25519_dalek::SigningKey;
    use nq_host_role_contract::{
        Generation, IdentityCatalog, IdentityId, IdentityVersion, NamespaceId, NamespaceSnapshot,
        NamespaceVersion, Token,
    };

    #[allow(clippy::wildcard_imports)]
    // Closed in-crate qualification fixtures exercise the full surface.
    use super::*;

    pub(crate) struct Fixture {
        anchor: Ed25519TrustAnchor,
        catalog_bytes: Vec<u8>,
        external_bytes: Vec<u8>,
        authority_bytes: Vec<u8>,
        receipt_set: SignedAdmissionReceiptSet,
    }

    impl Fixture {
        pub(crate) fn decode(&self) -> Result<AuthenticatedRuntimeDependencyClosure> {
            AuthenticatedRuntimeDependencyClosure::decode_authenticated(
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

    /// Exact dependency-custody bytes produced by closed qualification
    /// scenarios.
    ///
    /// This carrier is deliberately neutral: possessing it does not establish
    /// that its nested snapshots or receipts authenticate. Qualification
    /// callers must pass the exact bytes through the production
    /// [`AuthenticatedRuntimeDependencyClosure::reopen_bound`] boundary.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct RuntimeDependencyCustodyFixture {
        generation_id: Sha256Digest,
        trust_anchor_id: Sha256Digest,
        canonical_custody_bytes: Vec<u8>,
    }

    impl RuntimeDependencyCustodyFixture {
        /// Returns the generation identity named by the exact carrier.
        #[must_use]
        pub const fn generation_id(&self) -> &Sha256Digest {
            &self.generation_id
        }

        /// Returns the independently expected fixture bootstrap-root identity.
        #[must_use]
        pub const fn trust_anchor_id(&self) -> &Sha256Digest {
            &self.trust_anchor_id
        }

        /// Returns the exact canonical dependency-custody carrier.
        #[must_use]
        pub fn canonical_custody_bytes(&self) -> &[u8] {
            &self.canonical_custody_bytes
        }
    }

    /// One exact receipt selected for a closed hostile fixture scenario.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum RuntimeDependencyFixtureReceiptTarget {
        /// The admission receipt for one exact external dependency.
        External(RecordRef),
        /// One exact purpose-bound authority admission receipt.
        Authority {
            /// Exact authority-bearing reference.
            reference: RecordRef,
            /// Closed admission purpose.
            kind: AuthorityAdmissionKind,
        },
    }

    /// Closed mutation applied by the qualification fixture before signing.
    ///
    /// This is intentionally not a generic graph or signing API. Each variant
    /// constructs one named source-custody case required by the Store
    /// integration campaign.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum RuntimeDependencyFixtureScenario {
        /// Exact online inputs, authority admissions, and receipt coverage.
        Exact,
        /// Change only the availability of one exact external dependency.
        ExternalAvailability {
            /// Exact external reference to change.
            reference: RecordRef,
            /// Replacement availability mode.
            availability: ExternalDependencyAvailability,
        },
        /// Omit one exact external dependency and its receipt from an
        /// otherwise authenticated closure.
        ExternalOmitted {
            /// Exact external reference to omit.
            reference: RecordRef,
        },
        /// Replace one exact external dependency with a deterministic,
        /// independently valid foreign reference and bytes.
        ExternalValidReplacement {
            /// Exact external reference to replace.
            reference: RecordRef,
        },
        /// Omit one purpose-bound authority admission and its receipt.
        AuthorityOmitted {
            /// Exact authority-bearing reference to omit.
            reference: RecordRef,
            /// Purpose of the admission to omit.
            kind: AuthorityAdmissionKind,
        },
        /// Replace one purpose-bound authority admission with a deterministic
        /// foreign exact reference under the same purpose.
        AuthorityWrongReference {
            /// Exact authority-bearing reference to replace.
            reference: RecordRef,
            /// Purpose of the admission to replace.
            kind: AuthorityAdmissionKind,
        },
        /// Retain one exact authority-bearing reference under the other closed
        /// purpose. The resulting signed carrier is intentionally not an
        /// authenticated closure: production reopen must refuse its
        /// purpose/schema mismatch.
        AuthorityWrongPurpose {
            /// Exact authority-bearing reference whose purpose is changed.
            reference: RecordRef,
            /// Original purpose of the admission.
            kind: AuthorityAdmissionKind,
        },
        /// Sign a receipt set which omits one receipt still named by a
        /// snapshot.
        SignedReceiptOmitted {
            /// Exact receipt to omit.
            target: RuntimeDependencyFixtureReceiptTarget,
        },
        /// Sign a receipt set containing one deterministic substituted receipt
        /// and bind the snapshot to that receipt identity.
        SignedReceiptSubstituted {
            /// Exact receipt to substitute.
            target: RuntimeDependencyFixtureReceiptTarget,
        },
        /// Sign one additional exact receipt which no snapshot member names.
        SignedReceiptExtraneous,
    }

    fn fixture_authority_receipt_kind(kind: AuthorityAdmissionKind) -> DependencyAdmissionKind {
        match kind {
            AuthorityAdmissionKind::OperationAuthorization => {
                DependencyAdmissionKind::OperationAuthorization
            }
            AuthorityAdmissionKind::InvocationAuthentication => {
                DependencyAdmissionKind::InvocationAuthentication
            }
        }
    }

    fn fixture_other_authority_kind(kind: AuthorityAdmissionKind) -> AuthorityAdmissionKind {
        match kind {
            AuthorityAdmissionKind::OperationAuthorization => {
                AuthorityAdmissionKind::InvocationAuthentication
            }
            AuthorityAdmissionKind::InvocationAuthentication => {
                AuthorityAdmissionKind::OperationAuthorization
            }
        }
    }

    fn fixture_replacement_reference(reference: &RecordRef, purpose: &str) -> (RecordRef, Vec<u8>) {
        let exact_bytes = format!(
            "nq closed runtime-dependency fixture replacement:{purpose}:{}",
            reference.record_id
        )
        .into_bytes();
        let record_id = semantic_digest(&serde_json::json!({
            "schema": "nq.runtime_dependency_fixture_replacement.v1",
            "purpose": purpose,
            "replaces": reference,
        }))
        .expect("fixture replacement identity");
        (
            RecordRef {
                schema: reference.schema.clone(),
                record_id,
                bytes_digest: sha256_bytes(&exact_bytes),
            },
            exact_bytes,
        )
    }

    fn fixture_receipt_matches(
        receipt: &DependencyAdmissionReceipt,
        target: &RuntimeDependencyFixtureReceiptTarget,
    ) -> bool {
        match target {
            RuntimeDependencyFixtureReceiptTarget::External(reference) => {
                receipt.reference == *reference
                    && receipt.kind == DependencyAdmissionKind::ExternalDependency
            }
            RuntimeDependencyFixtureReceiptTarget::Authority { reference, kind } => {
                receipt.reference == *reference
                    && receipt.kind == fixture_authority_receipt_kind(*kind)
            }
        }
    }

    fn fixture_reopen(
        fixture: &RuntimeDependencyCustodyFixture,
    ) -> Result<AuthenticatedRuntimeDependencyClosure> {
        let custody_length = u64::try_from(fixture.canonical_custody_bytes.len())
            .map_err(|_| DependencyCustodyError::CustodyLengthOverflow)?;
        let binding = ExactDependencyCustodyBinding::new(
            fixture.generation_id.clone(),
            fixture.trust_anchor_id.clone(),
            sha256_bytes(&fixture.canonical_custody_bytes),
            custody_length,
        )?;
        AuthenticatedRuntimeDependencyClosure::reopen_bound(
            &fixture.canonical_custody_bytes,
            &binding,
        )
    }

    #[allow(clippy::too_many_lines)] // One closed signed fixture keeps mutation order auditable.
    /// Builds exact custody for one closed dependency qualification scenario.
    ///
    /// The fixture signer and key remain private to this module. The returned
    /// value is only exact custody plus its outer generation/root identities;
    /// it carries no authenticated standing.
    ///
    /// # Panics
    ///
    /// Panics when supplied base inputs are inconsistent, a scenario target is
    /// absent, or a deterministic closed scenario cannot be encoded. This
    /// constructor is feature-gated qualification scaffolding.
    #[must_use]
    pub fn runtime_dependency_custody_fixture(
        seed: u8,
        mut runtime_identities: Vec<IdentityRef>,
        external_inputs: Vec<(RecordRef, Vec<u8>)>,
        operation_authorizations: Vec<RecordRef>,
        invocation_authentication: Vec<RecordRef>,
        scenario: RuntimeDependencyFixtureScenario,
    ) -> RuntimeDependencyCustodyFixture {
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
        for runtime_identity in runtime_identities {
            identity_catalog
                .insert(runtime_identity)
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
        let mut external = external_inputs
            .into_iter()
            .map(|(reference, exact_bytes)| {
                let receipt = DependencyAdmissionReceipt {
                    reference: reference.clone(),
                    kind: DependencyAdmissionKind::ExternalDependency,
                    admitted_by: verifier_generation.clone(),
                    admitted_at: admitted_at.clone(),
                };
                let admission_receipt_id = receipt.receipt_id().expect("receipt identity");
                receipts.push(receipt);
                ExactExternalDependency {
                    reference,
                    exact_bytes_hex: Some(hex::encode(exact_bytes)),
                    availability: ExternalDependencyAvailability::Online,
                    admission_receipt_id,
                    admitted_by: verifier_generation.clone(),
                    admitted_at: admitted_at.clone(),
                }
            })
            .collect::<Vec<_>>();

        let mut admissions = Vec::new();
        for (reference, kind) in operation_authorizations
            .into_iter()
            .map(|reference| (reference, AuthorityAdmissionKind::OperationAuthorization))
            .chain(
                invocation_authentication
                    .into_iter()
                    .map(|reference| (reference, AuthorityAdmissionKind::InvocationAuthentication)),
            )
        {
            let receipt = DependencyAdmissionReceipt {
                reference: reference.clone(),
                kind: fixture_authority_receipt_kind(kind),
                admitted_by: verifier_generation.clone(),
                admitted_at: admitted_at.clone(),
            };
            let admission_receipt_id = receipt.receipt_id().expect("receipt identity");
            receipts.push(receipt);
            admissions.push(AuthorityAdmission {
                reference,
                kind,
                admission_receipt_id,
                admitted_by: verifier_generation.clone(),
                admitted_at: admitted_at.clone(),
            });
        }

        let mut authority_shape_is_intentionally_invalid = false;
        match scenario {
            RuntimeDependencyFixtureScenario::Exact => {}
            RuntimeDependencyFixtureScenario::ExternalAvailability {
                reference,
                availability,
            } => {
                let dependency = external
                    .iter_mut()
                    .find(|dependency| dependency.reference == reference)
                    .expect("external-availability scenario target");
                dependency.availability = availability;
                if availability == ExternalDependencyAvailability::CommittedUnavailable {
                    dependency.exact_bytes_hex = None;
                }
            }
            RuntimeDependencyFixtureScenario::ExternalOmitted { reference } => {
                let position = external
                    .iter()
                    .position(|dependency| dependency.reference == reference)
                    .expect("external-omission scenario target");
                let removed = external.remove(position);
                receipts.retain(|receipt| {
                    receipt.receipt_id().expect("receipt identity") != removed.admission_receipt_id
                });
            }
            RuntimeDependencyFixtureScenario::ExternalValidReplacement { reference } => {
                let dependency = external
                    .iter_mut()
                    .find(|dependency| dependency.reference == reference)
                    .expect("external-replacement scenario target");
                let old_receipt_id = dependency.admission_receipt_id.clone();
                let receipt = receipts
                    .iter_mut()
                    .find(|receipt| {
                        receipt.receipt_id().expect("receipt identity") == old_receipt_id
                    })
                    .expect("external-replacement scenario receipt");
                let (replacement, exact_bytes) =
                    fixture_replacement_reference(&reference, "external");
                dependency.reference = replacement.clone();
                dependency.exact_bytes_hex = Some(hex::encode(exact_bytes));
                receipt.reference = replacement;
                dependency.admission_receipt_id =
                    receipt.receipt_id().expect("replacement receipt identity");
            }
            RuntimeDependencyFixtureScenario::AuthorityOmitted { reference, kind } => {
                let position = admissions
                    .iter()
                    .position(|admission| {
                        admission.reference == reference && admission.kind == kind
                    })
                    .expect("authority-omission scenario target");
                let removed = admissions.remove(position);
                receipts.retain(|receipt| {
                    receipt.receipt_id().expect("receipt identity") != removed.admission_receipt_id
                });
            }
            RuntimeDependencyFixtureScenario::AuthorityWrongReference { reference, kind } => {
                let admission = admissions
                    .iter_mut()
                    .find(|admission| admission.reference == reference && admission.kind == kind)
                    .expect("authority-reference scenario target");
                let old_receipt_id = admission.admission_receipt_id.clone();
                let receipt = receipts
                    .iter_mut()
                    .find(|receipt| {
                        receipt.receipt_id().expect("receipt identity") == old_receipt_id
                    })
                    .expect("authority-reference scenario receipt");
                let (replacement, _) = fixture_replacement_reference(&reference, "authority");
                admission.reference = replacement.clone();
                receipt.reference = replacement;
                admission.admission_receipt_id =
                    receipt.receipt_id().expect("replacement receipt identity");
            }
            RuntimeDependencyFixtureScenario::AuthorityWrongPurpose { reference, kind } => {
                let admission = admissions
                    .iter_mut()
                    .find(|admission| admission.reference == reference && admission.kind == kind)
                    .expect("authority-purpose scenario target");
                let old_receipt_id = admission.admission_receipt_id.clone();
                let receipt = receipts
                    .iter_mut()
                    .find(|receipt| {
                        receipt.receipt_id().expect("receipt identity") == old_receipt_id
                    })
                    .expect("authority-purpose scenario receipt");
                let replacement_kind = fixture_other_authority_kind(kind);
                admission.kind = replacement_kind;
                receipt.kind = fixture_authority_receipt_kind(replacement_kind);
                admission.admission_receipt_id =
                    receipt.receipt_id().expect("replacement receipt identity");
                authority_shape_is_intentionally_invalid = true;
            }
            RuntimeDependencyFixtureScenario::SignedReceiptOmitted { target } => {
                let position = receipts
                    .iter()
                    .position(|receipt| fixture_receipt_matches(receipt, &target))
                    .expect("receipt-omission scenario target");
                receipts.remove(position);
            }
            RuntimeDependencyFixtureScenario::SignedReceiptSubstituted { target } => {
                let receipt = receipts
                    .iter_mut()
                    .find(|receipt| fixture_receipt_matches(receipt, &target))
                    .expect("receipt-substitution scenario target");
                let (replacement, _) = fixture_replacement_reference(&receipt.reference, "receipt");
                receipt.reference = replacement;
                let substituted_receipt_id =
                    receipt.receipt_id().expect("substituted receipt identity");
                match &target {
                    RuntimeDependencyFixtureReceiptTarget::External(reference) => {
                        external
                            .iter_mut()
                            .find(|dependency| dependency.reference == *reference)
                            .expect("receipt-substitution external snapshot target")
                            .admission_receipt_id = substituted_receipt_id;
                    }
                    RuntimeDependencyFixtureReceiptTarget::Authority { reference, kind } => {
                        admissions
                            .iter_mut()
                            .find(|admission| {
                                admission.reference == *reference && admission.kind == *kind
                            })
                            .expect("receipt-substitution authority snapshot target")
                            .admission_receipt_id = substituted_receipt_id;
                    }
                }
            }
            RuntimeDependencyFixtureScenario::SignedReceiptExtraneous => {
                let reference = record_ref(
                    "example.runtime_dependency_fixture_extraneous.v1",
                    b"extraneous signed fixture receipt",
                );
                receipts.push(DependencyAdmissionReceipt {
                    reference,
                    kind: DependencyAdmissionKind::ExternalDependency,
                    admitted_by: verifier_generation.clone(),
                    admitted_at: admitted_at.clone(),
                });
            }
        }

        let external_snapshot =
            ExternalDependencySnapshot::new(external).expect("runtime external snapshot");
        let external_bytes = external_snapshot
            .canonical_bytes()
            .expect("runtime external bytes");
        let (authority_snapshot, authority_bytes) = if authority_shape_is_intentionally_invalid {
            admissions.sort_by(|left, right| {
                left.reference.cmp(&right.reference).then_with(|| {
                    admission_kind_rank(left.kind).cmp(&admission_kind_rank(right.kind))
                })
            });
            let bytes = canonical_json_bytes(&serde_json::json!({
                "schema": AUTHORITY_ADMISSION_SNAPSHOT_SCHEMA,
                "admissions": admissions,
            }))
            .expect("intentionally invalid authority snapshot bytes");
            (None, bytes)
        } else {
            let snapshot =
                AuthorityAdmissionSnapshot::new(admissions).expect("runtime authority snapshot");
            let bytes = snapshot.canonical_bytes().expect("runtime authority bytes");
            (Some(snapshot), bytes)
        };

        let signed_at = timestamp("2026-07-29T17:00:01-04:00");
        let manifest_digest =
            SignedAdmissionReceiptSet::fixture_manifest_digest(&anchor, &signed_at, &receipts)
                .expect("runtime manifest");
        let generation = if let Some(authority_snapshot) = authority_snapshot.as_ref() {
            RuntimeDependencyGeneration::derive(
                &catalog,
                &external_snapshot,
                authority_snapshot,
                &anchor,
                manifest_digest,
            )
            .expect("runtime generation")
        } else {
            let authority_value: serde_json::Value =
                serde_json::from_slice(&authority_bytes).expect("authority fixture JSON");
            let generation = RuntimeDependencyGeneration {
                schema: RUNTIME_DEPENDENCY_GENERATION_SCHEMA.to_owned(),
                identity_catalog_snapshot_digest: catalog
                    .semantic_digest()
                    .expect("catalog identity"),
                external_dependency_snapshot_digest: external_snapshot
                    .semantic_digest()
                    .expect("external identity"),
                authority_admission_snapshot_digest: semantic_digest(&authority_value)
                    .expect("authority identity"),
                admission_receipt_manifest_digest: manifest_digest,
                trust_anchor_id: anchor.anchor_id().expect("anchor identity"),
                key_generation: anchor.key_generation().clone(),
                trust_policy: anchor.trust_policy().clone(),
                verifier_generation: anchor.verifier_generation().clone(),
            };
            generation.validate().expect("raw fixture generation");
            generation
        };
        let receipt_set = SignedAdmissionReceiptSet::fixture_signed(
            &generation,
            &anchor,
            signed_at,
            receipts,
            &signing_key,
        )
        .expect("runtime receipts");
        let generation_id = generation
            .generation_id()
            .expect("runtime generation identity");
        let trust_anchor_id = anchor.anchor_id().expect("runtime anchor identity");
        let custody = RuntimeDependencyGenerationCustody {
            generation_id: generation_id.clone(),
            generation_canonical_bytes: generation
                .canonical_bytes()
                .expect("runtime generation bytes"),
            identity_catalog_canonical_bytes: catalog.canonical_bytes().expect("catalog bytes"),
            external_dependency_canonical_bytes: external_bytes,
            authority_admission_canonical_bytes: authority_bytes,
            trust_anchor_canonical_bytes: anchor.canonical_bytes().expect("anchor bytes"),
            admission_receipt_set_canonical_bytes: receipt_set
                .canonical_bytes()
                .expect("receipt bytes"),
        };
        RuntimeDependencyCustodyFixture {
            generation_id,
            trust_anchor_id,
            canonical_custody_bytes: custody
                .canonical_closure_bytes()
                .expect("runtime custody bytes"),
        }
    }

    #[allow(clippy::too_many_lines)] // Compatibility argument surface remains intentionally exact.
    /// Builds one fully authenticated dependency closure for downstream
    /// qualification tests.
    ///
    /// # Panics
    ///
    /// Panics when supplied fixture identities or references are internally
    /// inconsistent. This constructor is feature-gated qualification
    /// scaffolding and deliberately fails closed on invalid fixture input.
    #[must_use]
    pub fn authenticated_runtime_fixture(
        seed: u8,
        runtime_identities: Vec<IdentityRef>,
        external_inputs: Vec<(RecordRef, Vec<u8>)>,
        operation_authorizations: Vec<RecordRef>,
        invocation_authentication: Vec<RecordRef>,
    ) -> AuthenticatedRuntimeDependencyClosure {
        let fixture = runtime_dependency_custody_fixture(
            seed,
            runtime_identities,
            external_inputs,
            operation_authorizations,
            invocation_authentication,
            RuntimeDependencyFixtureScenario::Exact,
        );
        fixture_reopen(&fixture).expect("authenticated runtime dependencies")
    }

    #[cfg(test)]
    fn closed_scenario_inputs() -> (RecordRef, RecordRef, RecordRef) {
        (
            record_ref(
                "example.runtime_fixture_external.v1",
                b"closed external fixture bytes",
            ),
            record_ref(
                RuntimeSchema::OperationAuthorizationV1.as_str(),
                b"closed operation authorization",
            ),
            record_ref(
                "example.runtime_fixture_authentication.v1",
                b"closed invocation authentication",
            ),
        )
    }

    #[cfg(test)]
    fn closed_scenario_fixture(
        scenario: RuntimeDependencyFixtureScenario,
    ) -> RuntimeDependencyCustodyFixture {
        let (external, operation, authentication) = closed_scenario_inputs();
        runtime_dependency_custody_fixture(
            43,
            Vec::new(),
            vec![
                (external, b"closed external fixture bytes".to_vec()),
                (
                    authentication.clone(),
                    b"closed invocation authentication".to_vec(),
                ),
            ],
            vec![operation],
            vec![authentication],
            scenario,
        )
    }

    #[test]
    fn neutral_exact_fixture_earns_standing_only_after_production_reopen() {
        let fixture = closed_scenario_fixture(RuntimeDependencyFixtureScenario::Exact);
        assert!(!fixture.canonical_custody_bytes().is_empty());
        let reopened = fixture_reopen(&fixture).expect("exact fixture reopens");
        assert_eq!(reopened.generation_id(), fixture.generation_id());
        assert_eq!(
            reopened
                .custody()
                .trust_anchor_id()
                .expect("reopened fixture root"),
            *fixture.trust_anchor_id()
        );

        let compatibility = authenticated_runtime_fixture(
            43,
            Vec::new(),
            vec![(
                record_ref(
                    "example.runtime_fixture_external.v1",
                    b"closed external fixture bytes",
                ),
                b"closed external fixture bytes".to_vec(),
            )],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            compatibility
                .custody()
                .reopen(
                    &compatibility
                        .custody()
                        .trust_anchor_id()
                        .expect("compatibility root")
                )
                .expect("compatibility fixture proves reopen")
                .generation_id(),
            compatibility.generation_id()
        );
    }

    #[test]
    fn closed_external_scenarios_preserve_availability_and_exact_missing() {
        let (external, _, _) = closed_scenario_inputs();
        for (availability, expected) in [
            (
                ExternalDependencyAvailability::ArchivedRetrieved,
                "archived_retrieved",
            ),
            (
                ExternalDependencyAvailability::CommittedUnavailable,
                "committed_unavailable",
            ),
        ] {
            let fixture =
                closed_scenario_fixture(RuntimeDependencyFixtureScenario::ExternalAvailability {
                    reference: external.clone(),
                    availability,
                });
            let reopened = fixture_reopen(&fixture).expect("availability fixture reopens");
            let resolution = reopened
                .resolve_sources(
                    &[
                        ExternalSourceRequirement::generation_match(external.clone())
                            .expect("external requirement"),
                    ],
                    &[],
                )
                .expect("availability resolution");
            match (expected, resolution.external()[0].state()) {
                (
                    "archived_retrieved",
                    ExternalSourceState::Available {
                        availability: ExternalDependencyAvailability::ArchivedRetrieved,
                        exact_bytes,
                        ..
                    },
                ) => assert_eq!(*exact_bytes, b"closed external fixture bytes"),
                ("committed_unavailable", ExternalSourceState::CommittedUnavailable { .. }) => {}
                (_, state) => panic!("unexpected availability state: {state:?}"),
            }
        }

        for scenario in [
            RuntimeDependencyFixtureScenario::ExternalOmitted {
                reference: external.clone(),
            },
            RuntimeDependencyFixtureScenario::ExternalValidReplacement {
                reference: external.clone(),
            },
        ] {
            let fixture = closed_scenario_fixture(scenario);
            let reopened = fixture_reopen(&fixture).expect("closed external fixture reopens");
            let resolution = reopened
                .resolve_sources(
                    &[
                        ExternalSourceRequirement::generation_match(external.clone())
                            .expect("external requirement"),
                    ],
                    &[],
                )
                .expect("external missing resolution");
            assert!(matches!(
                resolution.external()[0].state(),
                ExternalSourceState::Missing
            ));
        }
    }

    #[test]
    fn closed_authority_scenarios_preserve_reference_and_purpose_failures() {
        let (_, operation, authentication) = closed_scenario_inputs();
        for (reference, kind) in [
            (
                operation.clone(),
                AuthorityAdmissionKind::OperationAuthorization,
            ),
            (
                authentication.clone(),
                AuthorityAdmissionKind::InvocationAuthentication,
            ),
        ] {
            for scenario in [
                RuntimeDependencyFixtureScenario::AuthorityOmitted {
                    reference: reference.clone(),
                    kind,
                },
                RuntimeDependencyFixtureScenario::AuthorityWrongReference {
                    reference: reference.clone(),
                    kind,
                },
            ] {
                let fixture = closed_scenario_fixture(scenario);
                let reopened = fixture_reopen(&fixture).expect("authority fixture reopens");
                let requirement = match kind {
                    AuthorityAdmissionKind::OperationAuthorization => {
                        AuthoritySourceRequirement::operation_authorization(reference.clone())
                    }
                    AuthorityAdmissionKind::InvocationAuthentication => {
                        AuthoritySourceRequirement::invocation_authentication(reference.clone())
                    }
                }
                .expect("authority requirement");
                let resolution = reopened
                    .resolve_sources(&[], &[requirement])
                    .expect("authority missing resolution");
                assert!(matches!(
                    resolution.authority()[0].state(),
                    AuthoritySourceState::RequiredAdmissionMissing
                ));
            }

            let wrong_purpose =
                closed_scenario_fixture(RuntimeDependencyFixtureScenario::AuthorityWrongPurpose {
                    reference,
                    kind,
                });
            assert!(matches!(
                fixture_reopen(&wrong_purpose),
                Err(DependencyCustodyError::AuthorityAdmissionKindMismatch)
            ));
        }
    }

    #[test]
    fn closed_signed_receipt_scenarios_fail_at_exact_coverage_boundaries() {
        let (external, operation, _) = closed_scenario_inputs();
        for target in [
            RuntimeDependencyFixtureReceiptTarget::External(external),
            RuntimeDependencyFixtureReceiptTarget::Authority {
                reference: operation,
                kind: AuthorityAdmissionKind::OperationAuthorization,
            },
        ] {
            let omitted =
                closed_scenario_fixture(RuntimeDependencyFixtureScenario::SignedReceiptOmitted {
                    target: target.clone(),
                });
            assert!(matches!(
                fixture_reopen(&omitted),
                Err(DependencyCustodyError::DependencyAdmissionReceiptMissing)
            ));

            let substituted = closed_scenario_fixture(
                RuntimeDependencyFixtureScenario::SignedReceiptSubstituted { target },
            );
            assert!(matches!(
                fixture_reopen(&substituted),
                Err(DependencyCustodyError::DependencyAdmissionReceiptSubstitution)
            ));
        }

        let extraneous =
            closed_scenario_fixture(RuntimeDependencyFixtureScenario::SignedReceiptExtraneous);
        assert!(matches!(
            fixture_reopen(&extraneous),
            Err(DependencyCustodyError::ExtraneousDependencyAdmissionReceipt)
        ));
    }

    fn fixture_with_external_availability(
        fixture: &Fixture,
        seed: u8,
        availability: ExternalDependencyAvailability,
    ) -> (AuthenticatedRuntimeDependencyClosure, RecordRef) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let catalog =
            CatalogSnapshot::decode_canonical(&fixture.catalog_bytes).expect("fixture catalog");
        let mut external = ExternalDependencySnapshot::decode_canonical(&fixture.external_bytes)
            .expect("fixture external snapshot");
        let reference = external.dependencies[0].reference.clone();
        external.dependencies[0].availability = availability;
        if availability == ExternalDependencyAvailability::CommittedUnavailable {
            external.dependencies[0].exact_bytes_hex = None;
        }
        let external = ExternalDependencySnapshot::new(external.dependencies.clone())
            .expect("availability-specific snapshot");
        let authority = AuthorityAdmissionSnapshot::decode_canonical(&fixture.authority_bytes)
            .expect("fixture authority snapshot");
        let signed_at = timestamp("2026-07-29T17:01:00-04:00");
        let receipts = fixture.receipt_set.receipts.clone();
        let manifest = SignedAdmissionReceiptSet::fixture_manifest_digest(
            &fixture.anchor,
            &signed_at,
            &receipts,
        )
        .expect("receipt manifest");
        let generation = RuntimeDependencyGeneration::derive(
            &catalog,
            &external,
            &authority,
            &fixture.anchor,
            manifest,
        )
        .expect("dependency generation");
        let receipt_set = SignedAdmissionReceiptSet::fixture_signed(
            &generation,
            &fixture.anchor,
            signed_at,
            receipts,
            &signing_key,
        )
        .expect("receipt set");
        let dependencies = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            &fixture.catalog_bytes,
            &external.canonical_bytes().expect("external bytes"),
            &fixture.authority_bytes,
            &fixture.anchor,
            &AdmissionReceiptSetCustody::available(
                AdmissionReceiptSetAvailability::Online,
                receipt_set.canonical_bytes().expect("receipt bytes"),
            )
            .expect("receipt custody"),
        )
        .expect("authenticated availability-specific closure");
        (dependencies, reference)
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
            DependencyCustodyError::DependencyTrustAnchorSubstitution { .. }
        ));

        let attacker_receipts = AdmissionReceiptSetCustody::available(
            AdmissionReceiptSetAvailability::Online,
            attacker
                .receipt_set
                .canonical_bytes()
                .expect("attacker receipt bytes"),
        )
        .expect("attacker receipt custody");
        let error = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            &legitimate.catalog_bytes,
            &legitimate.external_bytes,
            &legitimate.authority_bytes,
            &legitimate.anchor,
            &attacker_receipts,
        )
        .expect_err("self-derived pin and receipt set cannot replace signed trust");
        assert!(matches!(
            error,
            DependencyCustodyError::AdmissionReceiptSetBindingMismatch
                | DependencyCustodyError::AdmissionReceiptSetSignatureInvalid
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
            let error = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
                &fixture.catalog_bytes,
                &fixture.external_bytes,
                &fixture.authority_bytes,
                &fixture.anchor,
                &custody,
            )
            .expect_err("changing any signed receipt field must fail");
            assert!(matches!(
                error,
                DependencyCustodyError::AdmissionReceiptSetBindingMismatch
                    | DependencyCustodyError::AdmissionReceiptSetSignatureInvalid
            ));
        }
    }

    #[test]
    fn unavailable_receipt_custody_refuses_before_parsing_or_verifying() {
        let fixture = fixture(7);
        let custody =
            AdmissionReceiptSetCustody::committed_unavailable(sha256_bytes(b"sealed elsewhere"));
        let error = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            b"not a catalog",
            b"not external dependencies",
            b"not authority admissions",
            &fixture.anchor,
            &custody,
        )
        .expect_err("unavailable signed evidence must refuse first");
        assert!(matches!(
            error,
            DependencyCustodyError::AdmissionReceiptSetUnavailable
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
            DependencyCustodyError::AdmissionReceiptSetByteSubstitution
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
        let error = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            &fixture.catalog_bytes,
            &fixture.external_bytes,
            &fixture.authority_bytes,
            &fixture.anchor,
            &custody,
        )
        .expect_err("closed set extension must fail");
        assert!(matches!(
            error,
            DependencyCustodyError::AdmissionReceiptSetBindingMismatch
                | DependencyCustodyError::AdmissionReceiptSetSignatureInvalid
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

        let error = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            &fixture.catalog_bytes,
            &fixture.external_bytes,
            &fixture.authority_bytes,
            &fixture.anchor,
            &custody,
        )
        .expect_err("signed receipts remain a closed snapshot closure");
        assert!(matches!(
            error,
            DependencyCustodyError::ExtraneousDependencyAdmissionReceipt
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
        let error = AuthenticatedRuntimeDependencyClosure::decode_authenticated(
            &fixture.catalog_bytes,
            &fixture.external_bytes,
            &fixture.authority_bytes,
            &fixture.anchor,
            &custody,
        )
        .expect_err("wrong key cannot mint receipts under stored anchor");
        assert!(matches!(
            error,
            DependencyCustodyError::AdmissionReceiptSetSignatureInvalid
        ));
    }

    #[test]
    fn exact_bound_reopen_checks_length_digest_generation_and_root() {
        let fixture = fixture(7);
        let dependencies = fixture.decode().expect("authenticated dependencies");
        let canonical_custody = dependencies
            .custody()
            .canonical_closure_bytes()
            .expect("canonical custody");
        let generation_id = dependencies.generation_id().clone();
        let trust_anchor_id = fixture.anchor.anchor_id().expect("anchor identity");
        let digest = sha256_bytes(&canonical_custody);
        let length = u64::try_from(canonical_custody.len()).expect("fixture length");
        let binding = ExactDependencyCustodyBinding::new(
            generation_id.clone(),
            trust_anchor_id.clone(),
            digest.clone(),
            length,
        )
        .expect("exact binding");

        let reopened =
            AuthenticatedRuntimeDependencyClosure::reopen_bound(&canonical_custody, &binding)
                .expect("bound reopen");
        assert_eq!(reopened.generation_id(), &generation_id);

        let wrong_length = ExactDependencyCustodyBinding::new(
            generation_id.clone(),
            trust_anchor_id.clone(),
            digest,
            length + 1,
        )
        .expect("wrong-length binding");
        assert!(matches!(
            AuthenticatedRuntimeDependencyClosure::reopen_bound(&canonical_custody, &wrong_length),
            Err(DependencyCustodyError::CustodyLengthMismatch { .. })
        ));

        let wrong_digest = ExactDependencyCustodyBinding::new(
            generation_id.clone(),
            trust_anchor_id.clone(),
            sha256_bytes(b"substituted custody"),
            length,
        )
        .expect("wrong-digest binding");
        assert!(matches!(
            AuthenticatedRuntimeDependencyClosure::reopen_bound(&canonical_custody, &wrong_digest),
            Err(DependencyCustodyError::CustodyDigestMismatch { .. })
        ));

        let wrong_generation = ExactDependencyCustodyBinding::new(
            sha256_bytes(b"another generation"),
            trust_anchor_id.clone(),
            sha256_bytes(&canonical_custody),
            length,
        )
        .expect("wrong-generation binding");
        assert!(matches!(
            AuthenticatedRuntimeDependencyClosure::reopen_bound(
                &canonical_custody,
                &wrong_generation
            ),
            Err(DependencyCustodyError::RuntimeDependencyGenerationSubstitution)
        ));

        let wrong_root = ExactDependencyCustodyBinding::new(
            generation_id,
            sha256_bytes(b"another root"),
            sha256_bytes(&canonical_custody),
            length,
        )
        .expect("wrong-root binding");
        assert!(matches!(
            AuthenticatedRuntimeDependencyClosure::reopen_bound(&canonical_custody, &wrong_root),
            Err(DependencyCustodyError::DependencyTrustAnchorSubstitution { .. })
        ));
    }

    #[test]
    fn source_resolution_preserves_physical_and_authority_requirements() {
        let fixture = fixture(7);
        let dependencies = fixture.decode().expect("authenticated dependencies");
        let external_reference = dependencies.external_dependency_snapshot().dependencies[0]
            .reference
            .clone();
        let admitted_authentication = dependencies
            .authority_admission_snapshot()
            .admissions
            .iter()
            .find(|admission| admission.kind == AuthorityAdmissionKind::InvocationAuthentication)
            .expect("authentication admission")
            .reference
            .clone();
        let resolution = dependencies
            .resolve_sources(
                &[
                    ExternalSourceRequirement::capability(external_reference.clone())
                        .expect("capability requirement"),
                    ExternalSourceRequirement::invocation_authentication(
                        external_reference.clone(),
                    )
                    .expect("physical authentication requirement"),
                ],
                &[
                    AuthoritySourceRequirement::invocation_authentication(admitted_authentication)
                        .expect("authority authentication requirement"),
                ],
            )
            .expect("source resolution");

        assert_eq!(resolution.external().len(), 2);
        assert!(resolution.external().iter().all(|result| matches!(
            result.state(),
            ExternalSourceState::Available { exact_bytes, .. }
                if *exact_bytes == b"exact external diagnostic input"
        )));
        assert!(matches!(
            resolution.authority()[0].state(),
            AuthoritySourceState::Admitted { .. }
        ));

        let split_resolution =
            dependencies
                .resolve_sources(
                    &[ExternalSourceRequirement::invocation_authentication(
                        external_reference.clone(),
                    )
                    .expect("physical authentication requirement")],
                    &[
                        AuthoritySourceRequirement::invocation_authentication(external_reference)
                            .expect("separate authority requirement"),
                    ],
                )
                .expect("split source resolution");
        assert!(matches!(
            split_resolution.external()[0].state(),
            ExternalSourceState::Available { .. }
        ));
        assert!(matches!(
            split_resolution.authority()[0].state(),
            AuthoritySourceState::RequiredAdmissionMissing
        ));
    }

    #[test]
    fn resolution_refuses_duplicate_requirements_and_ineligible_references() {
        let fixture = fixture(7);
        let dependencies = fixture.decode().expect("authenticated dependencies");
        let external_reference = dependencies.external_dependency_snapshot().dependencies[0]
            .reference
            .clone();
        let external_requirement = ExternalSourceRequirement::generation_match(external_reference)
            .expect("generation requirement");
        assert!(matches!(
            dependencies
                .resolve_sources(&[external_requirement.clone(), external_requirement], &[]),
            Err(DependencyCustodyError::DuplicateExternalSourceRequirement)
        ));

        let authority_reference = dependencies
            .authority_admission_snapshot()
            .admissions
            .iter()
            .find(|admission| admission.kind == AuthorityAdmissionKind::OperationAuthorization)
            .expect("operation admission")
            .reference
            .clone();
        let authority_requirement =
            AuthoritySourceRequirement::operation_authorization(authority_reference.clone())
                .expect("operation requirement");
        assert!(matches!(
            dependencies
                .resolve_sources(&[], &[authority_requirement.clone(), authority_requirement]),
            Err(DependencyCustodyError::DuplicateAuthoritySourceRequirement)
        ));
        assert!(matches!(
            ExternalSourceRequirement::capability(authority_reference),
            Err(DependencyCustodyError::ExternalSourceRequirementInvalid)
        ));
        assert!(matches!(
            AuthoritySourceRequirement::operation_authorization(record_ref(
                "example.not_authorization.v1",
                b"not authorization",
            )),
            Err(DependencyCustodyError::AuthoritySourceRequirementInvalid)
        ));
    }

    #[test]
    fn committed_unavailable_source_resolves_without_fabricating_bytes() {
        let fixture = fixture(7);
        let (dependencies, reference) = fixture_with_external_availability(
            &fixture,
            7,
            ExternalDependencyAvailability::CommittedUnavailable,
        );
        let resolution = dependencies
            .resolve_sources(
                &[
                    ExternalSourceRequirement::custody_reservation_commit(reference)
                        .expect("custody requirement"),
                ],
                &[],
            )
            .expect("source resolution");
        assert!(matches!(
            resolution.external()[0].state(),
            ExternalSourceState::CommittedUnavailable { .. }
        ));
    }

    #[test]
    fn archived_retrieved_source_exposes_exact_authenticated_bytes() {
        let fixture = fixture(7);
        let (dependencies, reference) = fixture_with_external_availability(
            &fixture,
            7,
            ExternalDependencyAvailability::ArchivedRetrieved,
        );
        let resolution = dependencies
            .resolve_sources(
                &[ExternalSourceRequirement::generation_match(reference)
                    .expect("generation requirement")],
                &[],
            )
            .expect("source resolution");
        assert!(matches!(
            resolution.external()[0].state(),
            ExternalSourceState::Available {
                availability: ExternalDependencyAvailability::ArchivedRetrieved,
                exact_bytes,
                ..
            } if *exact_bytes == b"exact external diagnostic input"
        ));
    }

    #[test]
    fn missing_external_and_exact_operation_authorization_remain_distinct() {
        let fixture = fixture(7);
        let dependencies = fixture.decode().expect("authenticated dependencies");
        let missing_reference = record_ref("example.missing.v1", b"missing");
        let operation_reference = dependencies
            .authority_admission_snapshot()
            .admissions
            .iter()
            .find(|admission| admission.kind == AuthorityAdmissionKind::OperationAuthorization)
            .expect("operation authorization admission")
            .reference
            .clone();
        let resolution = dependencies
            .resolve_sources(
                &[ExternalSourceRequirement::capability(missing_reference)
                    .expect("missing external requirement")],
                &[
                    AuthoritySourceRequirement::operation_authorization(operation_reference)
                        .expect("operation authorization requirement"),
                ],
            )
            .expect("source resolution");
        assert!(matches!(
            resolution.external()[0].state(),
            ExternalSourceState::Missing
        ));
        assert!(matches!(
            resolution.authority()[0].state(),
            AuthoritySourceState::Admitted { .. }
        ));
    }
}
