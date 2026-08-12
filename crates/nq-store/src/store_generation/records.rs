//! Canonical foundational C2 Store-generation records.
//!
//! Constructors in this module validate closed structural invariants and
//! compute canonical bytes and semantic identities.  Signature authenticity,
//! Store-complete currentness, physical descriptor observations, and durable
//! append results are deliberately separate evidence inputs; no Boolean in a
//! record can stand in for those proofs.

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use nq_protocol::{CanonicalizationError, Sha256Digest, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Key-enrollment carrier schema.
pub const STORE_INTEGRITY_KEY_ENROLLMENT_SCHEMA_V1: &str =
    "nq.c2_store_integrity_key_enrollment.v1";
/// Key-enrollment semantic identity domain.
pub const STORE_INTEGRITY_KEY_ENROLLMENT_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.store_integrity_key_enrollment.identity.v1";
/// External terminal-A1 bootstrap-grant signature domain consumed by the
/// corrected enrollment provenance chain.
pub const STORE_INTEGRITY_BOOTSTRAP_GRANT_A1_SIGNATURE_DOMAIN_V1: &str =
    "nq.c2.store_integrity_bootstrap_grant.a1_signature.v1";
/// The sole accepted Store-integrity key algorithm.
pub const ED25519_STORE_INTEGRITY_ALGORITHM_V1: &str = "ed25519_store_integrity_v1";
const IJSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Store-generation install-policy carrier schema.
pub const STORE_GENERATION_INSTALL_POLICY_SCHEMA_V1: &str =
    "nq.c2_store_generation_install_policy.v1";
/// Store-generation install-policy semantic identity domain.
pub const STORE_GENERATION_INSTALL_POLICY_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.store_generation_install_policy.identity.v1";
/// Canonical pre-policy calculation schema authenticated by MSG-01.
pub const STORE_GENERATION_INSTALL_POLICY_CALCULATION_SCHEMA_V1: &str =
    "nq.c2_store_generation_install_policy_calculation.v1";
/// Semantic identity domain for the complete acyclic pre-policy calculation.
pub const STORE_GENERATION_INSTALL_POLICY_CALCULATION_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.store_generation_install_policy_calculation.identity.v1";
/// Sole accepted append-extent layout.
pub const APPEND_EXTENT_LAYOUT_V1: &str = "nq.append_extent_layout.v1";
/// Sole accepted production backend.
pub const LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1: &str =
    "linux_posix_fallocate_regular_file_v1";

macro_rules! digest_identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Bind an already parsed SHA-256 semantic identity to this exact
            /// coordinate.  This is data typing, not authority construction.
            #[must_use]
            pub const fn new(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// Exact algorithm-qualified digest.
            #[must_use]
            pub const fn digest(&self) -> &Sha256Digest {
                &self.0
            }
        }
    };
}

/// Exact bounded Gen4 Store occurrence identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StoreOccurrenceIdentityV1(String);

impl StoreOccurrenceIdentityV1 {
    /// Parse the closed textual occurrence coordinate used by Gen4.
    pub fn new(value: impl Into<String>) -> Result<Self, C2CanonicalRecordErrorV1> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@-".contains(&byte))
        {
            return Err(C2CanonicalRecordErrorV1::InvalidTextField("occurrence"));
        }
        Ok(Self(value))
    }

    /// Exact occurrence text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StoreOccurrenceIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}
digest_identity!(
    A2ChainRootIdentityV1,
    "Exact resident-activation chain-root identity."
);
digest_identity!(
    ControllingActivationIdentityV1,
    "Exact controlling activation identity."
);
digest_identity!(
    DependencyAnchorIdentityV1,
    "Exact runtime-dependency anchor identity."
);

/// Exact Gen4 resident identity.
///
/// Gen4 deliberately treats this as a bounded opaque string. It is not a
/// SHA-256 digest, and C2 preserves it byte-for-byte inside its enclosing
/// canonical records.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResidentIdentityV1(String);

impl ResidentIdentityV1 {
    /// Parse the exact bounded Gen4 resident coordinate.
    pub fn new(value: impl Into<String>) -> Result<Self, C2CanonicalRecordErrorV1> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(C2CanonicalRecordErrorV1::InvalidTextField(
                "resident_identity",
            ));
        }
        Ok(Self(value))
    }

    /// Exact raw Gen4 resident text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ResidentIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}
digest_identity!(RoleManifestIdentityV1, "Exact role-manifest identity.");
digest_identity!(
    EnrollmentIdentityV1,
    "Exact Store-integrity enrollment identity."
);
digest_identity!(
    BootstrapGrantIdentityV1,
    "Exact terminal-A1 bootstrap-grant identity."
);
digest_identity!(
    BootstrapGrantRequestIdentityV1,
    "Exact non-authoritative bootstrap-grant request identity."
);
digest_identity!(
    TerminalA1IssuerIdentityV1,
    "Exact uniquely resolved terminal-A1 issuer identity."
);
digest_identity!(
    StoreIntegrityProposalIdentityV1,
    "Exact inert Store-integrity key-proposal identity."
);
digest_identity!(
    StoreIntegrityEnrollmentAttemptIdentityV1,
    "Exact pre-generation enrollment-attempt identity."
);
digest_identity!(
    StoreIntegrityEnrollmentCandidateIdentityV1,
    "Exact inert pre-generation enrollment-candidate identity."
);
digest_identity!(
    StoreIntegrityCustodyEvidenceIdentityV1,
    "Exact verified pre-generation key-custody correspondence identity."
);
digest_identity!(
    StoreIntegrityProofOfPossessionIdentityV1,
    "Exact possession-only proof identity."
);
/// Exact A2 applicability-only interpretation rule. It is not grant authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct A2ApplicabilityInterpretationIdentityV1(String);

impl A2ApplicabilityInterpretationIdentityV1 {
    /// The sole accepted interpretation identifier.
    pub const EXACT: &'static str = "nq.c2.a1_runtime_dependency_admission_refinement.v1";

    /// Refuse a substituted interpretation.
    pub fn new(value: impl Into<String>) -> Result<Self, C2CanonicalRecordErrorV1> {
        let value = value.into();
        if value != Self::EXACT {
            return Err(C2CanonicalRecordErrorV1::SubstitutedClosedConstant(
                "a2_applicability_interpretation",
            ));
        }
        Ok(Self(value))
    }

    /// Exact rule text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for A2ApplicabilityInterpretationIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}
digest_identity!(
    InstallPolicyIdentityV1,
    "Exact Store-generation install-policy identity."
);
digest_identity!(
    PhysicalStoreGenerationIdentityV1,
    "Exact physical Store-generation identity."
);
digest_identity!(
    SignerLifecycleRootIdentityV1,
    "Exact immutable signer-lifecycle-root identity."
);
digest_identity!(
    SignerScopePolicyIdentityV1,
    "Exact signer-scope policy identity."
);
digest_identity!(
    ActiveStorePolicyIdentityV1,
    "Exact active Store policy identity."
);
digest_identity!(
    BootstrapIdentityV1,
    "Exact physical-generation bootstrap identity."
);
digest_identity!(
    InstallationReceiptIdentityV1,
    "Exact installation receipt identity."
);
digest_identity!(
    RestoreDispositionIdentityV1,
    "Exact Gen4 restore-disposition identity."
);
digest_identity!(
    QualifiedBackendProfileIdentityV1,
    "Exact qualified-backend profile identity."
);

/// Total, structural C2 cut coordinate.  This is not wall-clock time.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2StructuralCutV1 {
    /// Store authority-ledger position.
    pub ledger_position: u64,
    /// Effect position within that ledger frontier.
    pub effect_position: u32,
}

/// Store-integrity key-generation number.  Generation zero is the exact
/// initial enrollment; successors are strictly increasing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StoreIntegrityKeyGenerationV1(u32);

impl StoreIntegrityKeyGenerationV1 {
    /// Construct a generation number, including the exact initial value zero.
    pub fn new(value: u32) -> Result<Self, C2CanonicalRecordErrorV1> {
        Ok(Self(value))
    }

    /// Numeric generation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Canonical lower-case hexadecimal Ed25519 public key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Ed25519StoreIntegrityPublicKeyV1(String);

impl Ed25519StoreIntegrityPublicKeyV1 {
    /// Parse and cryptographically validate exactly 32 Ed25519 public-key
    /// bytes represented as 64 lower-case hexadecimal characters.
    pub fn from_lower_hex(value: impl Into<String>) -> Result<Self, C2CanonicalRecordErrorV1> {
        let value = value.into();
        let bytes = decode_exact_lower_hex::<32>(&value)
            .map_err(|()| C2CanonicalRecordErrorV1::MalformedEd25519PublicKey)?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| C2CanonicalRecordErrorV1::MalformedEd25519PublicKey)?;
        Ok(Self(value))
    }

    /// Canonical lower-case hexadecimal bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Ed25519StoreIntegrityPublicKeyV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_lower_hex(value).map_err(serde::de::Error::custom)
    }
}

/// Canonical lower-case hexadecimal Ed25519 signature bytes.
///
/// Structural parsing here does not claim signature authenticity.  The exact
/// terminal-A1, dependency-anchor, or Store-integrity verifier owns that
/// judgment according to the exact carrier family.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Ed25519SignatureBytesV1(String);

impl Ed25519SignatureBytesV1 {
    /// Parse exactly 64 signature bytes represented as 128 lower-case
    /// hexadecimal characters.
    pub fn from_lower_hex(value: impl Into<String>) -> Result<Self, C2CanonicalRecordErrorV1> {
        let value = value.into();
        decode_exact_lower_hex::<64>(&value)
            .map_err(|()| C2CanonicalRecordErrorV1::MalformedEd25519Signature)?;
        Ok(Self(value))
    }

    /// Canonical lower-case hexadecimal bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Ed25519SignatureBytesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_lower_hex(value).map_err(serde::de::Error::custom)
    }
}

fn decode_exact_lower_hex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let decoded = hex::decode(value).map_err(|_| ())?;
    decoded.try_into().map_err(|_| ())
}

/// Canonical record construction or correspondence refusal.
#[derive(Debug, Error)]
pub enum C2CanonicalRecordErrorV1 {
    /// Canonical JSON or semantic identity production failed.
    #[error(transparent)]
    Canonicalization(#[from] CanonicalizationError),
    /// A required bounded textual identity was absent or too large.
    #[error("required field `{0}` is empty or exceeds 256 UTF-8 bytes")]
    InvalidTextField(&'static str),
    /// Public-key bytes do not encode an accepted Ed25519 verifying key.
    #[error("Store-integrity public key is not exact canonical Ed25519 bytes")]
    MalformedEd25519PublicKey,
    /// Signature bytes are not exactly 64 canonical Ed25519 bytes.
    #[error("signature is not exactly 64 lower-case hexadecimal bytes")]
    MalformedEd25519Signature,
    /// The first/predecessor law is inconsistent with the generation number.
    #[error("enrollment predecessor is absent only for generation zero")]
    InvalidEnrollmentPredecessor,
    /// Installed maxima do not contain this record or violate key <= policy.
    #[error("installed policy/key maxima are zero, inconsistent, or exceeded")]
    InvalidInstalledMaximum,
    /// Enrollment purposes were absent or outside the closed provenance set.
    #[error("at least one provenance-only enrollment purpose is required")]
    MissingEnrollmentPurpose,
    /// Enrollment chain is gapped, forked, duplicated, or changes immutable
    /// correspondence.
    #[error("Store-integrity enrollment chain is not exact and linear")]
    InvalidEnrollmentChain,
    /// Current activation, external grant, enrollment, or policy correspondence is
    /// inconsistent.
    #[error("install-policy/enrollment/current-tip association mismatch")]
    InstallPolicyEnrollmentMismatch,
    /// A signature-authentication witness names another canonical record.
    #[error("anchor-authentication witness is detached from its record")]
    DetachedAnchorAuthentication,
    /// A structurally valid enrollment does not match the exact verified
    /// terminal-A1 grant chain.
    #[error("terminal-A1 bootstrap grant is detached from its enrollment")]
    DetachedBootstrapGrant,
    /// The installation-mode union is partial or contradictory.
    #[error("fresh and restore-successor installation fields do not form one closed mode")]
    InvalidInstallationMode,
    /// Carrier geometry is zero, overflowing, or cannot contain its bounded G
    /// refusal vocabulary.
    #[error("installed B/G carrier geometry is invalid")]
    InvalidCarrierGeometry,
    /// A fixed schema/backend/layout value differs from the sole accepted
    /// implementation value.
    #[error("closed implementation constant `{0}` has a substituted value")]
    SubstitutedClosedConstant(&'static str),
    /// Durable record bytes are malformed or are not the exact RFC 8785 form.
    #[error("canonical C2 record bytes are malformed or noncanonical")]
    MalformedOrNoncanonical,
}

fn validate_text(value: &str, name: &'static str) -> Result<(), C2CanonicalRecordErrorV1> {
    if value.is_empty() || value.len() > 256 {
        return Err(C2CanonicalRecordErrorV1::InvalidTextField(name));
    }
    Ok(())
}

/// Common read-only surface of every canonical C2 record.
pub trait CanonicalC2RecordV1: Serialize {
    /// Exact schema string embedded in canonical bytes.
    fn schema(&self) -> &'static str;
    /// Canonical JCS bytes of the complete carrier.
    fn canonical_bytes(&self) -> &[u8];
    /// Semantic SHA-256 identity of those exact bytes.
    fn canonical_identity(&self) -> &Sha256Digest;
}

/// Closed, provenance-only reasons an enrollment remains retained.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentProvenancePurposeV1 {
    /// Verify the immutable physical-generation bootstrap.
    PhysicalGenerationBootstrapVerification,
    /// Verify retained active-policy and transition frames.
    ActivePolicyFrameVerification,
    /// Verify retained installation intent and receipt frames.
    InstallationFrameVerification,
    /// Preserve verification of future retained downstream material without
    /// granting current signing authority.
    FutureRetainedMaterialVerification,
}

/// Complete non-authority input to a key-enrollment carrier constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreIntegrityKeyEnrollmentInputV1 {
    pub occurrence: StoreOccurrenceIdentityV1,
    pub signer_scope_policy: SignerScopePolicyIdentityV1,
    pub signer_scope_policy_version: u64,
    pub a2_chain_root: A2ChainRootIdentityV1,
    pub controlling_activation: ControllingActivationIdentityV1,
    pub dependency_anchor: DependencyAnchorIdentityV1,
    pub resident: ResidentIdentityV1,
    pub resident_generation: u64,
    pub role: String,
    pub role_manifest: RoleManifestIdentityV1,
    pub role_manifest_generation: u64,
    pub domain: String,
    pub activation_policy_version: u64,
    pub active_store_policy: ActiveStorePolicyIdentityV1,
    pub active_store_policy_generation: u64,
    pub authority_cut: C2StructuralCutV1,
    pub candidate_cut: C2StructuralCutV1,
    pub pop_cut: C2StructuralCutV1,
    pub enrollment_cut: C2StructuralCutV1,
    pub public_key: Ed25519StoreIntegrityPublicKeyV1,
    pub key_generation: StoreIntegrityKeyGenerationV1,
    pub predecessor_enrollment: Option<EnrollmentIdentityV1>,
    pub maximum_retained_key_generations: u32,
    pub provenance_purposes: BTreeSet<EnrollmentProvenancePurposeV1>,
    pub bootstrap_grant_request: BootstrapGrantRequestIdentityV1,
    pub bootstrap_grant: BootstrapGrantIdentityV1,
    pub bootstrap_grant_signature: Ed25519SignatureBytesV1,
    pub bootstrap_issuer: TerminalA1IssuerIdentityV1,
    pub bootstrap_issuer_key_generation: u64,
    pub attempt_identity: StoreIntegrityEnrollmentAttemptIdentityV1,
    pub proposal_identity: StoreIntegrityProposalIdentityV1,
    pub candidate_identity: StoreIntegrityEnrollmentCandidateIdentityV1,
    pub custody_evidence_identity: StoreIntegrityCustodyEvidenceIdentityV1,
    pub proof_of_possession_identity: StoreIntegrityProofOfPossessionIdentityV1,
    pub interpretation_policy: A2ApplicabilityInterpretationIdentityV1,
    pub predecessor_grant: Option<BootstrapGrantIdentityV1>,
    pub superseded_grant: Option<BootstrapGrantIdentityV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreIntegrityKeyEnrollmentBodyV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    occurrence: StoreOccurrenceIdentityV1,
    signer_scope_policy: SignerScopePolicyIdentityV1,
    signer_scope_policy_version: u64,
    a2_chain_root: A2ChainRootIdentityV1,
    controlling_activation: ControllingActivationIdentityV1,
    dependency_anchor: DependencyAnchorIdentityV1,
    resident: ResidentIdentityV1,
    resident_generation: u64,
    role: String,
    role_manifest: RoleManifestIdentityV1,
    role_manifest_generation: u64,
    domain: String,
    activation_policy_version: u64,
    active_store_policy: ActiveStorePolicyIdentityV1,
    active_store_policy_generation: u64,
    authority_cut: C2StructuralCutV1,
    candidate_cut: C2StructuralCutV1,
    pop_cut: C2StructuralCutV1,
    enrollment_cut: C2StructuralCutV1,
    algorithm: String,
    public_key: Ed25519StoreIntegrityPublicKeyV1,
    key_generation: StoreIntegrityKeyGenerationV1,
    predecessor_enrollment: Option<EnrollmentIdentityV1>,
    maximum_retained_key_generations: u32,
    provenance_purposes: BTreeSet<EnrollmentProvenancePurposeV1>,
    bootstrap_grant_request: BootstrapGrantRequestIdentityV1,
    bootstrap_grant: BootstrapGrantIdentityV1,
    bootstrap_grant_signature_domain: String,
    bootstrap_grant_signature: Ed25519SignatureBytesV1,
    bootstrap_issuer: TerminalA1IssuerIdentityV1,
    bootstrap_issuer_key_generation: u64,
    attempt_identity: StoreIntegrityEnrollmentAttemptIdentityV1,
    proposal_identity: StoreIntegrityProposalIdentityV1,
    candidate_identity: StoreIntegrityEnrollmentCandidateIdentityV1,
    custody_evidence_identity: StoreIntegrityCustodyEvidenceIdentityV1,
    proof_of_possession_identity: StoreIntegrityProofOfPossessionIdentityV1,
    interpretation_policy: A2ApplicabilityInterpretationIdentityV1,
    predecessor_grant: Option<BootstrapGrantIdentityV1>,
    superseded_grant: Option<BootstrapGrantIdentityV1>,
}

fn validate_enrollment_token(
    value: &str,
    name: &'static str,
) -> Result<(), C2CanonicalRecordErrorV1> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@-".contains(&byte))
    {
        return Err(C2CanonicalRecordErrorV1::InvalidTextField(name));
    }
    Ok(())
}

fn validate_key_enrollment_body(
    body: &StoreIntegrityKeyEnrollmentBodyV1,
) -> Result<(), C2CanonicalRecordErrorV1> {
    if body.schema != STORE_INTEGRITY_KEY_ENROLLMENT_SCHEMA_V1
        || body.identity_domain != STORE_INTEGRITY_KEY_ENROLLMENT_IDENTITY_DOMAIN_V1
        || body.algorithm != ED25519_STORE_INTEGRITY_ALGORITHM_V1
        || body.bootstrap_grant_signature_domain
            != STORE_INTEGRITY_BOOTSTRAP_GRANT_A1_SIGNATURE_DOMAIN_V1
        || body.interpretation_policy.as_str() != A2ApplicabilityInterpretationIdentityV1::EXACT
    {
        return Err(C2CanonicalRecordErrorV1::SubstitutedClosedConstant(
            "foundational_enrollment",
        ));
    }
    if body.schema_version != 1 {
        return Err(C2CanonicalRecordErrorV1::SubstitutedClosedConstant(
            "foundational_enrollment_schema_version",
        ));
    }
    validate_enrollment_token(&body.role, "role")?;
    validate_enrollment_token(&body.domain, "domain")?;
    if body.resident_generation == 0
        || body.role_manifest_generation == 0
        || body.signer_scope_policy_version == 0
        || body.activation_policy_version == 0
        || body.active_store_policy_generation == 0
        || body.bootstrap_issuer_key_generation == 0
        || [
            body.resident_generation,
            body.role_manifest_generation,
            body.signer_scope_policy_version,
            body.activation_policy_version,
            body.active_store_policy_generation,
        ]
        .into_iter()
        .any(|value| value > u64::from(u32::MAX))
        || [
            body.bootstrap_issuer_key_generation,
            body.authority_cut.ledger_position,
            body.candidate_cut.ledger_position,
            body.pop_cut.ledger_position,
            body.enrollment_cut.ledger_position,
        ]
        .into_iter()
        .any(|value| value > IJSON_SAFE_INTEGER)
    {
        return Err(C2CanonicalRecordErrorV1::InvalidTextField(
            "foundational_enrollment_integer_bound",
        ));
    }
    let generation = body.key_generation.get();
    if (generation == 0) != body.predecessor_enrollment.is_none() {
        return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentPredecessor);
    }
    if body.maximum_retained_key_generations == 0
        || generation > body.maximum_retained_key_generations
    {
        return Err(C2CanonicalRecordErrorV1::InvalidInstalledMaximum);
    }
    if body.provenance_purposes.is_empty() {
        return Err(C2CanonicalRecordErrorV1::MissingEnrollmentPurpose);
    }
    if !(body.authority_cut < body.candidate_cut
        && body.candidate_cut < body.pop_cut
        && body.pop_cut < body.enrollment_cut)
    {
        return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentChain);
    }
    if generation == 0 && (body.predecessor_grant.is_some() || body.superseded_grant.is_some()) {
        return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentPredecessor);
    }
    Ok(())
}

/// Canonical Store-integrity public-key enrollment associated with one exact
/// terminal-A1 bootstrap-grant chain. The embedded dependency anchor is scope
/// correspondence only and does not authenticate this enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreIntegrityKeyEnrollmentV1 {
    body: StoreIntegrityKeyEnrollmentBodyV1,
    canonical_bytes: Vec<u8>,
    identity: EnrollmentIdentityV1,
}

impl Serialize for StoreIntegrityKeyEnrollmentV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.body.serialize(serializer)
    }
}

impl CanonicalC2RecordV1 for StoreIntegrityKeyEnrollmentV1 {
    fn schema(&self) -> &'static str {
        STORE_INTEGRITY_KEY_ENROLLMENT_SCHEMA_V1
    }

    fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn canonical_identity(&self) -> &Sha256Digest {
        self.identity.digest()
    }
}

impl StoreIntegrityKeyEnrollmentV1 {
    /// Exact enrollment identity.
    #[must_use]
    pub const fn identity(&self) -> &EnrollmentIdentityV1 {
        &self.identity
    }

    /// Exact pre-generation Store occurrence.
    #[must_use]
    pub const fn occurrence(&self) -> &StoreOccurrenceIdentityV1 {
        &self.body.occurrence
    }

    /// Exact immutable signer-scope policy.
    #[must_use]
    pub const fn signer_scope_policy(&self) -> &SignerScopePolicyIdentityV1 {
        &self.body.signer_scope_policy
    }

    #[must_use]
    pub const fn a2_chain_root(&self) -> &A2ChainRootIdentityV1 {
        &self.body.a2_chain_root
    }

    #[must_use]
    pub const fn dependency_anchor(&self) -> &DependencyAnchorIdentityV1 {
        &self.body.dependency_anchor
    }

    #[must_use]
    pub const fn resident(&self) -> &ResidentIdentityV1 {
        &self.body.resident
    }

    #[must_use]
    pub const fn resident_generation(&self) -> u64 {
        self.body.resident_generation
    }

    #[must_use]
    pub fn role(&self) -> &str {
        &self.body.role
    }

    #[must_use]
    pub const fn role_manifest(&self) -> &RoleManifestIdentityV1 {
        &self.body.role_manifest
    }

    #[must_use]
    pub const fn role_manifest_generation(&self) -> u64 {
        self.body.role_manifest_generation
    }

    #[must_use]
    pub fn authority_domain(&self) -> &str {
        &self.body.domain
    }

    #[must_use]
    pub const fn signer_scope_policy_version(&self) -> u64 {
        self.body.signer_scope_policy_version
    }

    #[must_use]
    pub const fn activation_policy_version(&self) -> u64 {
        self.body.activation_policy_version
    }

    #[must_use]
    pub const fn active_store_policy(&self) -> &ActiveStorePolicyIdentityV1 {
        &self.body.active_store_policy
    }

    #[must_use]
    pub const fn active_store_policy_generation(&self) -> u64 {
        self.body.active_store_policy_generation
    }

    /// Exact enrollment attempt.
    #[must_use]
    pub const fn attempt_identity(&self) -> &StoreIntegrityEnrollmentAttemptIdentityV1 {
        &self.body.attempt_identity
    }

    /// Exact inert candidate adopted by this enrollment.
    #[must_use]
    pub const fn candidate_identity(&self) -> &StoreIntegrityEnrollmentCandidateIdentityV1 {
        &self.body.candidate_identity
    }

    /// Exact key-custody correspondence consumed by enrollment.
    #[must_use]
    pub const fn custody_evidence_identity(&self) -> &StoreIntegrityCustodyEvidenceIdentityV1 {
        &self.body.custody_evidence_identity
    }

    #[must_use]
    pub const fn proposal_identity(&self) -> &StoreIntegrityProposalIdentityV1 {
        &self.body.proposal_identity
    }

    #[must_use]
    pub const fn bootstrap_grant_request(&self) -> &BootstrapGrantRequestIdentityV1 {
        &self.body.bootstrap_grant_request
    }

    #[must_use]
    pub const fn bootstrap_grant(&self) -> &BootstrapGrantIdentityV1 {
        &self.body.bootstrap_grant
    }

    #[must_use]
    pub fn bootstrap_grant_signature(&self) -> &str {
        self.body.bootstrap_grant_signature.as_str()
    }

    #[must_use]
    pub const fn bootstrap_issuer(&self) -> &TerminalA1IssuerIdentityV1 {
        &self.body.bootstrap_issuer
    }

    #[must_use]
    pub const fn bootstrap_issuer_key_generation(&self) -> u64 {
        self.body.bootstrap_issuer_key_generation
    }

    /// Exact possession-only proof consumed by enrollment.
    #[must_use]
    pub const fn proof_of_possession_identity(&self) -> &StoreIntegrityProofOfPossessionIdentityV1 {
        &self.body.proof_of_possession_identity
    }

    /// Cut at which the external grant was authoritative.
    #[must_use]
    pub const fn authority_cut(&self) -> C2StructuralCutV1 {
        self.body.authority_cut
    }

    /// Exact cut at which the inert candidate was fixed.
    #[must_use]
    pub const fn candidate_cut(&self) -> C2StructuralCutV1 {
        self.body.candidate_cut
    }

    /// Exact cut at which possession of the proposed key was verified.
    #[must_use]
    pub const fn pop_cut(&self) -> C2StructuralCutV1 {
        self.body.pop_cut
    }

    /// Later cut at which the foundational enrollment was adopted durably.
    #[must_use]
    pub const fn enrollment_cut(&self) -> C2StructuralCutV1 {
        self.body.enrollment_cut
    }

    /// Exact public key enrolled as evidence.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519StoreIntegrityPublicKeyV1 {
        &self.body.public_key
    }

    /// Generation selected by this enrollment.
    #[must_use]
    pub const fn key_generation(&self) -> StoreIntegrityKeyGenerationV1 {
        self.body.key_generation
    }

    /// Exact predecessor identity, absent only for generation zero.
    #[must_use]
    pub const fn predecessor_enrollment(&self) -> Option<&EnrollmentIdentityV1> {
        self.body.predecessor_enrollment.as_ref()
    }

    /// Immutable installed maximum.
    #[must_use]
    pub const fn maximum_retained_key_generations(&self) -> u32 {
        self.body.maximum_retained_key_generations
    }

    /// Exact current activation named by the external carrier.
    #[must_use]
    pub const fn controlling_activation(&self) -> &ControllingActivationIdentityV1 {
        &self.body.controlling_activation
    }

    /// Exact current activation named by the external carrier.
    #[must_use]
    pub const fn current_activation(&self) -> &ControllingActivationIdentityV1 {
        &self.body.controlling_activation
    }
}

fn construct_key_enrollment(
    input: StoreIntegrityKeyEnrollmentInputV1,
) -> Result<StoreIntegrityKeyEnrollmentV1, C2CanonicalRecordErrorV1> {
    validate_text(&input.role, "role")?;
    validate_text(&input.domain, "domain")?;
    if input.resident_generation == 0 || input.role_manifest_generation == 0 {
        return Err(C2CanonicalRecordErrorV1::InvalidTextField(
            "resident_or_role_manifest_generation",
        ));
    }
    let generation = input.key_generation.get();
    if (generation == 0) != input.predecessor_enrollment.is_none() {
        return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentPredecessor);
    }
    if input.maximum_retained_key_generations == 0
        || generation > input.maximum_retained_key_generations
    {
        return Err(C2CanonicalRecordErrorV1::InvalidInstalledMaximum);
    }
    if input.provenance_purposes.is_empty() {
        return Err(C2CanonicalRecordErrorV1::MissingEnrollmentPurpose);
    }
    if input.bootstrap_issuer_key_generation == 0
        || input.active_store_policy_generation == 0
        || input.signer_scope_policy_version == 0
        || input.activation_policy_version == 0
    {
        return Err(C2CanonicalRecordErrorV1::InvalidTextField(
            "bootstrap_issuer_or_policy_generation",
        ));
    }
    if !(input.authority_cut < input.candidate_cut
        && input.candidate_cut < input.pop_cut
        && input.pop_cut < input.enrollment_cut)
    {
        return Err(C2CanonicalRecordErrorV1::InvalidTextField(
            "foundational_enrollment_cut_order",
        ));
    }
    if generation == 0 && (input.predecessor_grant.is_some() || input.superseded_grant.is_some()) {
        return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentPredecessor);
    }

    let body = StoreIntegrityKeyEnrollmentBodyV1 {
        schema: STORE_INTEGRITY_KEY_ENROLLMENT_SCHEMA_V1.to_owned(),
        schema_version: 1,
        identity_domain: STORE_INTEGRITY_KEY_ENROLLMENT_IDENTITY_DOMAIN_V1.to_owned(),
        occurrence: input.occurrence,
        signer_scope_policy: input.signer_scope_policy,
        signer_scope_policy_version: input.signer_scope_policy_version,
        a2_chain_root: input.a2_chain_root,
        controlling_activation: input.controlling_activation,
        dependency_anchor: input.dependency_anchor,
        resident: input.resident,
        resident_generation: input.resident_generation,
        role: input.role,
        role_manifest: input.role_manifest,
        role_manifest_generation: input.role_manifest_generation,
        domain: input.domain,
        activation_policy_version: input.activation_policy_version,
        active_store_policy: input.active_store_policy,
        active_store_policy_generation: input.active_store_policy_generation,
        authority_cut: input.authority_cut,
        candidate_cut: input.candidate_cut,
        pop_cut: input.pop_cut,
        enrollment_cut: input.enrollment_cut,
        algorithm: ED25519_STORE_INTEGRITY_ALGORITHM_V1.to_owned(),
        public_key: input.public_key,
        key_generation: input.key_generation,
        predecessor_enrollment: input.predecessor_enrollment,
        maximum_retained_key_generations: input.maximum_retained_key_generations,
        provenance_purposes: input.provenance_purposes,
        bootstrap_grant_request: input.bootstrap_grant_request,
        bootstrap_grant: input.bootstrap_grant,
        bootstrap_grant_signature_domain: STORE_INTEGRITY_BOOTSTRAP_GRANT_A1_SIGNATURE_DOMAIN_V1
            .to_owned(),
        bootstrap_grant_signature: input.bootstrap_grant_signature,
        bootstrap_issuer: input.bootstrap_issuer,
        bootstrap_issuer_key_generation: input.bootstrap_issuer_key_generation,
        attempt_identity: input.attempt_identity,
        proposal_identity: input.proposal_identity,
        candidate_identity: input.candidate_identity,
        custody_evidence_identity: input.custody_evidence_identity,
        proof_of_possession_identity: input.proof_of_possession_identity,
        interpretation_policy: input.interpretation_policy,
        predecessor_grant: input.predecessor_grant,
        superseded_grant: input.superseded_grant,
    };
    validate_key_enrollment_body(&body)?;
    let canonical_bytes = canonical_json_bytes(&body)?;
    let identity = EnrollmentIdentityV1::new(semantic_digest(&body)?);
    Ok(StoreIntegrityKeyEnrollmentV1 {
        body,
        canonical_bytes,
        identity,
    })
}

/// N-18 constructor target.
pub fn construct_n_18_key_enrollment(
    input: StoreIntegrityKeyEnrollmentInputV1,
) -> Result<StoreIntegrityKeyEnrollmentV1, C2CanonicalRecordErrorV1> {
    construct_key_enrollment(input)
}

/// Decode only exact canonical persisted foundational-enrollment bytes.
///
/// Decoding reconstructs durable evidence only. It cannot produce the
/// process-local Store adoption consumed by signer acceptance or standing.
pub fn decode_store_integrity_key_enrollment_v1(
    bytes: &[u8],
) -> Result<StoreIntegrityKeyEnrollmentV1, C2CanonicalRecordErrorV1> {
    let body: StoreIntegrityKeyEnrollmentBodyV1 = serde_json::from_slice(bytes)
        .map_err(|_| C2CanonicalRecordErrorV1::MalformedOrNoncanonical)?;
    let canonical_bytes = canonical_json_bytes(&body)?;
    if canonical_bytes != bytes {
        return Err(C2CanonicalRecordErrorV1::MalformedOrNoncanonical);
    }
    let identity = EnrollmentIdentityV1::new(semantic_digest(&body)?);
    let enrollment = StoreIntegrityKeyEnrollmentV1 {
        body,
        canonical_bytes,
        identity,
    };
    verify_n_18_key_enrollment(&enrollment)?;
    Ok(enrollment)
}

/// N-18 structural and canonical verifier target.
pub fn verify_n_18_key_enrollment(
    enrollment: &StoreIntegrityKeyEnrollmentV1,
) -> Result<(), C2CanonicalRecordErrorV1> {
    validate_key_enrollment_body(&enrollment.body)?;
    if canonical_json_bytes(&enrollment.body)? != enrollment.canonical_bytes
        || semantic_digest(&enrollment.body)? != enrollment.identity.digest().clone()
    {
        return Err(C2CanonicalRecordErrorV1::DetachedAnchorAuthentication);
    }
    Ok(())
}

macro_rules! enrollment_constructor_aliases {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = "Construct the exact canonical enrollment while preserving this matrix row's named evidence surface."]
            pub fn $name(
                input: StoreIntegrityKeyEnrollmentInputV1,
            ) -> Result<StoreIntegrityKeyEnrollmentV1, C2CanonicalRecordErrorV1> {
                construct_n_18_key_enrollment(input)
            }
        )+
    };
}

macro_rules! enrollment_verifier_aliases {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = "Verify this row's exact enrollment fields and canonical identity."]
            pub fn $name(
                enrollment: &StoreIntegrityKeyEnrollmentV1,
            ) -> Result<(), C2CanonicalRecordErrorV1> {
                verify_n_18_key_enrollment(enrollment)
            }
        )+
    };
}

enrollment_constructor_aliases!(
    construct_rec_02_enrollment_occurrence_a2_chain_root_controlling_activation,
    construct_rec_03_enrollment_resident_id_generation_role_manifest_generation,
    construct_rec_04_algorithm_ed25519_store_integrity_public_key_key,
    construct_rec_05_predecessor_enrollment_absent_first_max_retained_generation,
    construct_rec_06_own_canonical_digest_schema_version_anchor_signature,
);

enrollment_verifier_aliases!(
    verify_rec_02_enrollment_occurrence_a2_chain_root_controlling_activation,
    verify_rec_03_enrollment_resident_id_generation_role_manifest_generation,
    verify_rec_04_algorithm_ed25519_store_integrity_public_key_key,
    verify_rec_05_predecessor_enrollment_absent_first_max_retained_generation,
    verify_rec_06_own_canonical_digest_schema_version_anchor_signature,
);

/// Exact result of validating a complete retained enrollment chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEnrollmentChainV1 {
    retained: Vec<EnrollmentIdentityV1>,
    selected: EnrollmentIdentityV1,
}

impl VerifiedEnrollmentChainV1 {
    /// Ordered retained enrollment identities.
    #[must_use]
    pub fn retained(&self) -> &[EnrollmentIdentityV1] {
        &self.retained
    }

    /// Exactly selected current enrollment.
    #[must_use]
    pub const fn selected(&self) -> &EnrollmentIdentityV1 {
        &self.selected
    }
}

/// N-21 constructor target: consume the complete resident enrollment set and
/// prove an exact predecessor-linked chain with one selected generation.
pub fn construct_n_21_enrollment_chain_strictly_linked_increasing_resident_validated(
    enrollments: &[StoreIntegrityKeyEnrollmentV1],
    selected_generation: StoreIntegrityKeyGenerationV1,
) -> Result<VerifiedEnrollmentChainV1, C2CanonicalRecordErrorV1> {
    verify_n_21_enrollment_chain_strictly_linked_increasing_resident_validated(
        enrollments,
        selected_generation,
    )
}

/// N-21 verifier target.
pub fn verify_n_21_enrollment_chain_strictly_linked_increasing_resident_validated(
    enrollments: &[StoreIntegrityKeyEnrollmentV1],
    selected_generation: StoreIntegrityKeyGenerationV1,
) -> Result<VerifiedEnrollmentChainV1, C2CanonicalRecordErrorV1> {
    let Some(first) = enrollments.first() else {
        return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentChain);
    };
    let immutable_maximum = first.maximum_retained_key_generations();
    let mut selected = None;
    let mut retained = Vec::with_capacity(enrollments.len());
    for (index, enrollment) in enrollments.iter().enumerate() {
        verify_n_18_key_enrollment(enrollment)?;
        let expected_generation =
            u32::try_from(index).map_err(|_| C2CanonicalRecordErrorV1::InvalidEnrollmentChain)?;
        if enrollment.key_generation().get() != expected_generation
            || enrollment.maximum_retained_key_generations() != immutable_maximum
            || enrollment.body.occurrence != first.body.occurrence
            || enrollment.body.signer_scope_policy != first.body.signer_scope_policy
            || enrollment.body.a2_chain_root != first.body.a2_chain_root
            || enrollment.body.dependency_anchor != first.body.dependency_anchor
            || enrollment.body.resident != first.body.resident
            || enrollment.body.role != first.body.role
            || enrollment.body.role_manifest != first.body.role_manifest
            || enrollment.body.domain != first.body.domain
            || (index > 0
                && enrollment.predecessor_enrollment() != Some(enrollments[index - 1].identity()))
        {
            return Err(C2CanonicalRecordErrorV1::InvalidEnrollmentChain);
        }
        if enrollment.key_generation() == selected_generation {
            selected = Some(enrollment.identity().clone());
        }
        retained.push(enrollment.identity().clone());
    }
    let selected = selected.ok_or(C2CanonicalRecordErrorV1::InvalidEnrollmentChain)?;
    Ok(VerifiedEnrollmentChainV1 { retained, selected })
}

/// Store-generation installation mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2InstallationModeV1 {
    /// New physical generation with no predecessor tuple.
    Fresh,
    /// New physical generation explicitly succeeding one authenticated
    /// predecessor physical generation.
    RestoreSuccessor,
}

/// Complete predecessor tuple required by restore-successor mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreInstallPredecessorV1 {
    pub physical_generation: PhysicalStoreGenerationIdentityV1,
    pub bootstrap: BootstrapIdentityV1,
    pub completion_receipt: InstallationReceiptIdentityV1,
    pub installation_cut: C2StructuralCutV1,
    pub restore_disposition: RestoreDispositionIdentityV1,
}

/// Exact B/G geometry selected by an independently authenticated install
/// policy.  Values are subsequently checked against the candidate-pinned
/// profile and implementation manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2InstalledCarrierGeometryV1 {
    pub store_root_layout_version: String,
    pub lock_format_identity: String,
    pub append_extent_layout: String,
    pub b_role_identity: String,
    pub b_payload_bound: u64,
    pub g_role_identity: String,
    pub g_payload_bound: u64,
    pub global_refusal_max_entries: u32,
    pub global_refusal_entry_max_bytes: u32,
}

/// Exact Gen4/current-activation tuple repeated by install policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2InstallAuthorityTupleV1 {
    pub occurrence: StoreOccurrenceIdentityV1,
    pub a2_chain_root: A2ChainRootIdentityV1,
    pub controlling_activation: ControllingActivationIdentityV1,
    pub dependency_anchor: DependencyAnchorIdentityV1,
    pub resident: ResidentIdentityV1,
    pub resident_generation: u64,
    pub role: String,
    pub role_manifest: RoleManifestIdentityV1,
    pub role_manifest_generation: u64,
    pub domain: String,
    pub policy_version: u64,
    pub authority_cut: C2StructuralCutV1,
}

/// Complete input to the acyclic pre-policy calculation authenticated by
/// MSG-01. It deliberately excludes enrollment because foundational
/// enrollment is created only after MSG-02. No signature or authority is
/// carried by this inert calculation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2StoreGenerationInstallPolicyCalculationInputV1 {
    pub authority: C2InstallAuthorityTupleV1,
    pub operator_installation_nonce: String,
    pub installation_cut: C2StructuralCutV1,
    pub mode: C2InstallationModeV1,
    pub restore_predecessor: Option<RestoreInstallPredecessorV1>,
    pub geometry: C2InstalledCarrierGeometryV1,
    pub backend_identity: String,
    pub qualified_backend_profile: QualifiedBackendProfileIdentityV1,
    pub maximum_policy_generations: u32,
    pub maximum_key_generations: u32,
    pub predecessor_install_policy: Option<InstallPolicyIdentityV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct C2StoreGenerationInstallPolicyCalculationBodyV1 {
    schema: String,
    identity_domain: String,
    authority: C2InstallAuthorityTupleV1,
    operator_installation_nonce: String,
    installation_cut: C2StructuralCutV1,
    mode: C2InstallationModeV1,
    restore_predecessor: Option<RestoreInstallPredecessorV1>,
    geometry: C2InstalledCarrierGeometryV1,
    backend_identity: String,
    qualified_backend_profile: QualifiedBackendProfileIdentityV1,
    maximum_policy_generations: u32,
    maximum_key_generations: u32,
    predecessor_install_policy: Option<InstallPolicyIdentityV1>,
}

/// Canonical inert pre-policy calculation. Possession establishes neither
/// terminal-A1 adoption nor live Store authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2StoreGenerationInstallPolicyCalculationV1 {
    body: C2StoreGenerationInstallPolicyCalculationBodyV1,
    canonical_bytes: Vec<u8>,
    identity: Sha256Digest,
}

impl C2StoreGenerationInstallPolicyCalculationV1 {
    #[must_use]
    pub(crate) const fn identity(&self) -> &Sha256Digest {
        &self.identity
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub(crate) const fn authority(&self) -> &C2InstallAuthorityTupleV1 {
        &self.body.authority
    }

    #[must_use]
    pub(crate) fn operator_installation_nonce(&self) -> &str {
        &self.body.operator_installation_nonce
    }

    #[must_use]
    pub(crate) const fn installation_cut(&self) -> C2StructuralCutV1 {
        self.body.installation_cut
    }

    #[must_use]
    pub(crate) const fn mode(&self) -> C2InstallationModeV1 {
        self.body.mode
    }

    #[must_use]
    pub(crate) const fn maximum_key_generations(&self) -> u32 {
        self.body.maximum_key_generations
    }
}

/// Store-private final-policy construction input. The Store can construct it
/// only after the MSG-01-authenticated calculation and exact foundational
/// enrollment have both been adopted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2StoreGenerationInstallPolicyInputV1 {
    pub calculation: C2StoreGenerationInstallPolicyCalculationV1,
    pub enrollment: EnrollmentIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct C2StoreGenerationInstallPolicyBodyV1 {
    schema: &'static str,
    identity_domain: &'static str,
    authority: C2InstallAuthorityTupleV1,
    enrollment: EnrollmentIdentityV1,
    operator_installation_nonce: String,
    installation_cut: C2StructuralCutV1,
    mode: C2InstallationModeV1,
    restore_predecessor: Option<RestoreInstallPredecessorV1>,
    geometry: C2InstalledCarrierGeometryV1,
    backend_identity: &'static str,
    qualified_backend_profile: QualifiedBackendProfileIdentityV1,
    installed_policy_calculation_identity: Sha256Digest,
    maximum_policy_generations: u32,
    maximum_key_generations: u32,
    predecessor_install_policy: Option<InstallPolicyIdentityV1>,
}

/// Canonical anchor-carried Store-generation install policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2StoreGenerationInstallPolicyV1 {
    body: C2StoreGenerationInstallPolicyBodyV1,
    canonical_bytes: Vec<u8>,
    identity: InstallPolicyIdentityV1,
}

impl Serialize for C2StoreGenerationInstallPolicyV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.body.serialize(serializer)
    }
}

impl CanonicalC2RecordV1 for C2StoreGenerationInstallPolicyV1 {
    fn schema(&self) -> &'static str {
        STORE_GENERATION_INSTALL_POLICY_SCHEMA_V1
    }

    fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn canonical_identity(&self) -> &Sha256Digest {
        self.identity.digest()
    }
}

impl C2StoreGenerationInstallPolicyV1 {
    /// Exact install-policy identity.
    #[must_use]
    pub const fn identity(&self) -> &InstallPolicyIdentityV1 {
        &self.identity
    }

    /// Enrollment named by this policy.
    #[must_use]
    pub const fn enrollment(&self) -> &EnrollmentIdentityV1 {
        &self.body.enrollment
    }

    /// Current activation named by this policy.
    #[must_use]
    pub const fn controlling_activation(&self) -> &ControllingActivationIdentityV1 {
        &self.body.authority.controlling_activation
    }

    /// Dependency anchor named by this policy.
    #[must_use]
    pub const fn dependency_anchor(&self) -> &DependencyAnchorIdentityV1 {
        &self.body.authority.dependency_anchor
    }

    /// Installed maximum retained key generations.
    #[must_use]
    pub const fn maximum_key_generations(&self) -> u32 {
        self.body.maximum_key_generations
    }

    /// Exact authenticated installation mode.
    #[must_use]
    pub const fn mode(&self) -> C2InstallationModeV1 {
        self.body.mode
    }

    /// Exact fixed-carrier geometry selected by the policy.
    #[must_use]
    pub const fn geometry(&self) -> &C2InstalledCarrierGeometryV1 {
        &self.body.geometry
    }

    /// Candidate-pinned qualified backend profile coordinate.
    #[must_use]
    pub const fn qualified_backend_profile(&self) -> &QualifiedBackendProfileIdentityV1 {
        &self.body.qualified_backend_profile
    }

    /// Operator-chosen occurrence-unique installation nonce. It is evidence,
    /// not authority, and is consumed only by the Store-owned driver.
    #[must_use]
    pub fn operator_installation_nonce(&self) -> &str {
        &self.body.operator_installation_nonce
    }

    /// Exact installation cut from the authenticated policy.
    #[must_use]
    pub const fn installation_cut(&self) -> C2StructuralCutV1 {
        self.body.installation_cut
    }

    /// Complete current-authority tuple repeated by the policy.
    #[must_use]
    pub const fn authority(&self) -> &C2InstallAuthorityTupleV1 {
        &self.body.authority
    }

    /// Candidate-pinned installed-policy calculation identity.
    #[must_use]
    pub const fn installed_policy_calculation_identity(&self) -> &Sha256Digest {
        &self.body.installed_policy_calculation_identity
    }
}

fn validate_geometry(
    geometry: &C2InstalledCarrierGeometryV1,
) -> Result<(), C2CanonicalRecordErrorV1> {
    validate_text(
        &geometry.store_root_layout_version,
        "store_root_layout_version",
    )?;
    validate_text(&geometry.lock_format_identity, "lock_format_identity")?;
    validate_text(&geometry.b_role_identity, "b_role_identity")?;
    validate_text(&geometry.g_role_identity, "g_role_identity")?;
    if geometry.append_extent_layout != APPEND_EXTENT_LAYOUT_V1 {
        return Err(C2CanonicalRecordErrorV1::SubstitutedClosedConstant(
            "append_extent_layout",
        ));
    }
    let refusal_bytes = u64::from(geometry.global_refusal_max_entries)
        .checked_mul(u64::from(geometry.global_refusal_entry_max_bytes))
        .ok_or(C2CanonicalRecordErrorV1::InvalidCarrierGeometry)?;
    if geometry.b_payload_bound == 0
        || geometry.g_payload_bound == 0
        || geometry.global_refusal_max_entries == 0
        || geometry.global_refusal_entry_max_bytes == 0
        || refusal_bytes > geometry.g_payload_bound
        || geometry.b_role_identity == geometry.g_role_identity
    {
        return Err(C2CanonicalRecordErrorV1::InvalidCarrierGeometry);
    }
    Ok(())
}

pub(crate) fn construct_install_policy_calculation_v1(
    input: C2StoreGenerationInstallPolicyCalculationInputV1,
) -> Result<C2StoreGenerationInstallPolicyCalculationV1, C2CanonicalRecordErrorV1> {
    validate_text(&input.authority.role, "role")?;
    validate_text(&input.authority.domain, "domain")?;
    validate_text(
        &input.operator_installation_nonce,
        "operator_installation_nonce",
    )?;
    validate_geometry(&input.geometry)?;
    if input.backend_identity != LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1 {
        return Err(C2CanonicalRecordErrorV1::SubstitutedClosedConstant(
            "backend_identity",
        ));
    }
    if input.maximum_policy_generations == 0
        || input.maximum_key_generations == 0
        || input.maximum_key_generations > input.maximum_policy_generations
    {
        return Err(C2CanonicalRecordErrorV1::InvalidInstalledMaximum);
    }
    match (input.mode, input.restore_predecessor.as_ref()) {
        (C2InstallationModeV1::Fresh, None) => {}
        (C2InstallationModeV1::RestoreSuccessor, Some(predecessor))
            if input.installation_cut > predecessor.installation_cut => {}
        _ => return Err(C2CanonicalRecordErrorV1::InvalidInstallationMode),
    }
    if input.mode == C2InstallationModeV1::Fresh && input.predecessor_install_policy.is_some() {
        return Err(C2CanonicalRecordErrorV1::InvalidInstallationMode);
    }

    let body = C2StoreGenerationInstallPolicyCalculationBodyV1 {
        schema: STORE_GENERATION_INSTALL_POLICY_CALCULATION_SCHEMA_V1.to_owned(),
        identity_domain: STORE_GENERATION_INSTALL_POLICY_CALCULATION_IDENTITY_DOMAIN_V1.to_owned(),
        authority: input.authority,
        operator_installation_nonce: input.operator_installation_nonce,
        installation_cut: input.installation_cut,
        mode: input.mode,
        restore_predecessor: input.restore_predecessor,
        geometry: input.geometry,
        backend_identity: LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1.to_owned(),
        qualified_backend_profile: input.qualified_backend_profile,
        maximum_policy_generations: input.maximum_policy_generations,
        maximum_key_generations: input.maximum_key_generations,
        predecessor_install_policy: input.predecessor_install_policy,
    };
    let canonical_bytes = canonical_json_bytes(&body)?;
    let identity = semantic_digest(&body)?;
    Ok(C2StoreGenerationInstallPolicyCalculationV1 {
        body,
        canonical_bytes,
        identity,
    })
}

pub(crate) fn decode_install_policy_calculation_v1(
    bytes: &[u8],
) -> Result<C2StoreGenerationInstallPolicyCalculationV1, C2CanonicalRecordErrorV1> {
    let body: C2StoreGenerationInstallPolicyCalculationBodyV1 = serde_json::from_slice(bytes)
        .map_err(|_| C2CanonicalRecordErrorV1::MalformedOrNoncanonical)?;
    let input = C2StoreGenerationInstallPolicyCalculationInputV1 {
        authority: body.authority,
        operator_installation_nonce: body.operator_installation_nonce,
        installation_cut: body.installation_cut,
        mode: body.mode,
        restore_predecessor: body.restore_predecessor,
        geometry: body.geometry,
        backend_identity: body.backend_identity,
        qualified_backend_profile: body.qualified_backend_profile,
        maximum_policy_generations: body.maximum_policy_generations,
        maximum_key_generations: body.maximum_key_generations,
        predecessor_install_policy: body.predecessor_install_policy,
    };
    let calculation = construct_install_policy_calculation_v1(input)?;
    if calculation.canonical_bytes() != bytes {
        return Err(C2CanonicalRecordErrorV1::MalformedOrNoncanonical);
    }
    Ok(calculation)
}

pub(crate) fn construct_install_policy(
    input: C2StoreGenerationInstallPolicyInputV1,
) -> Result<C2StoreGenerationInstallPolicyV1, C2CanonicalRecordErrorV1> {
    let calculation = input.calculation;
    let body = C2StoreGenerationInstallPolicyBodyV1 {
        schema: STORE_GENERATION_INSTALL_POLICY_SCHEMA_V1,
        identity_domain: STORE_GENERATION_INSTALL_POLICY_IDENTITY_DOMAIN_V1,
        authority: calculation.body.authority,
        enrollment: input.enrollment,
        operator_installation_nonce: calculation.body.operator_installation_nonce,
        installation_cut: calculation.body.installation_cut,
        mode: calculation.body.mode,
        restore_predecessor: calculation.body.restore_predecessor,
        geometry: calculation.body.geometry,
        backend_identity: LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1,
        qualified_backend_profile: calculation.body.qualified_backend_profile,
        installed_policy_calculation_identity: calculation.identity,
        maximum_policy_generations: calculation.body.maximum_policy_generations,
        maximum_key_generations: calculation.body.maximum_key_generations,
        predecessor_install_policy: calculation.body.predecessor_install_policy,
    };
    let canonical_bytes = canonical_json_bytes(&body)?;
    let identity = InstallPolicyIdentityV1::new(semantic_digest(&body)?);
    Ok(C2StoreGenerationInstallPolicyV1 {
        body,
        canonical_bytes,
        identity,
    })
}

macro_rules! install_policy_constructor_aliases {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = "Construct the exact canonical install policy while preserving this matrix row's evidence surface."]
            pub(crate) fn $name(
                input: C2StoreGenerationInstallPolicyInputV1,
            ) -> Result<C2StoreGenerationInstallPolicyV1, C2CanonicalRecordErrorV1> {
                construct_install_policy(input)
            }
        )+
    };
}

macro_rules! install_policy_verifier_aliases {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = "Verify this row's exact install-policy fields and canonical identity."]
            pub fn $name(
                policy: &C2StoreGenerationInstallPolicyV1,
            ) -> Result<(), C2CanonicalRecordErrorV1> {
                verify_install_policy(policy)
            }
        )+
    };
}

install_policy_constructor_aliases!(
    construct_rec_07_install_policy_complete_gen4_tuple_enrollment_digest,
    construct_rec_08_operator_nonce_structural_cut_fresh_restore_successor,
    construct_rec_09_root_layout_lock_format_append_layout_b,
    construct_rec_10_sole_backend_name_profile_digest_installed_policy,
    construct_rec_11_fixed_positive_policy_key_maxima_key_policy,
);

install_policy_verifier_aliases!(
    verify_rec_07_install_policy_complete_gen4_tuple_enrollment_digest,
    verify_rec_08_operator_nonce_structural_cut_fresh_restore_successor,
    verify_rec_09_root_layout_lock_format_append_layout_b,
    verify_rec_10_sole_backend_name_profile_digest_installed_policy,
    verify_rec_11_fixed_positive_policy_key_maxima_key_policy,
);

fn verify_install_policy(
    policy: &C2StoreGenerationInstallPolicyV1,
) -> Result<(), C2CanonicalRecordErrorV1> {
    validate_geometry(&policy.body.geometry)?;
    if policy.body.schema != STORE_GENERATION_INSTALL_POLICY_SCHEMA_V1
        || policy.body.identity_domain != STORE_GENERATION_INSTALL_POLICY_IDENTITY_DOMAIN_V1
        || policy.body.backend_identity != LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1
        || canonical_json_bytes(&policy.body)? != policy.canonical_bytes
        || semantic_digest(&policy.body)? != policy.identity.digest().clone()
    {
        return Err(C2CanonicalRecordErrorV1::DetachedAnchorAuthentication);
    }
    if policy.body.maximum_policy_generations == 0
        || policy.body.maximum_key_generations == 0
        || policy.body.maximum_key_generations > policy.body.maximum_policy_generations
    {
        return Err(C2CanonicalRecordErrorV1::InvalidInstalledMaximum);
    }
    match (policy.body.mode, policy.body.restore_predecessor.as_ref()) {
        (C2InstallationModeV1::Fresh, None) => Ok(()),
        (C2InstallationModeV1::RestoreSuccessor, Some(predecessor))
            if policy.body.installation_cut > predecessor.installation_cut =>
        {
            Ok(())
        }
        _ => Err(C2CanonicalRecordErrorV1::InvalidInstallationMode),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn public_key() -> Ed25519StoreIntegrityPublicKeyV1 {
        Ed25519StoreIntegrityPublicKeyV1::from_lower_hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap()
    }

    fn signature() -> Ed25519SignatureBytesV1 {
        Ed25519SignatureBytesV1::from_lower_hex("00".repeat(64)).unwrap()
    }

    fn enrollment_input(
        generation: u32,
        predecessor: Option<EnrollmentIdentityV1>,
    ) -> StoreIntegrityKeyEnrollmentInputV1 {
        StoreIntegrityKeyEnrollmentInputV1 {
            occurrence: StoreOccurrenceIdentityV1::new("occurrence-1").unwrap(),
            signer_scope_policy: SignerScopePolicyIdentityV1::new(digest('f')),
            signer_scope_policy_version: 1,
            a2_chain_root: A2ChainRootIdentityV1::new(digest('2')),
            controlling_activation: ControllingActivationIdentityV1::new(digest('3')),
            dependency_anchor: DependencyAnchorIdentityV1::new(digest('4')),
            resident: ResidentIdentityV1::new("resident/node-a").unwrap(),
            resident_generation: 1,
            role: "nq.host_role.store.v1".to_owned(),
            role_manifest: RoleManifestIdentityV1::new(digest('6')),
            role_manifest_generation: 1,
            domain: "nq.store.v1".to_owned(),
            activation_policy_version: 1,
            active_store_policy: ActiveStorePolicyIdentityV1::new(digest('0')),
            active_store_policy_generation: 1,
            authority_cut: C2StructuralCutV1 {
                ledger_position: u64::from(generation) * 10,
                effect_position: 0,
            },
            candidate_cut: C2StructuralCutV1 {
                ledger_position: u64::from(generation) * 10 + 1,
                effect_position: 0,
            },
            pop_cut: C2StructuralCutV1 {
                ledger_position: u64::from(generation) * 10 + 2,
                effect_position: 0,
            },
            enrollment_cut: C2StructuralCutV1 {
                ledger_position: u64::from(generation) * 10 + 3,
                effect_position: 0,
            },
            public_key: public_key(),
            key_generation: StoreIntegrityKeyGenerationV1::new(generation).unwrap(),
            predecessor_enrollment: predecessor,
            maximum_retained_key_generations: 4,
            provenance_purposes: BTreeSet::from([
                EnrollmentProvenancePurposeV1::PhysicalGenerationBootstrapVerification,
                EnrollmentProvenancePurposeV1::ActivePolicyFrameVerification,
            ]),
            bootstrap_grant_request: BootstrapGrantRequestIdentityV1::new(digest('7')),
            bootstrap_grant: BootstrapGrantIdentityV1::new(digest('8')),
            bootstrap_grant_signature: signature(),
            bootstrap_issuer: TerminalA1IssuerIdentityV1::new(digest('9')),
            bootstrap_issuer_key_generation: 3,
            attempt_identity: StoreIntegrityEnrollmentAttemptIdentityV1::new(digest('c')),
            proposal_identity: StoreIntegrityProposalIdentityV1::new(digest('a')),
            candidate_identity: StoreIntegrityEnrollmentCandidateIdentityV1::new(digest('d')),
            custody_evidence_identity: StoreIntegrityCustodyEvidenceIdentityV1::new(digest('e')),
            proof_of_possession_identity: StoreIntegrityProofOfPossessionIdentityV1::new(digest(
                'b',
            )),
            interpretation_policy: A2ApplicabilityInterpretationIdentityV1::new(
                A2ApplicabilityInterpretationIdentityV1::EXACT,
            )
            .unwrap(),
            predecessor_grant: None,
            superseded_grant: None,
        }
    }

    #[test]
    fn key_enrollment_is_canonical_and_predecessor_linked() {
        let first = construct_n_18_key_enrollment(enrollment_input(0, None)).unwrap();
        verify_n_18_key_enrollment(&first).unwrap();
        let second =
            construct_n_18_key_enrollment(enrollment_input(1, Some(first.identity().clone())))
                .unwrap();
        let verified = verify_n_21_enrollment_chain_strictly_linked_increasing_resident_validated(
            &[first, second.clone()],
            second.key_generation(),
        )
        .unwrap();
        assert_eq!(verified.selected(), second.identity());
        assert_eq!(verified.retained().len(), 2);
    }

    #[test]
    fn predecessor_gap_refuses_and_generation_zero_is_initial() {
        assert!(StoreIntegrityKeyGenerationV1::new(0).is_ok());
        assert!(construct_n_18_key_enrollment(enrollment_input(2, None)).is_err());
    }

    #[test]
    fn foundational_enrollment_is_pre_generation_and_cut_ordered() {
        let enrollment = construct_n_18_key_enrollment(enrollment_input(0, None)).unwrap();
        let value = serde_json::to_value(&enrollment).unwrap();
        assert!(value.get("physical_store_generation").is_none());
        assert!(enrollment.authority_cut() < enrollment.enrollment_cut());

        let mut reversed = enrollment_input(0, None);
        reversed.enrollment_cut = reversed.pop_cut;
        assert!(construct_n_18_key_enrollment(reversed).is_err());
    }

    #[test]
    fn foundational_enrollment_exact_bytes_decode_as_evidence_only() {
        let enrollment = construct_n_18_key_enrollment(enrollment_input(0, None)).unwrap();
        let decoded =
            decode_store_integrity_key_enrollment_v1(enrollment.canonical_bytes()).unwrap();
        assert_eq!(
            decoded.canonical_identity(),
            enrollment.canonical_identity()
        );
        assert_eq!(decoded.canonical_bytes(), enrollment.canonical_bytes());

        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(enrollment.canonical_bytes()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            decode_store_integrity_key_enrollment_v1(&pretty),
            Err(C2CanonicalRecordErrorV1::MalformedOrNoncanonical)
        ));
    }

    #[test]
    fn foundational_enrollment_decoder_rejects_self_consistent_invalid_values() {
        let enrollment = construct_n_18_key_enrollment(enrollment_input(0, None)).unwrap();
        let original: Value = serde_json::from_slice(enrollment.canonical_bytes()).unwrap();

        for (field, invalid) in [
            ("occurrence", serde_json::json!("wrong occurrence")),
            ("domain", serde_json::json!("wrong domain")),
            ("signer_scope_policy_version", serde_json::json!(0)),
            ("activation_policy_version", serde_json::json!(0)),
            (
                "interpretation_policy",
                serde_json::json!("caller.selected.interpretation"),
            ),
        ] {
            let mut changed = original.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), invalid);
            let exact_changed = canonical_json_bytes(&changed).unwrap();
            assert!(decode_store_integrity_key_enrollment_v1(&exact_changed).is_err());
        }
    }

    #[test]
    fn foundational_enrollment_schema_and_runtime_have_one_field_set() {
        let enrollment = construct_n_18_key_enrollment(enrollment_input(0, None)).unwrap();
        let runtime = serde_json::to_value(&enrollment).unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../../assets/nq.c2_store_integrity_key_enrollment.v1.schema.json"
        ))
        .unwrap();
        let required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        let properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let runtime_fields = runtime
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(required, properties);
        assert_eq!(required, runtime_fields);
    }

    #[test]
    fn install_policy_identity_is_derived_after_the_stable_policy_calculation_and_enrollment() {
        let calculation = construct_install_policy_calculation_v1(
            C2StoreGenerationInstallPolicyCalculationInputV1 {
                authority: C2InstallAuthorityTupleV1 {
                    occurrence: StoreOccurrenceIdentityV1::new("occurrence-1").unwrap(),
                    a2_chain_root: A2ChainRootIdentityV1::new(digest('2')),
                    controlling_activation: ControllingActivationIdentityV1::new(digest('3')),
                    dependency_anchor: DependencyAnchorIdentityV1::new(digest('4')),
                    resident: ResidentIdentityV1::new("resident/node-a").unwrap(),
                    resident_generation: 1,
                    role: "nq.host_role.store.v1".into(),
                    role_manifest: RoleManifestIdentityV1::new(digest('6')),
                    role_manifest_generation: 1,
                    domain: "nq.store.v1".into(),
                    policy_version: 1,
                    authority_cut: C2StructuralCutV1 {
                        ledger_position: 10,
                        effect_position: 0,
                    },
                },
                operator_installation_nonce: "install-1".into(),
                installation_cut: C2StructuralCutV1 {
                    ledger_position: 14,
                    effect_position: 0,
                },
                mode: C2InstallationModeV1::Fresh,
                restore_predecessor: None,
                geometry: C2InstalledCarrierGeometryV1 {
                    store_root_layout_version: "nq.c2.store_root_layout.v1".into(),
                    lock_format_identity: "nq.c2.lock_format.v1".into(),
                    append_extent_layout: APPEND_EXTENT_LAYOUT_V1.into(),
                    b_role_identity: "nq.c2.bootstrap_extent.v1".into(),
                    b_payload_bound: 4096,
                    g_role_identity: "nq.c2.global_refusal_extent.v1".into(),
                    g_payload_bound: 4096,
                    global_refusal_max_entries: 1,
                    global_refusal_entry_max_bytes: 1024,
                },
                backend_identity: LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1.into(),
                qualified_backend_profile: QualifiedBackendProfileIdentityV1::new(digest('a')),
                maximum_policy_generations: 4,
                maximum_key_generations: 4,
                predecessor_install_policy: None,
            },
        )
        .unwrap();
        let mut enrollment_input = enrollment_input(0, None);
        enrollment_input.active_store_policy =
            ActiveStorePolicyIdentityV1::new(calculation.identity().clone());
        let enrollment = construct_n_18_key_enrollment(enrollment_input).unwrap();
        assert_eq!(
            enrollment.active_store_policy().digest(),
            calculation.identity()
        );

        let input = |enrollment: EnrollmentIdentityV1| C2StoreGenerationInstallPolicyInputV1 {
            calculation: calculation.clone(),
            enrollment,
        };

        let policy = construct_install_policy(input(enrollment.identity().clone())).unwrap();
        assert_eq!(
            policy.installed_policy_calculation_identity(),
            calculation.identity()
        );
        assert_eq!(policy.maximum_key_generations(), 4);
        assert_eq!(policy.enrollment(), enrollment.identity());

        let other =
            construct_install_policy(input(EnrollmentIdentityV1::new(digest('1')))).unwrap();
        assert_eq!(
            other.installed_policy_calculation_identity(),
            calculation.identity()
        );
        assert_ne!(other.identity(), policy.identity());
    }

    #[test]
    fn public_key_parser_rejects_noncanonical_or_invalid_bytes() {
        assert!(
            Ed25519StoreIntegrityPublicKeyV1::from_lower_hex(
                "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
            )
            .is_err()
        );
        assert!(Ed25519StoreIntegrityPublicKeyV1::from_lower_hex("00").is_err());
    }

    #[test]
    fn resident_identity_preserves_the_exact_gen4_text_bound() {
        assert_eq!(
            ResidentIdentityV1::new("resident/node-a").unwrap().as_str(),
            "resident/node-a"
        );
        assert!(ResidentIdentityV1::new("a".repeat(1024)).is_ok());
        assert!(ResidentIdentityV1::new("é".repeat(512)).is_ok());
        assert!(ResidentIdentityV1::new("").is_err());
        assert!(ResidentIdentityV1::new("resident\nnode-a").is_err());
        assert!(ResidentIdentityV1::new("a".repeat(1025)).is_err());
        assert!(ResidentIdentityV1::new("é".repeat(513)).is_err());
        assert!(
            serde_json::from_value::<ResidentIdentityV1>(serde_json::json!("resident\u{0}node"))
                .is_err()
        );
    }
}
