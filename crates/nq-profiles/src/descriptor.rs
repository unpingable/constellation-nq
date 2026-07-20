//! Canonical profile descriptors and their identities.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema identifier for serialized profile descriptors.
pub const PROFILE_DESCRIPTOR_SCHEMA: &str = "nq.profile_descriptor.v1";

/// A compiled profile identifier and version.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileKey {
    /// Stable namespaced profile identifier.
    pub id: String,
    /// Monotonically versioned profile semantics.
    pub version: u32,
}

impl ProfileKey {
    /// Builds a profile key.
    #[must_use]
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }
}

/// SHA-256 identity of the canonical descriptor bytes.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProfileDigest(nq_protocol::Sha256Digest);

impl ProfileDigest {
    /// Returns the lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One controlled vocabulary term.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VocabularyTerm {
    /// Stable machine name.
    pub name: String,
    /// Short operator-facing meaning.
    pub description: String,
}

impl VocabularyTerm {
    /// Builds a vocabulary term.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

/// Bounds enforced independently of the helper's declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardinalityLimits {
    /// Maximum observations in one report.
    pub max_observations: u32,
    /// Maximum canonical payload bytes in one observation.
    pub max_payload_bytes: u32,
    /// Maximum UTF-8 bytes in one profile subject.
    pub max_subject_bytes: u32,
    /// Maximum declarations in each controlled coverage class.
    pub max_coverage_declarations: u32,
}

/// Evidence reliance and temporal-alignment limits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessPolicy {
    /// Maximum age at which an observation may be relied upon.
    pub reliance_seconds: u64,
    /// Maximum skew when a detector explicitly composes watchers.
    pub alignment_seconds: u64,
}

/// Subject correlation policy owned by a profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRules {
    /// Namespace prefix used by subjects in this profile.
    pub namespace: String,
    /// Whether each observation must use the request's exact subject.
    pub exact_request_subject: bool,
}

/// Canonical, fixture-backed semantic contract for one profile version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDescriptor {
    /// Descriptor schema identifier.
    pub schema: String,
    /// Unversioned organizational family; it carries no runtime authority.
    pub family: String,
    /// Compiled profile identity.
    pub profile: ProfileKey,
    /// Human-readable profile name.
    pub title: String,
    /// Controlled observation-kind vocabulary.
    pub observation_kinds: Vec<VocabularyTerm>,
    /// Coverage classes that must each be declared exactly once.
    pub coverage: Vec<VocabularyTerm>,
    /// Subject identity and correlation policy.
    pub subjects: SubjectRules,
    /// Scope kinds this profile understands.
    pub scope_kinds: Vec<VocabularyTerm>,
    /// Vantage values this profile understands.
    pub vantages: Vec<VocabularyTerm>,
    /// Access paths this profile understands.
    pub access_paths: Vec<VocabularyTerm>,
    /// Evidence bases this profile understands.
    pub bases: Vec<VocabularyTerm>,
    /// Operating regimes this profile understands.
    pub regimes: Vec<VocabularyTerm>,
    /// Capability names that an instance may be granted.
    pub capabilities: Vec<VocabularyTerm>,
    /// Freshness and composition limits.
    pub freshness: FreshnessPolicy,
    /// Cardinality and byte limits.
    pub limits: CardinalityLimits,
    /// Explicit disturbance assumptions and limitations.
    pub disturbance_assumptions: Vec<String>,
}

impl ProfileDescriptor {
    /// Computes the identity of the canonical descriptor.
    ///
    /// The helper protocol owns canonicalization. Profile qualification remains
    /// a separate admission decision; this digest identifies descriptor bytes
    /// only.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError`] if the descriptor cannot be represented as
    /// canonical protocol JSON.
    pub fn digest(&self) -> Result<ProfileDigest, DescriptorError> {
        nq_protocol::semantic_digest(self)
            .map(ProfileDigest)
            .map_err(|error| DescriptorError::Canonicalization(error.to_string()))
    }

    /// Tests membership in the controlled observation-kind vocabulary.
    #[must_use]
    pub fn knows_observation_kind(&self, kind: &str) -> bool {
        vocabulary_contains(&self.observation_kinds, kind)
    }

    /// Tests membership in the controlled coverage vocabulary.
    #[must_use]
    pub fn knows_coverage(&self, coverage: &str) -> bool {
        vocabulary_contains(&self.coverage, coverage)
    }
}

/// Failure to construct a canonical descriptor identity.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DescriptorError {
    /// Canonical serialization failed.
    #[error("profile descriptor canonicalization failed: {0}")]
    Canonicalization(String),
}

pub(crate) fn vocabulary_contains(vocabulary: &[VocabularyTerm], value: &str) -> bool {
    vocabulary.iter().any(|term| term.name == value)
}
