//! Closed identity, generation, and exact-reference carriers.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, FixedOffset};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{ContractError, Result};

/// Production identity classes admitted by Host-Role Runtime Contract v1.
///
/// This is deliberately closed. A new identity class is a contract change,
/// not a free-form label that a producer may introduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// Authentication mechanism identity.
    AuthenticationScheme,
    /// Exact software/build identity.
    Build,
    /// Canonicalization rule identity.
    Canonicalization,
    /// Bounded capability identity.
    Capability,
    /// Clock source/model identity.
    Clock,
    /// Compatibility-policy identity.
    Compatibility,
    /// Configuration generation identity.
    ConfigurationGeneration,
    /// Consumer class identity.
    ConsumerClass,
    /// Contract schema identity.
    ContractSchema,
    /// Deployment generation identity.
    DeploymentGeneration,
    /// Delivery destination identity.
    Destination,
    /// Detector suite identity.
    DetectorSuite,
    /// Diagnostic profile identity.
    DiagnosticProfile,
    /// Diagnostic question identity.
    DiagnosticQuestion,
    /// Evaluator identity.
    Evaluator,
    /// Key generation identity.
    KeyGeneration,
    /// Normalization rule identity.
    NormalizationRule,
    /// Resident NQ node identity.
    NqNode,
    /// Platform identity.
    Platform,
    /// Policy identity.
    Policy,
    /// Authenticated principal identity.
    Principal,
    /// Projection identity.
    Projection,
    /// Provider identity.
    Provider,
    /// Receiver identity.
    Receiver,
    /// Resolver identity.
    Resolver,
    /// Role identity.
    Role,
    /// Scope identity.
    Scope,
    /// Static semantic cohort identity.
    StaticCohort,
    /// Store identity.
    Store,
    /// Diagnostic subject identity.
    Subject,
    /// Threshold-policy identity.
    ThresholdPolicy,
    /// Transport identity.
    Transport,
    /// Vantage identity.
    Vantage,
    /// Witness class or instance identity.
    Witness,
}

/// One exact production identity descriptor reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRef {
    /// Closed identity class.
    pub kind: IdentityKind,
    /// Stable logical identity.
    pub id: IdentityId,
    /// Exact descriptor version.
    pub version: IdentityVersion,
    /// Digest of the exact descriptor bytes.
    pub descriptor_digest: Sha256Digest,
}

impl IdentityRef {
    /// Requires this reference to have the expected production kind.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::IdentityKindMismatch`] on any mismatch.
    pub fn require_kind(&self, expected: IdentityKind, field: &'static str) -> Result<()> {
        if self.kind != expected {
            return Err(ContractError::IdentityKindMismatch {
                field,
                expected,
                actual: self.kind,
            });
        }
        Ok(())
    }

    /// Returns the stable `(kind, id, version)` descriptor key.
    #[must_use]
    pub fn key(&self) -> IdentityKey<'_> {
        IdentityKey {
            kind: self.kind,
            id: self.id.as_str(),
            version: self.version.as_str(),
        }
    }
}

/// Borrowed identity key used for exact catalog lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityKey<'a> {
    /// Identity class.
    pub kind: IdentityKind,
    /// Logical identity.
    pub id: &'a str,
    /// Version.
    pub version: &'a str,
}

macro_rules! path_component {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub struct $name(String);

        impl $name {
            /// Parses a production namespace path.
            ///
            /// # Errors
            ///
            /// Returns [`ContractError::InvalidIdentityPath`] for empty paths,
            /// empty components, uppercase text, or characters outside the
            /// ratified stable alphabet.
            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.is_empty()
                    || value.split('/').any(str::is_empty)
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-' | b'/')
                    })
                {
                    return Err(ContractError::InvalidIdentityPath(value));
                }
                Ok(Self(value))
            }

            /// Returns the exact path text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

path_component!(IdentityId, "Stable production identity path.");
path_component!(IdentityVersion, "Exact production identity version path.");

/// Stable bounded token used by the host-role contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Token(String);

impl Token {
    /// Parses a bounded token.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidToken`] when the value is empty,
    /// exceeds 255 UTF-8 bytes, or escapes the contract alphabet.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
            })
        {
            return Err(ContractError::InvalidToken(value));
        }
        Ok(Self(value))
    }

    /// Returns the exact token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Decimal, positive generation identity kept as exact text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Generation(String);

impl Generation {
    /// Parses a positive decimal generation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidGeneration`] for zero, leading zero,
    /// empty, or non-decimal input.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ContractError::InvalidGeneration(value));
        }
        Ok(Self(value))
    }

    /// Returns the exact decimal generation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Generation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// RFC 3339 timestamp whose exact source spelling remains available.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Timestamp(String);

impl Timestamp {
    /// Parses an RFC 3339 timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidTimestamp`] when parsing fails.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        DateTime::<FixedOffset>::parse_from_rfc3339(&value)
            .map_err(|_| ContractError::InvalidTimestamp(value.clone()))?;
        Ok(Self(value))
    }

    /// Returns the exact admitted timestamp text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the parsed instant for interval and ordering checks.
    ///
    /// This cannot fail because construction already validated the value.
    ///
    /// # Panics
    ///
    /// Panics only if the private validated timestamp invariant is violated
    /// by a defect in this crate.
    #[must_use]
    pub fn instant(&self) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(&self.0).expect("Timestamp construction validates RFC 3339")
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Exact immutable record reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRef {
    /// Exact target schema identity.
    pub schema: Token,
    /// Target record's semantic identity.
    pub record_id: Sha256Digest,
    /// Digest of the target's complete canonical bytes.
    pub bytes_digest: Sha256Digest,
}

/// Exact production namespace snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSnapshot {
    /// Closed namespace identity.
    pub namespace_id: NamespaceId,
    /// Closed namespace contract version.
    pub namespace_version: NamespaceVersion,
    /// Exact catalog generation.
    pub catalog_generation: Generation,
    /// Exact catalog identity.
    pub catalog_id: Sha256Digest,
}

/// Closed production namespace identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceId {
    /// NQ production namespace.
    #[serde(rename = "nq.production")]
    Production,
}

/// Closed namespace format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceVersion {
    /// First production namespace.
    #[serde(rename = "1")]
    V1,
}

/// Half-open effective interval for a binding or manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveInterval {
    /// Inclusive start.
    pub effective_from: Timestamp,
    /// Exclusive end, or no scheduled end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<Timestamp>,
}

impl EffectiveInterval {
    /// Validates interval ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidEffectiveInterval`] if the end is not
    /// strictly after the start.
    pub fn validate(&self) -> Result<()> {
        if self
            .effective_until
            .as_ref()
            .is_some_and(|end| end.instant() <= self.effective_from.instant())
        {
            return Err(ContractError::InvalidEffectiveInterval);
        }
        Ok(())
    }

    /// Reports whether the interval covers the supplied instant.
    #[must_use]
    pub fn contains(&self, instant: &Timestamp) -> bool {
        self.effective_from.instant() <= instant.instant()
            && self
                .effective_until
                .as_ref()
                .is_none_or(|end| instant.instant() < end.instant())
    }
}

/// Exact catalog of admitted identity descriptors.
#[derive(Debug, Default, Clone)]
pub struct IdentityCatalog {
    entries: BTreeMap<(IdentityKind, IdentityId, IdentityVersion), Sha256Digest>,
}

impl IdentityCatalog {
    /// Creates an empty catalog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts one exact descriptor reference.
    ///
    /// Exact duplicates are idempotent. Reusing `(kind,id,version)` with a
    /// different descriptor digest is refused as substitution.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::IdentityDescriptorSubstitution`] on conflict.
    pub fn insert(&mut self, identity: IdentityRef) -> Result<()> {
        let key = (identity.kind, identity.id, identity.version);
        match self.entries.get(&key) {
            Some(existing) if existing != &identity.descriptor_digest => {
                Err(ContractError::IdentityDescriptorSubstitution)
            }
            Some(_) => Ok(()),
            None => {
                self.entries.insert(key, identity.descriptor_digest);
                Ok(())
            }
        }
    }

    /// Resolves one exact reference.
    ///
    /// # Errors
    ///
    /// Returns an unresolved or substitution refusal.
    pub fn resolve(&self, identity: &IdentityRef) -> Result<()> {
        let key = (identity.kind, identity.id.clone(), identity.version.clone());
        match self.entries.get(&key) {
            None => Err(ContractError::UnresolvedIdentity {
                kind: identity.kind,
                id: identity.id.to_string(),
                version: identity.version.to_string(),
            }),
            Some(digest) if digest != &identity.descriptor_digest => {
                Err(ContractError::IdentityDescriptorSubstitution)
            }
            Some(_) => Ok(()),
        }
    }

    /// Iterates exact admitted descriptors in canonical key order.
    pub fn entries(&self) -> impl Iterator<Item = IdentityRef> + '_ {
        self.entries
            .iter()
            .map(|((kind, id, version), descriptor_digest)| IdentityRef {
                kind: *kind,
                id: id.clone(),
                version: version.clone(),
                descriptor_digest: descriptor_digest.clone(),
            })
    }

    /// Produces a deterministic persistence carrier bound to one externally
    /// admitted production namespace snapshot.
    #[must_use]
    pub fn snapshot(&self, namespace: NamespaceSnapshot) -> CatalogSnapshot {
        CatalogSnapshot {
            namespace,
            identities: self.entries().collect(),
        }
    }

    /// Reopens a deterministic snapshot without treating its producer as
    /// identity authority.
    ///
    /// Callers must separately admit the snapshot's namespace/catalog
    /// generation. This function only verifies closed ordering, uniqueness,
    /// and descriptor non-substitution.
    ///
    /// # Errors
    ///
    /// Returns a duplicate/order/substitution refusal.
    pub fn from_snapshot(snapshot: &CatalogSnapshot) -> Result<Self> {
        snapshot.validate()?;
        let mut catalog = Self::new();
        for identity in &snapshot.identities {
            catalog.insert(identity.clone())?;
        }
        Ok(catalog)
    }
}

/// Deterministic local persistence carrier for an externally admitted
/// identity catalog.
///
/// This is not a new runtime wire schema. The ratified contract leaves
/// catalog issuance external; this carrier preserves exact content across
/// restart without letting NQ infer or mint descriptor authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSnapshot {
    /// Exact externally admitted namespace/catalog generation.
    pub namespace: NamespaceSnapshot,
    /// Full descriptor set in canonical `(kind,id,version,digest)` order.
    pub identities: Vec<IdentityRef>,
}

impl CatalogSnapshot {
    /// Decodes one exact canonical catalog snapshot.
    ///
    /// This verifies deterministic bytes and descriptor ordering only. The
    /// caller must independently admit the named namespace/catalog
    /// generation.
    ///
    /// # Errors
    ///
    /// Refuses malformed JSON, noncanonical bytes, unknown fields, invalid
    /// descriptors, noncanonical ordering, and descriptor substitution.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        snapshot.validate()?;
        if canonical_json_bytes(&snapshot)? != bytes {
            return Err(ContractError::NonCanonicalCatalogSnapshot);
        }
        Ok(snapshot)
    }

    /// Returns exact deterministic canonical bytes.
    ///
    /// # Errors
    ///
    /// Refuses an invalid snapshot or canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Validates strict canonical ordering and unique descriptor keys.
    ///
    /// # Errors
    ///
    /// Returns a typed catalog-order or substitution refusal.
    pub fn validate(&self) -> Result<()> {
        if self.identities.is_empty() {
            return Err(ContractError::EmptyIdentityCatalog);
        }
        let mut previous: Option<&IdentityRef> = None;
        let mut seen = BTreeMap::new();
        for identity in &self.identities {
            if previous.is_some_and(|prior| prior >= identity) {
                return Err(ContractError::IdentityCatalogNotCanonical);
            }
            let key = (identity.kind, identity.id.clone(), identity.version.clone());
            if seen
                .insert(key, identity.descriptor_digest.clone())
                .is_some()
            {
                return Err(ContractError::IdentityDescriptorSubstitution);
            }
            previous = Some(identity);
        }
        Ok(())
    }

    /// Computes the semantic digest of the exact deterministic snapshot.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization error if the carrier ceases to be valid
    /// I-JSON.
    pub fn semantic_digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(semantic_digest(self)?)
    }
}
