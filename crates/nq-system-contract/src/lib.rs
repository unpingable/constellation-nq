//! Versioned, authority-free system cuts shared by observation and actuation
//! consumers.
//!
//! A [`SystemSpecV1`] is a descriptive draft. Compiling one selected system
//! with an external ratification record produces an immutable
//! [`PublishedScopeCutV1`]. NQ and future Porter consumers receive distinct
//! projections that cite that exact cut. None of these documents grants
//! authority, approves a transition, or reports an observed condition.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use nq_profiles::{ScopeGrant, ValidationContext, VantageGrant, resolve_profile};
use nq_protocol::{
    Capability, CoverageKind, InstanceId, ProfileBinding, Sha256Digest, SubjectBinding,
    canonical_json_bytes, semantic_digest,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// Schema identifier for a descriptive system draft.
pub const SYSTEM_SPEC_SCHEMA: &str = "nq.system_spec.v1";
/// Schema identifier for an immutable, ratification-bound scope cut.
pub const SCOPE_CUT_SCHEMA: &str = "nq.scope_cut.v1";
/// Schema identifier for the exact bytes presented for human ratification.
pub const SCOPE_CUT_PROPOSAL_SCHEMA: &str = "nq.scope_cut_proposal.v1";
/// Schema domain used to identify the canonical ratification record body.
pub const SCOPE_CUT_RATIFICATION_SCHEMA: &str = "nq.scope_cut_ratification.v1";
/// Schema identifier for the NQ-specific observation projection.
pub const NQ_OBSERVATION_PROJECTION_SCHEMA: &str = "nq.observation_projection.v1";
/// Schema identifier for the future Porter-specific descriptive projection.
pub const PORTER_ACTUATION_PROJECTION_SCHEMA: &str = "nq.porter_actuation_projection.v1";

/// Maximum accepted encoded system-contract document size.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1_048_576;
/// Maximum source snapshots in a system specification or cut.
pub const MAX_SOURCES: usize = 1_024;
/// Maximum targets in a system specification or cut.
pub const MAX_TARGETS: usize = 1_024;
/// Maximum named systems in one draft specification.
pub const MAX_SYSTEMS: usize = 1_024;
/// Maximum components in a system specification or cut.
pub const MAX_COMPONENTS: usize = 4_096;
/// Maximum dependency relationships in a system specification or cut.
pub const MAX_DEPENDENCIES: usize = 8_192;
/// Maximum observation obligations in a system specification or cut.
pub const MAX_OBSERVATION_OBLIGATIONS: usize = 4_096;

const MAX_ID_BYTES: usize = 255;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_BINDING_VALUE_BYTES: usize = 64 * 1_024;
const MAX_REQUIRED_COVERAGE: usize = 256;
const MAX_FRESHNESS_SECONDS: u64 = 366 * 24 * 60 * 60;

fn validate_id(value: &str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES {
        return Err(ContractError::InvalidIdentifier(value.to_owned()));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
    }) {
        return Err(ContractError::InvalidIdentifier(value.to_owned()));
    }
    Ok(())
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Constructs a bounded stable identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ContractError::InvalidIdentifier`] for an empty,
            /// oversized, or unsafe identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

id_type!(/// Stable identity of one system-specification lineage.
    SpecId);
id_type!(/// Stable identity of a ratified scope cut.
    CutId);
id_type!(/// Stable identity of one system.
    SystemId);
id_type!(/// Stable identity of one admitted target.
    TargetId);
id_type!(/// Stable identity of one system component.
    ComponentId);
id_type!(/// Stable identity of one dependency relationship.
    DependencyId);
id_type!(/// Stable identity of one observation obligation.
    ObservationObligationId);
id_type!(/// Stable identity of one declared-fact source snapshot.
    SourceSnapshotId);
id_type!(/// Stable identity of one consumer projection.
    ProjectionId);
id_type!(/// Local identity recorded for the human ratifier.
    OperatorId);
id_type!(/// Controlled descriptive target class.
    TargetClass);
id_type!(/// Controlled descriptive component kind.
    ComponentKind);

/// Explicit reminder that a descriptive artifact carries no authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySemantics {
    /// The document describes scope only and grants no effects.
    None,
}

/// Kind of declared-fact snapshot contributing to a draft.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Checked-in target bootstrap material.
    BootstrapTarget,
    /// Bounded `NetBox` inventory export.
    NetboxInventory,
    /// Human-authored system relationships and obligations.
    OperatorAuthored,
    /// Another identified descriptive source with no authority semantics.
    OtherDeclaredFacts,
}

/// One immutable bounded input snapshot used to author a system draft.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotV1 {
    /// NQ-ng-owned identity for this snapshot occurrence.
    pub source_snapshot_id: SourceSnapshotId,
    /// Descriptive source class.
    pub kind: SourceKind,
    /// Digest of the exact externally retained snapshot bytes.
    pub content_digest: Sha256Digest,
    /// Time at which the snapshot was captured.
    pub captured_at: DateTime<Utc>,
    /// Bounded human/audit locator; this is not a live-query instruction.
    pub provenance: String,
}

/// Stable descriptive target identity within a draft.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetV1 {
    /// Stable target identity.
    pub target_id: TargetId,
    /// Descriptive lifecycle class such as `persistent-dev`.
    pub target_class: TargetClass,
    /// Digest of the separately retained target-identity record.
    pub target_identity_digest: Sha256Digest,
    /// Exact source snapshots supporting this target description.
    pub source_snapshot_ids: Vec<SourceSnapshotId>,
}

/// Descriptive component within a system boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentV1 {
    /// Stable component identity.
    pub component_id: ComponentId,
    /// Controlled descriptive component class.
    pub kind: ComponentKind,
    /// Target on which the component is declared to be hosted.
    pub hosted_on: TargetId,
    /// Exact source snapshots supporting this component description.
    pub source_snapshot_ids: Vec<SourceSnapshotId>,
}

/// Meaning assigned to a dependency relationship by the ratified cut.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRequirement {
    /// The consumer requires the provider within this system theory.
    Required,
    /// The relationship is known but not required for this system theory.
    Incidental,
}

/// One explicit, directed component relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyV1 {
    /// Stable relationship identity.
    pub dependency_id: DependencyId,
    /// Component whose behavior depends on the provider.
    pub consumer_component_id: ComponentId,
    /// Component supplying the dependency.
    pub provider_component_id: ComponentId,
    /// Required or incidental status under this exact cut.
    pub requirement: DependencyRequirement,
    /// Source snapshots supporting the relationship.
    pub source_snapshot_ids: Vec<SourceSnapshotId>,
}

/// Exact compiled NQ collection obligation for one component.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationObligationV1 {
    /// Stable obligation identity.
    pub observation_obligation_id: ObservationObligationId,
    /// Component to which the observation applies.
    pub component_id: ComponentId,
    /// Exact NQ-owned witness instance expected to collect the testimony.
    pub instance_id: InstanceId,
    /// Exact compiled NQ profile identity and descriptor digest.
    pub profile: ProfileBinding,
    /// Exact subject, maximum scope, and vantage binding.
    pub subject_binding: SubjectBinding,
    /// Coverage dimensions required for this obligation.
    pub required_coverage: Vec<CoverageKind>,
    /// Exact capability subset expected by the observation binding.
    pub granted_capabilities: Vec<Capability>,
    /// Maximum evidence age accepted by this system theory.
    pub freshness_seconds: u64,
    /// Source snapshots supporting this authored obligation.
    pub source_snapshot_ids: Vec<SourceSnapshotId>,
}

/// Membership and relationship selection for one named system.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemDefinitionV1 {
    /// Stable system identity.
    pub system_id: SystemId,
    /// Bounded operator-facing title.
    pub title: String,
    /// Targets inside this system boundary.
    pub target_ids: Vec<TargetId>,
    /// Components inside this system boundary.
    pub component_ids: Vec<ComponentId>,
    /// Dependency relationships inside this system theory.
    pub dependency_ids: Vec<DependencyId>,
    /// Observation obligations required by this system theory.
    pub observation_obligation_ids: Vec<ObservationObligationId>,
    /// Exact authored/source snapshots supporting boundary membership.
    pub source_snapshot_ids: Vec<SourceSnapshotId>,
}

/// Descriptive, non-governing input from which ratified cuts are compiled.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSpecV1 {
    /// Must be [`SYSTEM_SPEC_SCHEMA`].
    pub schema: String,
    /// Stable specification lineage.
    pub spec_id: SpecId,
    /// Explicit positive draft revision.
    pub revision: u32,
    /// Bounded operator-facing title.
    pub title: String,
    /// Declared-fact snapshot custody records.
    pub source_snapshots: Vec<SourceSnapshotV1>,
    /// Described targets.
    pub targets: Vec<TargetV1>,
    /// Described components.
    pub components: Vec<ComponentV1>,
    /// Explicit component relationships.
    pub dependencies: Vec<DependencyV1>,
    /// Exact observation obligations.
    pub observation_obligations: Vec<ObservationObligationV1>,
    /// Named systems selectable for publication.
    pub systems: Vec<SystemDefinitionV1>,
    /// Always [`AuthoritySemantics::None`].
    pub authority: AuthoritySemantics,
}

/// External evidence that a human ratified the exact proposed cut inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RatificationV1 {
    /// Local identity of the ratifying operator.
    pub ratified_by: OperatorId,
    /// Time recorded for the ratification action.
    pub ratified_at: DateTime<Utc>,
    /// Exact canonical proposal identity presented for ratification.
    pub ratified_proposal_digest: Sha256Digest,
    /// Digest of the separately retained ratification record.
    pub ratification_record_digest: Sha256Digest,
}

/// Canonical fields identified by a scope-cut ratification record digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RatificationRecordBodyV1 {
    /// Local identity of the ratifying operator.
    pub ratified_by: OperatorId,
    /// Time recorded for the ratification action.
    pub ratified_at: DateTime<Utc>,
    /// Exact canonical proposal identity presented for ratification.
    pub ratified_proposal_digest: Sha256Digest,
}

impl RatificationV1 {
    /// Constructs a self-consistent ratification custody record for exact
    /// proposal bytes.
    ///
    /// This constructor records a local operator assertion. It does not prove
    /// identity, signature standing, authority, or approval of any actuation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if the canonical record body cannot be
    /// represented in the versioned digest domain.
    pub fn new(
        ratified_by: OperatorId,
        ratified_at: DateTime<Utc>,
        ratified_proposal_digest: Sha256Digest,
    ) -> Result<Self, ContractError> {
        let body = RatificationRecordBodyV1 {
            ratified_by: ratified_by.clone(),
            ratified_at,
            ratified_proposal_digest: ratified_proposal_digest.clone(),
        };
        let ratification_record_digest =
            versioned_artifact_digest(SCOPE_CUT_RATIFICATION_SCHEMA, &body)?;
        Ok(Self {
            ratified_by,
            ratified_at,
            ratified_proposal_digest,
            ratification_record_digest,
        })
    }

    /// Verifies that the record digest identifies these exact canonical fields.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::RatificationRecordMismatch`] when any record
    /// field has drifted or canonicalization fails.
    pub fn verify(&self) -> Result<(), ContractError> {
        let body = RatificationRecordBodyV1 {
            ratified_by: self.ratified_by.clone(),
            ratified_at: self.ratified_at,
            ratified_proposal_digest: self.ratified_proposal_digest.clone(),
        };
        let expected = versioned_artifact_digest(SCOPE_CUT_RATIFICATION_SCHEMA, &body)?;
        if expected != self.ratification_record_digest {
            return Err(ContractError::RatificationRecordMismatch);
        }
        Ok(())
    }
}

/// Exact source-specification identity retained by a published cut.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSpecReferenceV1 {
    /// Stable specification lineage.
    pub spec_id: SpecId,
    /// Exact draft revision.
    pub revision: u32,
    /// Digest of the validated, normalized complete specification.
    pub spec_digest: Sha256Digest,
}

/// Canonical proposed closure presented at the human ratification boundary.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCutProposalBodyV1 {
    /// Stable cut identity proposed for publication.
    pub cut_id: CutId,
    /// Exact complete source specification.
    pub source_spec: SystemSpecReferenceV1,
    /// Selected system membership.
    pub system: SystemDefinitionV1,
    /// Closed source-snapshot subset required by the system.
    pub source_snapshots: Vec<SourceSnapshotV1>,
    /// Closed target subset required by the system.
    pub targets: Vec<TargetV1>,
    /// Closed component subset required by the system.
    pub components: Vec<ComponentV1>,
    /// Closed dependency subset required by the system.
    pub dependencies: Vec<DependencyV1>,
    /// Closed observation-obligation subset required by the system.
    pub observation_obligations: Vec<ObservationObligationV1>,
    /// Always [`AuthoritySemantics::None`].
    pub authority: AuthoritySemantics,
}

/// Exact bounded proposal bytes that a publication workflow may present to a
/// human ratifier.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCutProposalV1 {
    /// Must be [`SCOPE_CUT_PROPOSAL_SCHEMA`].
    pub schema: String,
    /// SHA-256 digest of the canonical proposal body.
    pub proposal_digest: Sha256Digest,
    /// Canonical proposed closed system scope.
    pub proposal: ScopeCutProposalBodyV1,
}

/// Canonical body whose digest identifies one published scope cut.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCutBodyV1 {
    /// Stable cut identity.
    pub cut_id: CutId,
    /// Exact complete source specification.
    pub source_spec: SystemSpecReferenceV1,
    /// Human-ratification custody reference.
    pub ratification: RatificationV1,
    /// Selected system membership.
    pub system: SystemDefinitionV1,
    /// Closed source-snapshot subset required by the system.
    pub source_snapshots: Vec<SourceSnapshotV1>,
    /// Closed target subset required by the system.
    pub targets: Vec<TargetV1>,
    /// Closed component subset required by the system.
    pub components: Vec<ComponentV1>,
    /// Closed dependency subset required by the system.
    pub dependencies: Vec<DependencyV1>,
    /// Closed observation-obligation subset required by the system.
    pub observation_obligations: Vec<ObservationObligationV1>,
    /// Always [`AuthoritySemantics::None`].
    pub authority: AuthoritySemantics,
}

/// Immutable versioned system cut with an exact canonical semantic identity.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedScopeCutV1 {
    /// Must be [`SCOPE_CUT_SCHEMA`].
    pub schema: String,
    /// SHA-256 digest of the canonical [`ScopeCutBodyV1`].
    pub cut_digest: Sha256Digest,
    /// Canonical digested cut body.
    pub cut: ScopeCutBodyV1,
}

/// Reference carried by every consumer-specific projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCutReferenceV1 {
    /// Stable cut identity.
    pub cut_id: CutId,
    /// Exact canonical cut digest.
    pub cut_digest: Sha256Digest,
}

/// Canonical NQ observation-projection body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqObservationProjectionBodyV1 {
    /// Stable projection identity.
    pub projection_id: ProjectionId,
    /// Exact cut from which the projection was derived.
    pub scope_cut: ScopeCutReferenceV1,
    /// Exact system identity within the cut.
    pub system_id: SystemId,
    /// Target identities needed to correlate observations.
    pub targets: Vec<TargetV1>,
    /// Component membership needed to correlate observations.
    pub components: Vec<ComponentV1>,
    /// Explicit component relationships from the same published cut.
    pub dependencies: Vec<DependencyV1>,
    /// Complete observation obligations from the published cut.
    pub observation_obligations: Vec<ObservationObligationV1>,
    /// Always [`AuthoritySemantics::None`].
    pub authority: AuthoritySemantics,
}

/// Exact NQ consumer projection derived from one published cut.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqObservationProjectionV1 {
    /// Must be [`NQ_OBSERVATION_PROJECTION_SCHEMA`].
    pub schema: String,
    /// SHA-256 digest of the canonical projection body.
    pub projection_digest: Sha256Digest,
    /// Canonical digested projection body.
    pub projection: NqObservationProjectionBodyV1,
}

/// Narrowing selection used to derive a future Porter projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PorterProjectionSelectionV1 {
    /// Direct plan targets within the exact published cut.
    pub target_ids: Vec<TargetId>,
    /// Direct plan components within the selected targets and exact cut.
    pub component_ids: Vec<ComponentId>,
}

/// Canonical descriptive Porter-projection body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PorterActuationProjectionBodyV1 {
    /// Stable projection identity.
    pub projection_id: ProjectionId,
    /// Exact cut from which the projection was derived.
    pub scope_cut: ScopeCutReferenceV1,
    /// Exact system identity within the cut.
    pub system_id: SystemId,
    /// Direct plan target scope; this is not permission to change it.
    pub actuation_targets: Vec<TargetV1>,
    /// Direct plan component scope; this is not permission to change it.
    pub actuation_components: Vec<ComponentV1>,
    /// Host targets of the dependency-derived affected components.
    pub affected_targets: Vec<TargetV1>,
    /// Direct components plus transitive consumers that may be affected.
    pub affected_components: Vec<ComponentV1>,
    /// Cut relationships incident on the derived affected boundary.
    pub boundary_dependencies: Vec<DependencyV1>,
    /// Complete NQ witness obligations for the affected components.
    ///
    /// These obligations require fresh testimony. They do not prescribe a
    /// detector result or turn a valid failed report into a passing condition.
    pub verification_obligations: Vec<ObservationObligationV1>,
    /// Always [`AuthoritySemantics::None`].
    pub authority: AuthoritySemantics,
}

/// Future Porter-facing descriptive projection derived from one published cut.
///
/// This type intentionally has no command, effect, approval, grant, or native
/// plan field. An authority system may bind a separately qualified plan to its
/// digest, but the projection cannot authorize or enact that plan.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PorterActuationProjectionV1 {
    /// Must be [`PORTER_ACTUATION_PROJECTION_SCHEMA`].
    pub schema: String,
    /// SHA-256 digest of the canonical projection body.
    pub projection_digest: Sha256Digest,
    /// Canonical digested projection body.
    pub projection: PorterActuationProjectionBodyV1,
}

impl SystemSpecV1 {
    /// Strictly validates bounds, uniqueness, references, and closed system
    /// membership without publishing or ratifying anything.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for any invalid schema, bound, duplicate,
    /// unknown reference, orphaned object, or inconsistent relationship.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractError> {
        require_schema(&self.schema, SYSTEM_SPEC_SCHEMA)?;
        if self.revision == 0 {
            return Err(ContractError::InvalidValue("revision must be positive"));
        }
        validate_text("spec title", &self.title)?;
        validate_count(
            "source snapshots",
            self.source_snapshots.len(),
            1,
            MAX_SOURCES,
        )?;
        validate_count("targets", self.targets.len(), 1, MAX_TARGETS)?;
        validate_count("systems", self.systems.len(), 1, MAX_SYSTEMS)?;
        validate_count("components", self.components.len(), 1, MAX_COMPONENTS)?;
        validate_count("dependencies", self.dependencies.len(), 0, MAX_DEPENDENCIES)?;
        validate_count(
            "observation obligations",
            self.observation_obligations.len(),
            1,
            MAX_OBSERVATION_OBLIGATIONS,
        )?;

        let source_ids = unique_ids(
            "source snapshot",
            self.source_snapshots
                .iter()
                .map(|source| source.source_snapshot_id.as_str()),
        )?;
        let target_ids = unique_ids(
            "target",
            self.targets.iter().map(|target| target.target_id.as_str()),
        )?;
        let component_ids = unique_ids(
            "component",
            self.components
                .iter()
                .map(|component| component.component_id.as_str()),
        )?;
        let dependency_ids = unique_ids(
            "dependency",
            self.dependencies
                .iter()
                .map(|dependency| dependency.dependency_id.as_str()),
        )?;
        let obligation_ids = unique_ids(
            "observation obligation",
            self.observation_obligations
                .iter()
                .map(|obligation| obligation.observation_obligation_id.as_str()),
        )?;
        unique_ids(
            "system",
            self.systems.iter().map(|system| system.system_id.as_str()),
        )?;

        for source in &self.source_snapshots {
            validate_text("source provenance", &source.provenance)?;
        }
        for target in &self.targets {
            validate_nonempty_unique_refs(
                "target source snapshots",
                &target.source_snapshot_ids,
                &source_ids,
            )?;
        }
        for component in &self.components {
            require_reference(
                "component host target",
                component.hosted_on.as_str(),
                &target_ids,
            )?;
            validate_nonempty_unique_refs(
                "component source snapshots",
                &component.source_snapshot_ids,
                &source_ids,
            )?;
        }

        let mut dependency_pairs = BTreeSet::new();
        for dependency in &self.dependencies {
            require_reference(
                "dependency consumer",
                dependency.consumer_component_id.as_str(),
                &component_ids,
            )?;
            require_reference(
                "dependency provider",
                dependency.provider_component_id.as_str(),
                &component_ids,
            )?;
            if dependency.consumer_component_id == dependency.provider_component_id {
                return Err(ContractError::InvalidValue(
                    "dependency consumer and provider must differ",
                ));
            }
            let pair = (
                dependency.consumer_component_id.as_str(),
                dependency.provider_component_id.as_str(),
            );
            if !dependency_pairs.insert(pair) {
                return Err(ContractError::Duplicate {
                    kind: "dependency endpoint pair",
                    id: format!("{}->{}", pair.0, pair.1),
                });
            }
            validate_nonempty_unique_refs(
                "dependency source snapshots",
                &dependency.source_snapshot_ids,
                &source_ids,
            )?;
        }

        for obligation in &self.observation_obligations {
            require_reference(
                "observation component",
                obligation.component_id.as_str(),
                &component_ids,
            )?;
            if obligation.freshness_seconds == 0
                || obligation.freshness_seconds > MAX_FRESHNESS_SECONDS
            {
                return Err(ContractError::InvalidValue(
                    "freshness_seconds is outside the compiled bound",
                ));
            }
            let profile_version = obligation.profile.version.as_str();
            let parsed_profile_version = profile_version.parse::<u32>().ok();
            if parsed_profile_version
                .filter(|version| *version > 0 && version.to_string() == profile_version)
                .is_none()
            {
                return Err(ContractError::InvalidValue(
                    "profile version must be a positive canonical u32",
                ));
            }
            validate_count(
                "required coverage",
                obligation.required_coverage.len(),
                1,
                MAX_REQUIRED_COVERAGE,
            )?;
            unique_ids(
                "required coverage",
                obligation
                    .required_coverage
                    .iter()
                    .map(CoverageKind::as_str),
            )?;
            validate_count(
                "granted capabilities",
                obligation.granted_capabilities.len(),
                0,
                MAX_REQUIRED_COVERAGE,
            )?;
            unique_ids(
                "granted capability",
                obligation
                    .granted_capabilities
                    .iter()
                    .map(Capability::as_str),
            )?;
            validate_nonempty_unique_refs(
                "observation source snapshots",
                &obligation.source_snapshot_ids,
                &source_ids,
            )?;
            validate_binding_value("scope value", &obligation.subject_binding.scope.value)?;
            validate_binding_value("vantage value", &obligation.subject_binding.vantage.value)?;
        }

        let target_by_id =
            |id: &TargetId| self.targets.iter().find(|target| target.target_id == *id);
        let component_by_id = |id: &ComponentId| {
            self.components
                .iter()
                .find(|component| component.component_id == *id)
        };
        let dependency_by_id = |id: &DependencyId| {
            self.dependencies
                .iter()
                .find(|dependency| dependency.dependency_id == *id)
        };
        let obligation_by_id = |id: &ObservationObligationId| {
            self.observation_obligations
                .iter()
                .find(|obligation| obligation.observation_obligation_id == *id)
        };

        let mut used_sources = BTreeSet::new();
        let mut used_targets = BTreeSet::new();
        let mut used_components = BTreeSet::new();
        let mut used_dependencies = BTreeSet::new();
        let mut used_obligations = BTreeSet::new();
        for system in &self.systems {
            validate_text("system title", &system.title)?;
            validate_nonempty_unique_refs("system targets", &system.target_ids, &target_ids)?;
            validate_nonempty_unique_refs(
                "system components",
                &system.component_ids,
                &component_ids,
            )?;
            validate_unique_refs(
                "system dependencies",
                &system.dependency_ids,
                &dependency_ids,
            )?;
            validate_nonempty_unique_refs(
                "system observation obligations",
                &system.observation_obligation_ids,
                &obligation_ids,
            )?;
            validate_nonempty_unique_refs(
                "system source snapshots",
                &system.source_snapshot_ids,
                &source_ids,
            )?;

            let system_targets: BTreeSet<_> =
                system.target_ids.iter().map(TargetId::as_str).collect();
            let system_components: BTreeSet<_> = system
                .component_ids
                .iter()
                .map(ComponentId::as_str)
                .collect();
            for component_id in &system.component_ids {
                let component = component_by_id(component_id).ok_or_else(|| {
                    ContractError::UnknownReference {
                        kind: "system component",
                        id: component_id.to_string(),
                    }
                })?;
                if !system_targets.contains(component.hosted_on.as_str()) {
                    return Err(ContractError::ScopeEscape(format!(
                        "component {} is hosted on target {} outside system {}",
                        component.component_id, component.hosted_on, system.system_id
                    )));
                }
            }
            for dependency_id in &system.dependency_ids {
                let dependency = dependency_by_id(dependency_id).ok_or_else(|| {
                    ContractError::UnknownReference {
                        kind: "system dependency",
                        id: dependency_id.to_string(),
                    }
                })?;
                if !system_components.contains(dependency.consumer_component_id.as_str())
                    || !system_components.contains(dependency.provider_component_id.as_str())
                {
                    return Err(ContractError::ScopeEscape(format!(
                        "dependency {} crosses system {} component membership",
                        dependency.dependency_id, system.system_id
                    )));
                }
            }
            for obligation_id in &system.observation_obligation_ids {
                let obligation = obligation_by_id(obligation_id).ok_or_else(|| {
                    ContractError::UnknownReference {
                        kind: "system observation obligation",
                        id: obligation_id.to_string(),
                    }
                })?;
                if !system_components.contains(obligation.component_id.as_str()) {
                    return Err(ContractError::ScopeEscape(format!(
                        "observation obligation {} names a component outside system {}",
                        obligation.observation_obligation_id, system.system_id
                    )));
                }
            }

            used_sources.extend(
                system
                    .source_snapshot_ids
                    .iter()
                    .map(SourceSnapshotId::as_str),
            );
            for target_id in &system.target_ids {
                let target =
                    target_by_id(target_id).ok_or_else(|| ContractError::UnknownReference {
                        kind: "system target",
                        id: target_id.to_string(),
                    })?;
                used_targets.insert(target_id.as_str());
                used_sources.extend(
                    target
                        .source_snapshot_ids
                        .iter()
                        .map(SourceSnapshotId::as_str),
                );
            }
            for component_id in &system.component_ids {
                let component = component_by_id(component_id).ok_or_else(|| {
                    ContractError::UnknownReference {
                        kind: "system component",
                        id: component_id.to_string(),
                    }
                })?;
                used_components.insert(component_id.as_str());
                used_sources.extend(
                    component
                        .source_snapshot_ids
                        .iter()
                        .map(SourceSnapshotId::as_str),
                );
            }
            for dependency_id in &system.dependency_ids {
                let dependency = dependency_by_id(dependency_id).ok_or_else(|| {
                    ContractError::UnknownReference {
                        kind: "system dependency",
                        id: dependency_id.to_string(),
                    }
                })?;
                used_dependencies.insert(dependency_id.as_str());
                used_sources.extend(
                    dependency
                        .source_snapshot_ids
                        .iter()
                        .map(SourceSnapshotId::as_str),
                );
            }
            for obligation_id in &system.observation_obligation_ids {
                let obligation = obligation_by_id(obligation_id).ok_or_else(|| {
                    ContractError::UnknownReference {
                        kind: "system observation obligation",
                        id: obligation_id.to_string(),
                    }
                })?;
                used_obligations.insert(obligation_id.as_str());
                used_sources.extend(
                    obligation
                        .source_snapshot_ids
                        .iter()
                        .map(SourceSnapshotId::as_str),
                );
            }
        }

        require_no_orphans("source snapshot", &source_ids, &used_sources)?;
        require_no_orphans("target", &target_ids, &used_targets)?;
        require_no_orphans("component", &component_ids, &used_components)?;
        require_no_orphans("dependency", &dependency_ids, &used_dependencies)?;
        require_no_orphans("observation obligation", &obligation_ids, &used_obligations)?;

        let bytes = canonical_json_bytes(&self.normalized())?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::TooLarge {
                actual: bytes.len(),
                limit: MAX_DOCUMENT_BYTES,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_compiled_profiles(&self) -> Result<(), ContractError> {
        for obligation in &self.observation_obligations {
            let version = obligation
                .profile
                .version
                .as_str()
                .parse::<u32>()
                .map_err(|_| {
                    ContractError::Profile(
                        "profile version did not survive structural validation".to_owned(),
                    )
                })?;
            let profile =
                resolve_profile(obligation.profile.id.as_str(), version).ok_or_else(|| {
                    ContractError::Profile(format!(
                        "obligation {} names profile {} v{} not compiled into this binary",
                        obligation.observation_obligation_id, obligation.profile.id, version
                    ))
                })?;
            let descriptor = profile.descriptor();
            let descriptor_digest = descriptor.digest().map_err(|error| {
                ContractError::Profile(format!(
                    "cannot identify compiled profile {} v{}: {error}",
                    descriptor.profile.id, descriptor.profile.version
                ))
            })?;
            if descriptor_digest.as_str() != obligation.profile.digest.as_str() {
                return Err(ContractError::Profile(format!(
                    "obligation {} profile descriptor digest does not match compiled {} v{}",
                    obligation.observation_obligation_id,
                    descriptor.profile.id,
                    descriptor.profile.version
                )));
            }
            if obligation.freshness_seconds > descriptor.freshness.reliance_seconds {
                return Err(ContractError::Profile(format!(
                    "obligation {} freshness {}s expands compiled profile reliance {}s",
                    obligation.observation_obligation_id,
                    obligation.freshness_seconds,
                    descriptor.freshness.reliance_seconds
                )));
            }

            let required_coverage: BTreeSet<_> = obligation
                .required_coverage
                .iter()
                .map(CoverageKind::as_str)
                .collect();
            let compiled_coverage: BTreeSet<_> = descriptor
                .coverage
                .iter()
                .map(|term| term.name.as_str())
                .collect();
            if required_coverage != compiled_coverage {
                return Err(ContractError::Profile(format!(
                    "obligation {} must name the complete compiled coverage vocabulary",
                    obligation.observation_obligation_id
                )));
            }
            let compiled_capabilities: BTreeSet<_> = descriptor
                .capabilities
                .iter()
                .map(|term| term.name.as_str())
                .collect();
            if let Some(capability) = obligation
                .granted_capabilities
                .iter()
                .find(|capability| !compiled_capabilities.contains(capability.as_str()))
            {
                return Err(ContractError::Profile(format!(
                    "obligation {} grants profile-unknown capability {}",
                    obligation.observation_obligation_id, capability
                )));
            }
            let context = ValidationContext {
                instance_id: obligation.instance_id.to_string(),
                request_subject: obligation.subject_binding.subject.to_string(),
                scope: ScopeGrant {
                    kind: obligation.subject_binding.scope.kind.to_string(),
                    value: obligation.subject_binding.scope.value.clone(),
                },
                vantage: VantageGrant {
                    kind: obligation.subject_binding.vantage.kind.to_string(),
                    value: obligation.subject_binding.vantage.value.clone(),
                },
                granted_capabilities: obligation
                    .granted_capabilities
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                received_at: DateTime::<Utc>::UNIX_EPOCH,
                max_observations: descriptor.limits.max_observations,
                max_future_skew: Duration::zero(),
            };
            profile.validate_binding(&context).map_err(|refusal| {
                ContractError::Profile(format!(
                    "obligation {} binding refused at {:?}/{:?}: {}",
                    obligation.observation_obligation_id,
                    refusal.boundary,
                    refusal.code,
                    refusal.message
                ))
            })?;
        }
        Ok(())
    }

    /// Computes the semantic identity of the validated, normalized complete
    /// draft. Input array ordering does not change this digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or canonicalization fails.
    pub fn digest(&self) -> Result<Sha256Digest, ContractError> {
        self.validate()?;
        semantic_digest(&self.normalized()).map_err(ContractError::from)
    }

    /// Compiles the exact closed proposal bytes for one selected system.
    ///
    /// A publication workflow can display and retain this artifact before a
    /// human ratifier produces the external record cited by [`RatificationV1`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the draft is invalid, the selected system
    /// is absent, or the bounded proposal cannot be canonicalized.
    pub fn compile_cut_proposal(
        &self,
        cut_id: CutId,
        system_id: &SystemId,
    ) -> Result<ScopeCutProposalV1, ContractError> {
        let result = self.build_cut_proposal(cut_id, system_id)?;
        result.qualify_with_compiled_profiles()?;
        Ok(result)
    }

    fn build_cut_proposal(
        &self,
        cut_id: CutId,
        system_id: &SystemId,
    ) -> Result<ScopeCutProposalV1, ContractError> {
        self.validate()?;
        let normalized = self.normalized();
        let system = normalized
            .systems
            .iter()
            .find(|system| system.system_id == *system_id)
            .cloned()
            .ok_or_else(|| ContractError::UnknownReference {
                kind: "system",
                id: system_id.to_string(),
            })?;

        let target_ids: BTreeSet<_> = system.target_ids.iter().collect();
        let component_ids: BTreeSet<_> = system.component_ids.iter().collect();
        let dependency_ids: BTreeSet<_> = system.dependency_ids.iter().collect();
        let obligation_ids: BTreeSet<_> = system.observation_obligation_ids.iter().collect();
        let targets: Vec<_> = normalized
            .targets
            .iter()
            .filter(|target| target_ids.contains(&target.target_id))
            .cloned()
            .collect();
        let components: Vec<_> = normalized
            .components
            .iter()
            .filter(|component| component_ids.contains(&component.component_id))
            .cloned()
            .collect();
        let dependencies: Vec<_> = normalized
            .dependencies
            .iter()
            .filter(|dependency| dependency_ids.contains(&dependency.dependency_id))
            .cloned()
            .collect();
        let observation_obligations: Vec<_> = normalized
            .observation_obligations
            .iter()
            .filter(|obligation| obligation_ids.contains(&obligation.observation_obligation_id))
            .cloned()
            .collect();

        let mut source_ids: BTreeSet<&SourceSnapshotId> =
            system.source_snapshot_ids.iter().collect();
        for target in &targets {
            source_ids.extend(&target.source_snapshot_ids);
        }
        for component in &components {
            source_ids.extend(&component.source_snapshot_ids);
        }
        for dependency in &dependencies {
            source_ids.extend(&dependency.source_snapshot_ids);
        }
        for obligation in &observation_obligations {
            source_ids.extend(&obligation.source_snapshot_ids);
        }
        let source_snapshots = normalized
            .source_snapshots
            .iter()
            .filter(|source| source_ids.contains(&source.source_snapshot_id))
            .cloned()
            .collect();

        let proposal = ScopeCutProposalBodyV1 {
            cut_id,
            source_spec: SystemSpecReferenceV1 {
                spec_id: normalized.spec_id.clone(),
                revision: normalized.revision,
                spec_digest: semantic_digest(&normalized)?,
            },
            system,
            source_snapshots,
            targets,
            components,
            dependencies,
            observation_obligations,
            authority: AuthoritySemantics::None,
        };
        let proposal_digest = versioned_artifact_digest(SCOPE_CUT_PROPOSAL_SCHEMA, &proposal)?;
        let result = ScopeCutProposalV1 {
            schema: SCOPE_CUT_PROPOSAL_SCHEMA.to_owned(),
            proposal_digest,
            proposal,
        };
        result.verify()?;
        Ok(result)
    }

    /// Compiles one closed system cut under an exact external human
    /// ratification record that cites the proposal bytes.
    ///
    /// This operation records ratification; it does not authorize any effect.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the draft is invalid, the selected system
    /// is absent, or the resulting bounded cut cannot be canonicalized.
    pub fn compile_cut(
        &self,
        cut_id: CutId,
        system_id: &SystemId,
        ratification: RatificationV1,
    ) -> Result<PublishedScopeCutV1, ContractError> {
        let proposal = self.compile_cut_proposal(cut_id, system_id)?;
        ratification.verify()?;
        validate_ratification_chronology(&ratification, &proposal.proposal.source_snapshots)?;
        if ratification.ratified_proposal_digest != proposal.proposal_digest {
            return Err(ContractError::RatificationProposalMismatch);
        }
        let cut = ScopeCutBodyV1 {
            cut_id: proposal.proposal.cut_id,
            source_spec: proposal.proposal.source_spec,
            ratification,
            system: proposal.proposal.system,
            source_snapshots: proposal.proposal.source_snapshots,
            targets: proposal.proposal.targets,
            components: proposal.proposal.components,
            dependencies: proposal.proposal.dependencies,
            observation_obligations: proposal.proposal.observation_obligations,
            authority: AuthoritySemantics::None,
        };
        let cut_digest = versioned_artifact_digest(SCOPE_CUT_SCHEMA, &cut)?;
        let published = PublishedScopeCutV1 {
            schema: SCOPE_CUT_SCHEMA.to_owned(),
            cut_digest,
            cut,
        };
        published.qualify_with_compiled_profiles()?;
        Ok(published)
    }

    fn normalized(&self) -> Self {
        let mut value = self.clone();
        value
            .source_snapshots
            .sort_by(|left, right| left.source_snapshot_id.cmp(&right.source_snapshot_id));
        value
            .targets
            .sort_by(|left, right| left.target_id.cmp(&right.target_id));
        for target in &mut value.targets {
            target.source_snapshot_ids.sort();
        }
        value
            .components
            .sort_by(|left, right| left.component_id.cmp(&right.component_id));
        for component in &mut value.components {
            component.source_snapshot_ids.sort();
        }
        value
            .dependencies
            .sort_by(|left, right| left.dependency_id.cmp(&right.dependency_id));
        for dependency in &mut value.dependencies {
            dependency.source_snapshot_ids.sort();
        }
        value.observation_obligations.sort_by(|left, right| {
            left.observation_obligation_id
                .cmp(&right.observation_obligation_id)
        });
        for obligation in &mut value.observation_obligations {
            obligation
                .required_coverage
                .sort_by(|left, right| left.as_str().cmp(right.as_str()));
            obligation
                .granted_capabilities
                .sort_by(|left, right| left.as_str().cmp(right.as_str()));
            obligation.source_snapshot_ids.sort();
        }
        value
            .systems
            .sort_by(|left, right| left.system_id.cmp(&right.system_id));
        for system in &mut value.systems {
            system.target_ids.sort();
            system.component_ids.sort();
            system.dependency_ids.sort();
            system.observation_obligation_ids.sort();
            system.source_snapshot_ids.sort();
        }
        value
    }
}

impl ScopeCutProposalV1 {
    /// Verifies the versioned digest, closed references, canonical ordering,
    /// and every profile-independent system-contract bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the proposal is malformed, expanded,
    /// non-canonical, or digest-inconsistent.
    pub fn verify(&self) -> Result<(), ContractError> {
        require_schema(&self.schema, SCOPE_CUT_PROPOSAL_SCHEMA)?;
        let expected = versioned_artifact_digest(SCOPE_CUT_PROPOSAL_SCHEMA, &self.proposal)?;
        if expected != self.proposal_digest {
            return Err(ContractError::DigestMismatch("scope cut proposal"));
        }
        let spec = SystemSpecV1 {
            schema: SYSTEM_SPEC_SCHEMA.to_owned(),
            spec_id: self.proposal.source_spec.spec_id.clone(),
            revision: self.proposal.source_spec.revision,
            title: self.proposal.system.title.clone(),
            source_snapshots: self.proposal.source_snapshots.clone(),
            targets: self.proposal.targets.clone(),
            components: self.proposal.components.clone(),
            dependencies: self.proposal.dependencies.clone(),
            observation_obligations: self.proposal.observation_obligations.clone(),
            systems: vec![self.proposal.system.clone()],
            authority: AuthoritySemantics::None,
        };
        spec.validate()?;
        let normalized = spec.normalized();
        if self.proposal.source_snapshots != normalized.source_snapshots
            || self.proposal.targets != normalized.targets
            || self.proposal.components != normalized.components
            || self.proposal.dependencies != normalized.dependencies
            || self.proposal.observation_obligations != normalized.observation_obligations
            || self.proposal.system != normalized.systems[0]
        {
            return Err(ContractError::NonCanonical("scope cut proposal arrays"));
        }
        let bytes = canonical_json_bytes(self)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::TooLarge {
                actual: bytes.len(),
                limit: MAX_DOCUMENT_BYTES,
            });
        }
        Ok(())
    }

    /// Qualifies every observation obligation against the profiles compiled
    /// into this binary after verifying immutable proposal custody.
    ///
    /// Historical custody verification should use [`Self::verify`]; this
    /// qualification intentionally fails when the required profile version is
    /// not present in the current binary.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for structural failure or any unknown/drifted
    /// profile, coverage, capability, freshness, subject, scope, or vantage.
    pub fn qualify_with_compiled_profiles(&self) -> Result<(), ContractError> {
        self.verify()?;
        let spec = SystemSpecV1 {
            schema: SYSTEM_SPEC_SCHEMA.to_owned(),
            spec_id: self.proposal.source_spec.spec_id.clone(),
            revision: self.proposal.source_spec.revision,
            title: self.proposal.system.title.clone(),
            source_snapshots: self.proposal.source_snapshots.clone(),
            targets: self.proposal.targets.clone(),
            components: self.proposal.components.clone(),
            dependencies: self.proposal.dependencies.clone(),
            observation_obligations: self.proposal.observation_obligations.clone(),
            systems: vec![self.proposal.system.clone()],
            authority: AuthoritySemantics::None,
        };
        spec.validate_compiled_profiles()
    }
}

impl PublishedScopeCutV1 {
    /// Verifies schema, canonical digest, closed references, ordering, and all
    /// system-contract bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the cut is malformed, expanded,
    /// non-canonical, or digest-inconsistent.
    pub fn verify(&self) -> Result<(), ContractError> {
        require_schema(&self.schema, SCOPE_CUT_SCHEMA)?;
        if self.cut.source_spec.revision == 0 {
            return Err(ContractError::InvalidValue(
                "source specification revision must be positive",
            ));
        }
        let expected = versioned_artifact_digest(SCOPE_CUT_SCHEMA, &self.cut)?;
        if expected != self.cut_digest {
            return Err(ContractError::DigestMismatch("scope cut"));
        }
        self.cut.ratification.verify()?;
        validate_ratification_chronology(&self.cut.ratification, &self.cut.source_snapshots)?;
        let proposal = ScopeCutProposalV1 {
            schema: SCOPE_CUT_PROPOSAL_SCHEMA.to_owned(),
            proposal_digest: self.cut.ratification.ratified_proposal_digest.clone(),
            proposal: ScopeCutProposalBodyV1 {
                cut_id: self.cut.cut_id.clone(),
                source_spec: self.cut.source_spec.clone(),
                system: self.cut.system.clone(),
                source_snapshots: self.cut.source_snapshots.clone(),
                targets: self.cut.targets.clone(),
                components: self.cut.components.clone(),
                dependencies: self.cut.dependencies.clone(),
                observation_obligations: self.cut.observation_obligations.clone(),
                authority: AuthoritySemantics::None,
            },
        };
        proposal.verify().map_err(|error| match error {
            ContractError::DigestMismatch("scope cut proposal") => {
                ContractError::RatificationProposalMismatch
            }
            other => other,
        })?;
        let spec = SystemSpecV1 {
            schema: SYSTEM_SPEC_SCHEMA.to_owned(),
            spec_id: self.cut.source_spec.spec_id.clone(),
            revision: self.cut.source_spec.revision,
            title: self.cut.system.title.clone(),
            source_snapshots: self.cut.source_snapshots.clone(),
            targets: self.cut.targets.clone(),
            components: self.cut.components.clone(),
            dependencies: self.cut.dependencies.clone(),
            observation_obligations: self.cut.observation_obligations.clone(),
            systems: vec![self.cut.system.clone()],
            authority: AuthoritySemantics::None,
        };
        spec.validate()?;
        let normalized = spec.normalized();
        if self.cut.source_snapshots != normalized.source_snapshots
            || self.cut.targets != normalized.targets
            || self.cut.components != normalized.components
            || self.cut.dependencies != normalized.dependencies
            || self.cut.observation_obligations != normalized.observation_obligations
            || self.cut.system != normalized.systems[0]
        {
            return Err(ContractError::NonCanonical("scope cut arrays"));
        }
        let bytes = canonical_json_bytes(self)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::TooLarge {
                actual: bytes.len(),
                limit: MAX_DOCUMENT_BYTES,
            });
        }
        Ok(())
    }

    /// Qualifies the cut's exact observation obligations against the current
    /// compiled profile registry after verifying immutable custody.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for structural failure or any unknown/drifted
    /// compiled profile contract.
    pub fn qualify_with_compiled_profiles(&self) -> Result<(), ContractError> {
        self.verify()?;
        let proposal = ScopeCutProposalV1 {
            schema: SCOPE_CUT_PROPOSAL_SCHEMA.to_owned(),
            proposal_digest: self.cut.ratification.ratified_proposal_digest.clone(),
            proposal: ScopeCutProposalBodyV1 {
                cut_id: self.cut.cut_id.clone(),
                source_spec: self.cut.source_spec.clone(),
                system: self.cut.system.clone(),
                source_snapshots: self.cut.source_snapshots.clone(),
                targets: self.cut.targets.clone(),
                components: self.cut.components.clone(),
                dependencies: self.cut.dependencies.clone(),
                observation_obligations: self.cut.observation_obligations.clone(),
                authority: AuthoritySemantics::None,
            },
        };
        proposal.qualify_with_compiled_profiles()
    }

    /// Verifies that this cut is the exact closed derivation of retained
    /// source-specification bytes.
    ///
    /// This is a custody check and does not require the source specification's
    /// profiles to remain compiled in the current binary.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the retained spec identity, revision,
    /// digest, selected membership, or derived proposal differs from the cut.
    pub fn verify_against_spec(&self, spec: &SystemSpecV1) -> Result<(), ContractError> {
        self.verify()?;
        let expected =
            spec.build_cut_proposal(self.cut.cut_id.clone(), &self.cut.system.system_id)?;
        let actual = ScopeCutProposalBodyV1 {
            cut_id: self.cut.cut_id.clone(),
            source_spec: self.cut.source_spec.clone(),
            system: self.cut.system.clone(),
            source_snapshots: self.cut.source_snapshots.clone(),
            targets: self.cut.targets.clone(),
            components: self.cut.components.clone(),
            dependencies: self.cut.dependencies.clone(),
            observation_obligations: self.cut.observation_obligations.clone(),
            authority: AuthoritySemantics::None,
        };
        if expected.proposal != actual
            || expected.proposal_digest != self.cut.ratification.ratified_proposal_digest
        {
            return Err(ContractError::SourceSpecMismatch);
        }
        Ok(())
    }

    /// Derives the complete NQ observation projection for this exact cut.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if the cut or projection fails verification.
    pub fn nq_observation_projection(
        &self,
        projection_id: ProjectionId,
    ) -> Result<NqObservationProjectionV1, ContractError> {
        self.qualify_with_compiled_profiles()?;
        let projection = NqObservationProjectionBodyV1 {
            projection_id,
            scope_cut: self.reference(),
            system_id: self.cut.system.system_id.clone(),
            targets: self.cut.targets.clone(),
            components: self.cut.components.clone(),
            dependencies: self.cut.dependencies.clone(),
            observation_obligations: self.cut.observation_obligations.clone(),
            authority: AuthoritySemantics::None,
        };
        let result = NqObservationProjectionV1 {
            schema: NQ_OBSERVATION_PROJECTION_SCHEMA.to_owned(),
            projection_digest: versioned_artifact_digest(
                NQ_OBSERVATION_PROJECTION_SCHEMA,
                &projection,
            )?,
            projection,
        };
        result.verify_against(self)?;
        Ok(result)
    }

    /// Derives a narrowing-only descriptive future Porter projection.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if a target or component is outside the cut,
    /// if the direct target scope differs from the direct components' hosts,
    /// or if any dependency-derived affected component lacks a witness
    /// obligation.
    pub fn porter_actuation_projection(
        &self,
        projection_id: ProjectionId,
        selection: &PorterProjectionSelectionV1,
    ) -> Result<PorterActuationProjectionV1, ContractError> {
        self.qualify_with_compiled_profiles()?;
        let projection = self.porter_projection_body(projection_id, selection)?;
        let result = PorterActuationProjectionV1 {
            schema: PORTER_ACTUATION_PROJECTION_SCHEMA.to_owned(),
            projection_digest: versioned_artifact_digest(
                PORTER_ACTUATION_PROJECTION_SCHEMA,
                &projection,
            )?,
            projection,
        };
        result.verify_against(self)?;
        Ok(result)
    }

    fn reference(&self) -> ScopeCutReferenceV1 {
        ScopeCutReferenceV1 {
            cut_id: self.cut.cut_id.clone(),
            cut_digest: self.cut_digest.clone(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn porter_projection_body(
        &self,
        projection_id: ProjectionId,
        selection: &PorterProjectionSelectionV1,
    ) -> Result<PorterActuationProjectionBodyV1, ContractError> {
        let cut_target_ids: BTreeSet<_> = self.cut.targets.iter().map(|v| &v.target_id).collect();
        let cut_component_ids: BTreeSet<_> = self
            .cut
            .components
            .iter()
            .map(|v| &v.component_id)
            .collect();
        validate_nonempty_unique_refs(
            "Porter projection targets",
            &selection.target_ids,
            &cut_target_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<BTreeSet<_>>(),
        )?;
        validate_nonempty_unique_refs(
            "Porter projection components",
            &selection.component_ids,
            &cut_component_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<BTreeSet<_>>(),
        )?;
        let selected_targets: BTreeSet<_> = selection.target_ids.iter().collect();
        let selected_components: BTreeSet<_> = selection.component_ids.iter().collect();
        let expected_targets: BTreeSet<_> = self
            .cut
            .components
            .iter()
            .filter(|component| selected_components.contains(&component.component_id))
            .map(|component| &component.hosted_on)
            .collect();
        if selected_targets != expected_targets {
            return Err(ContractError::ScopeEscape(
                "Porter projection targets must equal the host targets of selected components"
                    .to_owned(),
            ));
        }
        let actuation_components: Vec<_> = self
            .cut
            .components
            .iter()
            .filter(|component| selected_components.contains(&component.component_id))
            .cloned()
            .collect();
        let actuation_targets = self
            .cut
            .targets
            .iter()
            .filter(|target| selected_targets.contains(&target.target_id))
            .cloned()
            .collect();

        let mut affected_component_ids = selected_components.clone();
        loop {
            let before = affected_component_ids.len();
            for dependency in &self.cut.dependencies {
                if affected_component_ids.contains(&dependency.provider_component_id) {
                    affected_component_ids.insert(&dependency.consumer_component_id);
                }
            }
            if affected_component_ids.len() == before {
                break;
            }
        }
        let affected_components: Vec<_> = self
            .cut
            .components
            .iter()
            .filter(|component| affected_component_ids.contains(&component.component_id))
            .cloned()
            .collect();
        let affected_target_ids: BTreeSet<_> = affected_components
            .iter()
            .map(|component| &component.hosted_on)
            .collect();
        let affected_targets = self
            .cut
            .targets
            .iter()
            .filter(|target| affected_target_ids.contains(&target.target_id))
            .cloned()
            .collect();
        if affected_component_ids.iter().any(|component_id| {
            !self
                .cut
                .observation_obligations
                .iter()
                .any(|obligation| &obligation.component_id == *component_id)
        }) {
            return Err(ContractError::InvalidValue(
                "every affected component requires at least one cut witness obligation",
            ));
        }
        let verification_obligations = self
            .cut
            .observation_obligations
            .iter()
            .filter(|obligation| affected_component_ids.contains(&obligation.component_id))
            .cloned()
            .collect();
        let boundary_dependencies = self
            .cut
            .dependencies
            .iter()
            .filter(|dependency| {
                affected_component_ids.contains(&dependency.consumer_component_id)
                    || affected_component_ids.contains(&dependency.provider_component_id)
            })
            .cloned()
            .collect();
        Ok(PorterActuationProjectionBodyV1 {
            projection_id,
            scope_cut: self.reference(),
            system_id: self.cut.system.system_id.clone(),
            actuation_targets,
            actuation_components,
            affected_targets,
            affected_components,
            boundary_dependencies,
            verification_obligations,
            authority: AuthoritySemantics::None,
        })
    }
}

impl NqObservationProjectionV1 {
    /// Verifies this projection against the exact published cut it cites.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] on schema, digest, cut, membership, or
    /// obligation drift.
    pub fn verify_against(&self, cut: &PublishedScopeCutV1) -> Result<(), ContractError> {
        require_schema(&self.schema, NQ_OBSERVATION_PROJECTION_SCHEMA)?;
        cut.verify()?;
        if versioned_artifact_digest(NQ_OBSERVATION_PROJECTION_SCHEMA, &self.projection)?
            != self.projection_digest
        {
            return Err(ContractError::DigestMismatch("NQ observation projection"));
        }
        let expected = cut.nq_observation_projection_body(self.projection.projection_id.clone());
        if self.projection != expected {
            return Err(ContractError::ProjectionCutMismatch);
        }
        Ok(())
    }
}

impl PublishedScopeCutV1 {
    fn nq_observation_projection_body(
        &self,
        projection_id: ProjectionId,
    ) -> NqObservationProjectionBodyV1 {
        NqObservationProjectionBodyV1 {
            projection_id,
            scope_cut: self.reference(),
            system_id: self.cut.system.system_id.clone(),
            targets: self.cut.targets.clone(),
            components: self.cut.components.clone(),
            dependencies: self.cut.dependencies.clone(),
            observation_obligations: self.cut.observation_obligations.clone(),
            authority: AuthoritySemantics::None,
        }
    }
}

impl PorterActuationProjectionV1 {
    /// Verifies this projection against the exact published cut it cites.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] on schema, digest, cut, direct scope, affected
    /// boundary, dependency, or verification-obligation drift.
    pub fn verify_against(&self, cut: &PublishedScopeCutV1) -> Result<(), ContractError> {
        require_schema(&self.schema, PORTER_ACTUATION_PROJECTION_SCHEMA)?;
        cut.verify()?;
        if versioned_artifact_digest(PORTER_ACTUATION_PROJECTION_SCHEMA, &self.projection)?
            != self.projection_digest
        {
            return Err(ContractError::DigestMismatch("Porter actuation projection"));
        }
        let selection = PorterProjectionSelectionV1 {
            target_ids: self
                .projection
                .actuation_targets
                .iter()
                .map(|target| target.target_id.clone())
                .collect(),
            component_ids: self
                .projection
                .actuation_components
                .iter()
                .map(|component| component.component_id.clone())
                .collect(),
        };
        let expected =
            cut.porter_projection_body(self.projection.projection_id.clone(), &selection)?;
        if self.projection != expected {
            return Err(ContractError::ProjectionCutMismatch);
        }
        Ok(())
    }
}

/// Parses and validates a bounded strict JSON system specification.
///
/// Unknown fields and duplicate object keys at any depth are rejected.
///
/// # Errors
///
/// Returns [`ContractError`] for oversized, malformed, duplicate-key, or
/// semantically invalid input.
pub fn parse_system_spec(bytes: &[u8]) -> Result<SystemSpecV1, ContractError> {
    let value: SystemSpecV1 = strict_json(bytes)?;
    value.validate()?;
    Ok(value)
}

/// Parses and verifies a bounded strict JSON scope-cut proposal.
///
/// # Errors
///
/// Returns [`ContractError`] for oversized, malformed, duplicate-key,
/// digest-inconsistent, or semantically invalid input.
pub fn parse_scope_cut_proposal(bytes: &[u8]) -> Result<ScopeCutProposalV1, ContractError> {
    let value: ScopeCutProposalV1 = strict_json(bytes)?;
    value.verify()?;
    Ok(value)
}

/// Parses and verifies a bounded strict JSON published cut.
///
/// # Errors
///
/// Returns [`ContractError`] for oversized, malformed, duplicate-key, or
/// semantically invalid input.
pub fn parse_scope_cut(bytes: &[u8]) -> Result<PublishedScopeCutV1, ContractError> {
    let value: PublishedScopeCutV1 = strict_json(bytes)?;
    value.verify()?;
    Ok(value)
}

/// Parses and verifies a bounded strict JSON NQ observation projection against
/// its exact published cut.
///
/// # Errors
///
/// Returns [`ContractError`] for oversized, malformed, duplicate-key,
/// digest-inconsistent, or cut-inconsistent input.
pub fn parse_nq_observation_projection(
    bytes: &[u8],
    cut: &PublishedScopeCutV1,
) -> Result<NqObservationProjectionV1, ContractError> {
    let value: NqObservationProjectionV1 = strict_json(bytes)?;
    value.verify_against(cut)?;
    Ok(value)
}

/// Parses and verifies a bounded strict JSON future Porter projection against
/// its exact published cut.
///
/// # Errors
///
/// Returns [`ContractError`] for oversized, malformed, duplicate-key,
/// digest-inconsistent, scope-expanded, or cut-inconsistent input.
pub fn parse_porter_actuation_projection(
    bytes: &[u8],
    cut: &PublishedScopeCutV1,
) -> Result<PorterActuationProjectionV1, ContractError> {
    let value: PorterActuationProjectionV1 = strict_json(bytes)?;
    value.verify_against(cut)?;
    Ok(value)
}

/// Returns canonical UTF-8 JSON bytes for a system-contract artifact.
///
/// # Errors
///
/// Returns [`ContractError`] when the value cannot be represented in the
/// canonical I-JSON/JCS model or exceeds the document byte bound.
pub fn canonical_document<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let bytes = canonical_json_bytes(value)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ContractError::TooLarge {
            actual: bytes.len(),
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    Ok(bytes)
}

/// Computes a schema-domain-separated digest for one artifact body.
///
/// The hashed value is canonical JCS JSON with exactly the keys `schema` and
/// `artifact`. Embedded digest fields are therefore identities of a specific
/// versioned contract, not merely of a structurally similar body.
///
/// # Errors
///
/// Returns [`ContractError`] if the envelope cannot be canonicalized.
pub fn versioned_artifact_digest<T: Serialize>(
    schema: &str,
    artifact: &T,
) -> Result<Sha256Digest, ContractError> {
    #[derive(Serialize)]
    struct DigestEnvelope<'a, T> {
        schema: &'a str,
        artifact: &'a T,
    }

    semantic_digest(&DigestEnvelope { schema, artifact }).map_err(ContractError::from)
}

fn strict_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ContractError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ContractError::TooLarge {
            actual: bytes.len(),
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| ContractError::InvalidJson(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| ContractError::InvalidJson(error.to_string()))
}

struct StrictValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> de::Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate object key {key:?}"
                )));
            }
            values.insert(key, object.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(serde_json::Value::Object(values)))
    }
}

fn validate_count(
    kind: &'static str,
    actual: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), ContractError> {
    if actual < minimum || actual > maximum {
        return Err(ContractError::Cardinality {
            kind,
            actual,
            minimum,
            maximum,
        });
    }
    Ok(())
}

fn validate_text(kind: &'static str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || display_confusing(character))
    {
        return Err(ContractError::InvalidText(kind));
    }
    Ok(())
}

fn display_confusing(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

fn validate_binding_value(
    kind: &'static str,
    value: &serde_json::Value,
) -> Result<(), ContractError> {
    let bytes = canonical_json_bytes(value)?;
    if bytes.len() > MAX_BINDING_VALUE_BYTES {
        return Err(ContractError::TooLarge {
            actual: bytes.len(),
            limit: MAX_BINDING_VALUE_BYTES,
        });
    }
    if !value.is_object() {
        return Err(ContractError::InvalidText(kind));
    }
    Ok(())
}

fn unique_ids<'a>(
    kind: &'static str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, ContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ContractError::Duplicate {
                kind,
                id: value.to_owned(),
            });
        }
    }
    Ok(seen)
}

trait IdRef {
    fn text(&self) -> &str;
}

macro_rules! impl_id_ref {
    ($($name:ty),+ $(,)?) => {
        $(impl IdRef for $name {
            fn text(&self) -> &str {
                self.as_str()
            }
        })+
    };
}

impl_id_ref!(
    SourceSnapshotId,
    TargetId,
    ComponentId,
    DependencyId,
    ObservationObligationId,
);

fn validate_nonempty_unique_refs<T: IdRef>(
    kind: &'static str,
    values: &[T],
    available: &BTreeSet<&str>,
) -> Result<(), ContractError> {
    if values.is_empty() {
        return Err(ContractError::Cardinality {
            kind,
            actual: 0,
            minimum: 1,
            maximum: usize::MAX,
        });
    }
    validate_unique_refs(kind, values, available)
}

fn validate_unique_refs<T: IdRef>(
    kind: &'static str,
    values: &[T],
    available: &BTreeSet<&str>,
) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !available.contains(value.text()) {
            return Err(ContractError::UnknownReference {
                kind,
                id: value.text().to_owned(),
            });
        }
        if !seen.insert(value.text()) {
            return Err(ContractError::Duplicate {
                kind,
                id: value.text().to_owned(),
            });
        }
    }
    Ok(())
}

fn require_reference(
    kind: &'static str,
    value: &str,
    available: &BTreeSet<&str>,
) -> Result<(), ContractError> {
    if !available.contains(value) {
        return Err(ContractError::UnknownReference {
            kind,
            id: value.to_owned(),
        });
    }
    Ok(())
}

fn require_no_orphans(
    kind: &'static str,
    available: &BTreeSet<&str>,
    used: &BTreeSet<&str>,
) -> Result<(), ContractError> {
    if let Some(orphan) = available.difference(used).next() {
        return Err(ContractError::Orphan {
            kind,
            id: (*orphan).to_owned(),
        });
    }
    Ok(())
}

fn require_schema(actual: &str, expected: &'static str) -> Result<(), ContractError> {
    if actual != expected {
        return Err(ContractError::WrongSchema {
            expected,
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn validate_ratification_chronology(
    ratification: &RatificationV1,
    sources: &[SourceSnapshotV1],
) -> Result<(), ContractError> {
    if sources
        .iter()
        .any(|source| source.captured_at > ratification.ratified_at)
    {
        return Err(ContractError::InvalidValue(
            "ratification time precedes a contributing source snapshot",
        ));
    }
    Ok(())
}

/// Strict system-contract validation or compilation failure.
#[derive(Debug, Error)]
pub enum ContractError {
    /// An identifier was empty, oversized, or outside the stable alphabet.
    #[error("invalid bounded system-contract identifier {0:?}")]
    InvalidIdentifier(String),
    /// An operator-facing string was empty, oversized, or contained controls.
    #[error("invalid bounded text in {0}")]
    InvalidText(&'static str),
    /// A document named the wrong exact schema.
    #[error("wrong schema {actual:?}; expected {expected}")]
    WrongSchema {
        /// Required exact schema identifier.
        expected: &'static str,
        /// Received schema identifier.
        actual: String,
    },
    /// A bounded collection fell outside its compiled range.
    #[error("{kind} cardinality {actual} is outside {minimum}..={maximum}")]
    Cardinality {
        /// Collection name.
        kind: &'static str,
        /// Actual item count.
        actual: usize,
        /// Smallest accepted count.
        minimum: usize,
        /// Largest accepted count.
        maximum: usize,
    },
    /// A set-like collection repeated one identity.
    #[error("duplicate {kind} identity {id:?}")]
    Duplicate {
        /// Identity class.
        kind: &'static str,
        /// Repeated identifier.
        id: String,
    },
    /// A reference did not exist in the exact input document.
    #[error("unknown {kind} reference {id:?}")]
    UnknownReference {
        /// Reference class.
        kind: &'static str,
        /// Missing identifier.
        id: String,
    },
    /// An object was not included by any named system.
    #[error("orphaned {kind} {id:?} is not in any system cut")]
    Orphan {
        /// Object class.
        kind: &'static str,
        /// Orphaned identifier.
        id: String,
    },
    /// A relationship or projection attempted to widen its parent scope.
    #[error("scope escape: {0}")]
    ScopeEscape(String),
    /// A scalar failed a compiled consistency rule.
    #[error("invalid system-contract value: {0}")]
    InvalidValue(&'static str),
    /// Canonically equivalent arrays were not in their required order.
    #[error("non-canonical ordering in {0}")]
    NonCanonical(&'static str),
    /// An embedded semantic digest did not match its body.
    #[error("{0} semantic digest mismatch")]
    DigestMismatch(&'static str),
    /// A projection did not exactly derive from the cited cut.
    #[error("projection does not match its exact published scope cut")]
    ProjectionCutMismatch,
    /// A retained source specification did not derive this exact cut closure.
    #[error("published cut does not derive from the retained source specification")]
    SourceSpecMismatch,
    /// The supplied ratification record cited different proposal bytes.
    #[error("ratification record does not cite the exact scope-cut proposal digest")]
    RatificationProposalMismatch,
    /// The ratification record digest did not identify its own exact fields.
    #[error("ratification record digest does not match its canonical fields")]
    RatificationRecordMismatch,
    /// A purported compiled profile identity, coverage set, capability, or
    /// binding did not match the executable catalog.
    #[error("compiled profile contract mismatch: {0}")]
    Profile(String),
    /// Input or canonical output crossed a hard byte bound.
    #[error("system-contract document is {actual} bytes; limit is {limit}")]
    TooLarge {
        /// Actual byte count.
        actual: usize,
        /// Maximum accepted byte count.
        limit: usize,
    },
    /// Strict JSON decoding failed.
    #[error("invalid strict system-contract JSON: {0}")]
    InvalidJson(String),
    /// JCS/I-JSON canonicalization failed.
    #[error(transparent)]
    Canonicalization(#[from] nq_protocol::CanonicalizationError),
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use nq_protocol::{
        ProfileId, ProfileVersion, ScopeBinding, ScopeKind, SubjectId, VantageBinding, VantageKind,
    };
    use serde_json::json;

    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn source(id: &str, kind: SourceKind, byte: u8) -> SourceSnapshotV1 {
        SourceSnapshotV1 {
            source_snapshot_id: SourceSnapshotId::new(id).unwrap(),
            kind,
            content_digest: digest(byte),
            captured_at: Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap(),
            provenance: format!("git:specimens/{id}@sha256"),
        }
    }

    fn obligation(id: &str, component: &str, instance: &str) -> ObservationObligationV1 {
        let compiled = nq_profiles::resolve_profile("nq.conformance", 1).unwrap();
        let descriptor = compiled.descriptor();
        ObservationObligationV1 {
            observation_obligation_id: ObservationObligationId::new(id).unwrap(),
            component_id: ComponentId::new(component).unwrap(),
            instance_id: InstanceId::new(instance).unwrap(),
            profile: ProfileBinding {
                id: ProfileId::new("nq.conformance").unwrap(),
                version: ProfileVersion::new("1").unwrap(),
                digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str()).unwrap(),
            },
            subject_binding: SubjectBinding {
                subject: SubjectId::new(format!("conformance:{component}")).unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").unwrap(),
                    value: json!({"id": component, "nonce": "system-cut-specimen"}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").unwrap(),
                    value: json!({}),
                },
            },
            required_coverage: descriptor
                .coverage
                .iter()
                .map(|term| CoverageKind::new(&term.name).unwrap())
                .collect(),
            granted_capabilities: Vec::new(),
            freshness_seconds: 60,
            source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
        }
    }

    fn fixture() -> SystemSpecV1 {
        let component = |id: &str, kind: &str| ComponentV1 {
            component_id: ComponentId::new(id).unwrap(),
            kind: ComponentKind::new(kind).unwrap(),
            hosted_on: TargetId::new("sushi-k").unwrap(),
            source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
        };
        let dependency = |id: &str, consumer: &str, provider: &str| DependencyV1 {
            dependency_id: DependencyId::new(id).unwrap(),
            consumer_component_id: ComponentId::new(consumer).unwrap(),
            provider_component_id: ComponentId::new(provider).unwrap(),
            requirement: DependencyRequirement::Required,
            source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
        };
        SystemSpecV1 {
            schema: SYSTEM_SPEC_SCHEMA.into(),
            spec_id: SpecId::new("home-netbox").unwrap(),
            revision: 1,
            title: "Home NetBox system".into(),
            source_snapshots: vec![
                source("bootstrap-sushi-k", SourceKind::BootstrapTarget, 0x11),
                source("authored-home-netbox", SourceKind::OperatorAuthored, 0x22),
            ],
            targets: vec![TargetV1 {
                target_id: TargetId::new("sushi-k").unwrap(),
                target_class: TargetClass::new("persistent-dev").unwrap(),
                target_identity_digest: digest(0x33),
                source_snapshot_ids: vec![SourceSnapshotId::new("bootstrap-sushi-k").unwrap()],
            }],
            components: vec![
                component("netbox-web", "web"),
                component("netbox-worker", "worker"),
                component("postgres", "database"),
                component("redis", "cache"),
            ],
            dependencies: vec![
                dependency("web-postgres", "netbox-web", "postgres"),
                dependency("web-redis", "netbox-web", "redis"),
                dependency("worker-postgres", "netbox-worker", "postgres"),
                dependency("worker-redis", "netbox-worker", "redis"),
            ],
            observation_obligations: vec![
                obligation("observe-web", "netbox-web", "netbox-web-local"),
                obligation("observe-worker", "netbox-worker", "netbox-worker-local"),
                obligation("observe-postgres", "postgres", "postgres-local"),
                obligation("observe-redis", "redis", "redis-local"),
            ],
            systems: vec![SystemDefinitionV1 {
                system_id: SystemId::new("home-netbox").unwrap(),
                title: "Home NetBox".into(),
                target_ids: vec![TargetId::new("sushi-k").unwrap()],
                component_ids: ["netbox-web", "netbox-worker", "postgres", "redis"]
                    .into_iter()
                    .map(|id| ComponentId::new(id).unwrap())
                    .collect(),
                dependency_ids: [
                    "web-postgres",
                    "web-redis",
                    "worker-postgres",
                    "worker-redis",
                ]
                .into_iter()
                .map(|id| DependencyId::new(id).unwrap())
                .collect(),
                observation_obligation_ids: [
                    "observe-web",
                    "observe-worker",
                    "observe-postgres",
                    "observe-redis",
                ]
                .into_iter()
                .map(|id| ObservationObligationId::new(id).unwrap())
                .collect(),
                source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
            }],
            authority: AuthoritySemantics::None,
        }
    }

    fn ratification(byte: u8, proposal_digest: Sha256Digest) -> RatificationV1 {
        RatificationV1::new(
            OperatorId::new("local:jbeck").unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 16, 13, 0, 0).unwrap()
                + Duration::seconds(i64::from(byte)),
            proposal_digest,
        )
        .unwrap()
    }

    fn cut(spec: &SystemSpecV1) -> PublishedScopeCutV1 {
        let cut_id = CutId::new("home-netbox/1").unwrap();
        let system_id = SystemId::new("home-netbox").unwrap();
        let proposal = spec
            .compile_cut_proposal(cut_id.clone(), &system_id)
            .unwrap();
        spec.compile_cut(
            cut_id,
            &system_id,
            ratification(0x55, proposal.proposal_digest),
        )
        .unwrap()
    }

    fn all_selection() -> PorterProjectionSelectionV1 {
        PorterProjectionSelectionV1 {
            target_ids: vec![TargetId::new("sushi-k").unwrap()],
            component_ids: ["netbox-web", "netbox-worker", "postgres", "redis"]
                .into_iter()
                .map(|id| ComponentId::new(id).unwrap())
                .collect(),
        }
    }

    #[test]
    fn compiling_a_cut_and_both_projections_is_deterministic_and_authority_free() {
        let spec = fixture();
        let first = cut(&spec);
        let mut reordered = spec.clone();
        reordered.source_snapshots.reverse();
        reordered.components.reverse();
        reordered.dependencies.reverse();
        reordered.observation_obligations.reverse();
        reordered.systems[0].component_ids.reverse();
        reordered.systems[0].dependency_ids.reverse();
        assert_eq!(spec.digest().unwrap(), reordered.digest().unwrap());
        assert_eq!(first.cut_digest, cut(&reordered).cut_digest);

        let observation = first
            .nq_observation_projection(ProjectionId::new("nq/home-netbox/1").unwrap())
            .unwrap();
        let actuation = first
            .porter_actuation_projection(
                ProjectionId::new("porter/home-netbox/1").unwrap(),
                &all_selection(),
            )
            .unwrap();
        observation.verify_against(&first).unwrap();
        actuation.verify_against(&first).unwrap();
        assert_eq!(
            observation.projection.scope_cut,
            actuation.projection.scope_cut
        );
        let value = serde_json::to_value(&actuation).unwrap();
        let body = value["projection"].as_object().unwrap();
        assert_eq!(body["authority"], "none");
        for forbidden in ["commands", "effects", "grant", "approved", "authorized"] {
            assert!(!body.contains_key(forbidden));
        }
    }

    #[test]
    fn changed_draft_creates_a_new_cut_without_refreshing_the_old_cut() {
        let spec = fixture();
        let old_cut = cut(&spec);
        let old_projection = old_cut
            .nq_observation_projection(ProjectionId::new("nq/home-netbox/1").unwrap())
            .unwrap();
        let mut changed = spec.clone();
        changed.targets[0].target_identity_digest = digest(0x99);
        changed.revision = 2;
        let cut_id = CutId::new("home-netbox/2").unwrap();
        let system_id = SystemId::new("home-netbox").unwrap();
        let proposal = changed
            .compile_cut_proposal(cut_id.clone(), &system_id)
            .unwrap();
        let new_cut = changed
            .compile_cut(
                cut_id,
                &system_id,
                ratification(0x56, proposal.proposal_digest),
            )
            .unwrap();
        assert_ne!(old_cut.cut_digest, new_cut.cut_digest);
        old_cut.verify().unwrap();
        old_cut.verify_against_spec(&spec).unwrap();
        assert!(new_cut.verify_against_spec(&spec).is_err());
        assert!(old_projection.verify_against(&new_cut).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn porter_projection_separates_actuation_from_affected_verification_scope() {
        let base_cut = cut(&fixture());
        let mut selection = all_selection();
        selection.component_ids = vec![ComponentId::new("netbox-web").unwrap()];
        let narrowed = base_cut
            .porter_actuation_projection(ProjectionId::new("porter/web-only").unwrap(), &selection)
            .unwrap();
        assert_eq!(narrowed.projection.actuation_components.len(), 1);
        assert_eq!(narrowed.projection.affected_components.len(), 1);
        assert_eq!(narrowed.projection.verification_obligations.len(), 1);
        assert_eq!(narrowed.projection.boundary_dependencies.len(), 2);

        let postgres = PorterProjectionSelectionV1 {
            target_ids: vec![TargetId::new("sushi-k").unwrap()],
            component_ids: vec![ComponentId::new("postgres").unwrap()],
        };
        let provider_change = base_cut
            .porter_actuation_projection(
                ProjectionId::new("porter/postgres-only").unwrap(),
                &postgres,
            )
            .unwrap();
        assert_eq!(provider_change.projection.actuation_components.len(), 1);
        let affected: Vec<_> = provider_change
            .projection
            .affected_components
            .iter()
            .map(|component| component.component_id.as_str())
            .collect();
        assert_eq!(affected, ["netbox-web", "netbox-worker", "postgres"]);
        assert_eq!(provider_change.projection.verification_obligations.len(), 3);

        selection
            .component_ids
            .push(ComponentId::new("outside").unwrap());
        assert!(
            base_cut
                .porter_actuation_projection(
                    ProjectionId::new("porter/escape").unwrap(),
                    &selection,
                )
                .is_err()
        );

        let mut extra_obligation_spec = fixture();
        extra_obligation_spec
            .observation_obligations
            .push(obligation(
                "observe-web-second",
                "netbox-web",
                "netbox-web-second-local",
            ));
        extra_obligation_spec.systems[0]
            .observation_obligation_ids
            .push(ObservationObligationId::new("observe-web-second").unwrap());
        let extra_obligation_cut = cut(&extra_obligation_spec);
        let automatic_obligations = extra_obligation_cut
            .porter_actuation_projection(
                ProjectionId::new("porter/all-obligations-derived").unwrap(),
                &all_selection(),
            )
            .unwrap();
        assert_eq!(
            automatic_obligations
                .projection
                .verification_obligations
                .len(),
            5
        );

        let mut second_target_spec = fixture();
        second_target_spec.targets.push(TargetV1 {
            target_id: TargetId::new("other-dev").unwrap(),
            target_class: TargetClass::new("persistent-dev").unwrap(),
            target_identity_digest: digest(0xbc),
            source_snapshot_ids: vec![SourceSnapshotId::new("bootstrap-sushi-k").unwrap()],
        });
        second_target_spec.components.push(ComponentV1 {
            component_id: ComponentId::new("other-component").unwrap(),
            kind: ComponentKind::new("fixture").unwrap(),
            hosted_on: TargetId::new("other-dev").unwrap(),
            source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
        });
        second_target_spec.observation_obligations.push(obligation(
            "observe-other",
            "other-component",
            "other-component-local",
        ));
        second_target_spec.systems[0]
            .target_ids
            .push(TargetId::new("other-dev").unwrap());
        second_target_spec.systems[0]
            .component_ids
            .push(ComponentId::new("other-component").unwrap());
        second_target_spec.systems[0]
            .observation_obligation_ids
            .push(ObservationObligationId::new("observe-other").unwrap());
        let second_target_cut = cut(&second_target_spec);
        let mut expanded_targets = all_selection();
        expanded_targets
            .target_ids
            .push(TargetId::new("other-dev").unwrap());
        assert!(
            second_target_cut
                .porter_actuation_projection(
                    ProjectionId::new("porter/unused-target").unwrap(),
                    &expanded_targets,
                )
                .is_err()
        );
    }

    #[test]
    fn strict_boundary_rejects_duplicates_unknown_fields_and_authority_overclaim() {
        let spec = fixture();
        let bytes = canonical_document(&spec).unwrap();
        parse_system_spec(&bytes).unwrap();
        let duplicate = br#"{"schema":"nq.system_spec.v1","schema":"nq.system_spec.v1"}"#;
        assert!(matches!(
            parse_system_spec(duplicate),
            Err(ContractError::InvalidJson(message)) if message.contains("duplicate object key")
        ));

        let mut value = serde_json::to_value(spec).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("authorized".into(), serde_json::Value::Bool(true));
        assert!(parse_system_spec(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("authorized");
        value["authority"] = json!("granted");
        assert!(parse_system_spec(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut confusing = fixture();
        confusing.title = "safe-looking\u{202e}gnp.exe".into();
        assert!(matches!(
            confusing.validate(),
            Err(ContractError::InvalidText("spec title"))
        ));
    }

    #[test]
    fn document_cardinality_and_binding_byte_limits_fail_before_publication() {
        let oversized = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert!(matches!(
            parse_system_spec(&oversized),
            Err(ContractError::TooLarge {
                limit: MAX_DOCUMENT_BYTES,
                ..
            })
        ));

        let mut too_many_targets = fixture();
        too_many_targets
            .targets
            .resize(MAX_TARGETS + 1, too_many_targets.targets[0].clone());
        assert!(matches!(
            too_many_targets.validate(),
            Err(ContractError::Cardinality {
                kind: "targets",
                maximum: MAX_TARGETS,
                ..
            })
        ));

        let mut binding_escape = fixture();
        binding_escape.observation_obligations[0]
            .subject_binding
            .scope
            .value = json!({"value": "x".repeat(MAX_BINDING_VALUE_BYTES)});
        assert!(matches!(
            binding_escape.validate(),
            Err(ContractError::TooLarge {
                limit: MAX_BINDING_VALUE_BYTES,
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn publication_requires_exact_compiled_profile_and_ratified_proposal() {
        let mut spec = fixture();
        spec.observation_obligations[0].profile.digest = digest(0xee);
        assert!(matches!(
            spec.compile_cut_proposal(
                CutId::new("home-netbox/bad-profile").unwrap(),
                &SystemId::new("home-netbox").unwrap(),
            ),
            Err(ContractError::Profile(_))
        ));

        let spec = fixture();
        assert!(matches!(
            spec.compile_cut(
                CutId::new("home-netbox/unratified").unwrap(),
                &SystemId::new("home-netbox").unwrap(),
                ratification(0x66, digest(0xff)),
            ),
            Err(ContractError::RatificationProposalMismatch)
        ));

        let mut incomplete = fixture();
        incomplete.observation_obligations[0]
            .required_coverage
            .clear();
        assert!(incomplete.validate().is_err());

        let mut overclaimed = fixture();
        overclaimed.observation_obligations[0].required_coverage =
            vec![CoverageKind::new("invented_green").unwrap()];
        assert!(matches!(
            overclaimed.compile_cut_proposal(
                CutId::new("home-netbox/bad-coverage").unwrap(),
                &SystemId::new("home-netbox").unwrap(),
            ),
            Err(ContractError::Profile(_))
        ));

        let mut stale_expansion = fixture();
        stale_expansion.observation_obligations[0].freshness_seconds = 61;
        assert!(matches!(
            stale_expansion.compile_cut_proposal(
                CutId::new("home-netbox/freshness-expansion").unwrap(),
                &SystemId::new("home-netbox").unwrap(),
            ),
            Err(ContractError::Profile(_))
        ));

        let chronology_spec = fixture();
        let chronology_cut_id = CutId::new("home-netbox/bad-chronology").unwrap();
        let chronology_system_id = SystemId::new("home-netbox").unwrap();
        let chronology_proposal = chronology_spec
            .compile_cut_proposal(chronology_cut_id.clone(), &chronology_system_id)
            .unwrap();
        let early_ratification = RatificationV1::new(
            OperatorId::new("local:jbeck").unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 16, 11, 59, 59).unwrap(),
            chronology_proposal.proposal_digest,
        )
        .unwrap();
        assert!(matches!(
            chronology_spec.compile_cut(
                chronology_cut_id,
                &chronology_system_id,
                early_ratification,
            ),
            Err(ContractError::InvalidValue(
                "ratification time precedes a contributing source snapshot"
            ))
        ));

        let mut forged_record = cut(&fixture());
        forged_record.cut.ratification.ratified_by = OperatorId::new("local:other").unwrap();
        forged_record.cut_digest =
            versioned_artifact_digest(SCOPE_CUT_SCHEMA, &forged_record.cut).unwrap();
        assert!(matches!(
            forged_record.verify(),
            Err(ContractError::RatificationRecordMismatch)
        ));

        let mut unrelated = fixture();
        unrelated.components.push(ComponentV1 {
            component_id: ComponentId::new("future-component").unwrap(),
            kind: ComponentKind::new("future").unwrap(),
            hosted_on: TargetId::new("sushi-k").unwrap(),
            source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
        });
        let mut future_obligation = obligation(
            "observe-future",
            "future-component",
            "future-component-local",
        );
        future_obligation.profile.id = ProfileId::new("nq.future.uncompiled").unwrap();
        future_obligation.profile.digest = digest(0xab);
        unrelated.observation_obligations.push(future_obligation);
        unrelated.systems.push(SystemDefinitionV1 {
            system_id: SystemId::new("future-system").unwrap(),
            title: "Unrelated future system".into(),
            target_ids: vec![TargetId::new("sushi-k").unwrap()],
            component_ids: vec![ComponentId::new("future-component").unwrap()],
            dependency_ids: Vec::new(),
            observation_obligation_ids: vec![
                ObservationObligationId::new("observe-future").unwrap(),
            ],
            source_snapshot_ids: vec![SourceSnapshotId::new("authored-home-netbox").unwrap()],
        });
        unrelated
            .compile_cut_proposal(
                CutId::new("home-netbox/selected-only").unwrap(),
                &SystemId::new("home-netbox").unwrap(),
            )
            .expect("unrelated draft profiles do not qualify the selected closure");

        let mut historical = cut(&fixture());
        historical.cut.observation_obligations[0].profile.id =
            ProfileId::new("nq.retired.profile").unwrap();
        historical.cut.observation_obligations[0].profile.digest = digest(0xcd);
        let historical_proposal = ScopeCutProposalBodyV1 {
            cut_id: historical.cut.cut_id.clone(),
            source_spec: historical.cut.source_spec.clone(),
            system: historical.cut.system.clone(),
            source_snapshots: historical.cut.source_snapshots.clone(),
            targets: historical.cut.targets.clone(),
            components: historical.cut.components.clone(),
            dependencies: historical.cut.dependencies.clone(),
            observation_obligations: historical.cut.observation_obligations.clone(),
            authority: AuthoritySemantics::None,
        };
        let historical_proposal_digest =
            versioned_artifact_digest(SCOPE_CUT_PROPOSAL_SCHEMA, &historical_proposal).unwrap();
        historical.cut.ratification = RatificationV1::new(
            OperatorId::new("local:jbeck").unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 16, 14, 0, 0).unwrap(),
            historical_proposal_digest,
        )
        .unwrap();
        historical.cut_digest =
            versioned_artifact_digest(SCOPE_CUT_SCHEMA, &historical.cut).unwrap();
        historical
            .verify()
            .expect("historical immutable custody does not require a current profile");
        assert!(matches!(
            historical.qualify_with_compiled_profiles(),
            Err(ContractError::Profile(_))
        ));
    }

    #[test]
    fn unknown_cross_system_references_and_orphans_are_refused() {
        let mut spec = fixture();
        spec.systems[0].component_ids.pop();
        assert!(matches!(
            spec.validate(),
            Err(ContractError::ScopeEscape(_))
        ));

        let mut spec = fixture();
        spec.dependencies[1].consumer_component_id = ComponentId::new("outside").unwrap();
        assert!(matches!(
            spec.validate(),
            Err(ContractError::UnknownReference { .. })
        ));

        let mut spec = fixture();
        spec.dependencies.pop();
        assert!(matches!(
            spec.validate(),
            Err(ContractError::UnknownReference { .. })
        ));
    }

    #[test]
    fn embedded_digest_and_cut_order_are_verified() {
        let original = cut(&fixture());
        let bytes = canonical_document(&original).unwrap();
        assert_eq!(parse_scope_cut(&bytes).unwrap(), original);

        let mut changed = original.clone();
        changed.cut.targets[0].target_identity_digest = digest(0xaa);
        assert!(matches!(
            changed.verify(),
            Err(ContractError::DigestMismatch("scope cut"))
        ));

        let mut reordered = original;
        reordered.cut.components.reverse();
        let reordered_proposal = ScopeCutProposalBodyV1 {
            cut_id: reordered.cut.cut_id.clone(),
            source_spec: reordered.cut.source_spec.clone(),
            system: reordered.cut.system.clone(),
            source_snapshots: reordered.cut.source_snapshots.clone(),
            targets: reordered.cut.targets.clone(),
            components: reordered.cut.components.clone(),
            dependencies: reordered.cut.dependencies.clone(),
            observation_obligations: reordered.cut.observation_obligations.clone(),
            authority: AuthoritySemantics::None,
        };
        let reordered_proposal_digest =
            versioned_artifact_digest(SCOPE_CUT_PROPOSAL_SCHEMA, &reordered_proposal).unwrap();
        reordered.cut.ratification = RatificationV1::new(
            reordered.cut.ratification.ratified_by.clone(),
            reordered.cut.ratification.ratified_at,
            reordered_proposal_digest,
        )
        .unwrap();
        reordered.cut_digest = versioned_artifact_digest(SCOPE_CUT_SCHEMA, &reordered.cut).unwrap();
        assert!(matches!(
            reordered.verify(),
            Err(ContractError::NonCanonical("scope cut proposal arrays"))
        ));
    }
}
