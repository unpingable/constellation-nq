//! Compiled and versioned semantic profiles for NQ-ng.
//!
//! Runtime integrations remain mechanically open: a helper is an ordinary
//! process speaking `nq-protocol`. Semantic authority remains compiled here.
//! The registry is explicit and static; this crate performs no directory
//! scanning, dynamic loading, linker inventory, SQL rule execution, or runtime
//! predicate interpretation.

mod descriptor;
mod detector;
mod identity;
mod projection;
mod registry;
mod validation;

/// Conformance-only profile used by the language-neutral helper corpus.
pub mod conformance;
/// Local host operational profile.
pub mod host;

pub use descriptor::{
    CardinalityLimits, DescriptorError, FreshnessPolicy, PROFILE_DESCRIPTOR_SCHEMA,
    ProfileDescriptor, ProfileDigest, ProfileKey, SubjectRules, VocabularyTerm,
};
pub use detector::{
    DETECTOR_DESCRIPTOR_SCHEMA, Detector, DetectorDescriptor, DetectorEvidence, DetectorInput,
    DetectorReport, DetectorResult, DetectorRuleParameters, DetectorState, EvidenceWatermark,
};
pub use identity::{
    EVALUATOR_SOURCE_DIGEST, PROFILE_SEMANTIC_ID_SCHEMA, ProfileSemanticId, profile_semantic_id,
    profile_semantic_id_for_source,
};
pub use projection::{ProfileProjection, ProjectionResult};
pub use registry::{all_profiles, resolve_profile, resolve_profile_key};
pub use validation::{
    AdmittedObservation, CoverageInput, EvidenceBasis, ObservationInput, ProfileRefusal,
    ProfileRefusalCode, RefusalBoundary, ReportInput, ReportNormalizationError, ScopeGrant,
    SemanticCoverageState, SemanticReportStatus, ValidatedReport, ValidationContext,
    ValidationResult, VantageGrant,
};

/// Narrow object-safe contract implemented once by each compiled profile.
pub trait ProfileModule: Send + Sync {
    /// Canonical descriptor and controlled vocabularies.
    fn descriptor(&self) -> &'static ProfileDescriptor;

    /// Validates an NQ-owned subject, scope, vantage, and capability binding
    /// independently of any helper testimony.
    ///
    /// This is used while checking configuration so profile-specific
    /// correlation laws fail before admission or daemon startup.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ProfileRefusal`] from the compiled profile boundary
    /// when the configured binding is not one the profile can represent.
    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal>;

    /// Strictly validates a protocol-normalized report against an NQ binding.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ProfileRefusal`] from the exact failing boundary and
    /// responsible instance when the report is not admissible.
    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult;

    /// Produces typed, rebuildable projections only from admitted evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ProfileRefusal`] if an admitted payload cannot be
    /// recovered into the module's compiled projection type.
    fn project(&self, report: &ValidatedReport) -> ProjectionResult;

    /// Separately versioned detectors owned by this profile revision.
    fn detectors(&self) -> &'static [&'static dyn Detector];
}
