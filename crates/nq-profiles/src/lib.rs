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
mod operator_beta_subject;
mod projection;
mod registry;
mod validation;

/// Closed repository-state factual evaluation and replay contract.
pub mod repository_state;

/// Conformance-only profile used by the language-neutral helper corpus.
pub mod conformance;
/// Local host operational profile.
pub mod host;
/// Controller-vantage bounded HTTP endpoint profile.
pub mod http_endpoint;
/// Retained Docket-bound synthetic-cache executor result profile.
pub mod synthetic_cache_executor_result;
/// Target-local systemd unit profile.
pub mod systemd_unit;

pub use descriptor::{
    CardinalityLimits, DescriptorError, FreshnessPolicy, PROFILE_DESCRIPTOR_SCHEMA,
    ProfileDescriptor, ProfileDigest, ProfileKey, SubjectRules, VocabularyTerm,
};
pub use detector::{
    DETECTOR_DESCRIPTOR_SCHEMA, Detector, DetectorDescriptor, DetectorEvidence, DetectorInput,
    DetectorReport, DetectorResult, DetectorRuleParameters, DetectorState, EvidenceWatermark,
    ThresholdPolicyInput,
};
pub use identity::{
    EVALUATOR_SOURCE_DIGEST, PROFILE_SEMANTIC_ID_SCHEMA, ProfileSemanticId, profile_semantic_id,
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

    /// Validates an optional immutable external verdict policy against this exact
    /// profile binding before admission or evaluation.
    ///
    /// Profiles without an external policy surface accept only absence.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the policy is missing, unexpected, or invalid.
    fn validate_threshold_policy(
        &self,
        context: &ValidationContext,
        policy: Option<&ThresholdPolicyInput>,
    ) -> Result<(), ProfileRefusal> {
        if policy.is_none() {
            return Ok(());
        }
        Err(ProfileRefusal::new(
            context,
            self.descriptor(),
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            "this compiled profile does not accept an external threshold policy",
        ))
    }

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
