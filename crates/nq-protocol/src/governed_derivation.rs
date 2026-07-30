//! Shared semantic identity for one governed diagnostic derivation.
//!
//! Core constructs this identity when it derives a diagnostic. Store
//! independently recomputes the same identity from exact sealed custody before
//! publishing a projection. Keeping the canonical preimage here prevents two
//! security boundaries from drifting into merely similar algorithms.

use serde::Serialize;

use crate::{CanonicalizationError, Sha256Digest, semantic_digest};

/// Canonical schema for the governed derivation identity preimage.
pub const GOVERNED_DERIVATION_IDENTITY_SCHEMA: &str = "nq.governed_derivation_identity.v1";

/// One exact immutable record reference in the derivation identity.
///
/// This deliberately mirrors the language-neutral record-reference surface
/// without depending on a runtime or host-role crate.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct GovernedDerivationRecordRef<'a> {
    /// Exact target schema identity.
    pub schema: &'a str,
    /// Target record semantic identity.
    pub record_id: &'a Sha256Digest,
    /// Digest of the target's complete canonical bytes.
    pub bytes_digest: &'a Sha256Digest,
}

/// Complete verdict-affecting input to one governed derivation identity.
#[derive(Clone, Copy, Debug)]
pub struct GovernedDerivationIdentityInput<'a> {
    /// Self-identity of the exact canonical diagnostic.
    pub diagnostic_artifact_id: &'a Sha256Digest,
    /// Digest of the complete canonical diagnostic file bytes.
    pub diagnostic_file_bytes_digest: &'a Sha256Digest,
    /// Exact admitted provider occurrence.
    pub provider_intake: GovernedDerivationRecordRef<'a>,
    /// Exact authorized execution-launch occurrence.
    pub execution_launch: GovernedDerivationRecordRef<'a>,
    /// Authenticated dependency-generation identity.
    pub dependency_generation_id: &'a Sha256Digest,
    /// Digest of the complete dependency custody closure.
    pub dependency_generation_custody_digest: &'a Sha256Digest,
    /// Independently bound trust anchor for the dependency generation.
    pub trust_anchor_id: &'a Sha256Digest,
    /// Compiled profile semantics used for evaluation.
    pub profile_semantic_id: &'a Sha256Digest,
    /// Evaluator semantic identity retained by the diagnostic.
    pub evaluator_semantic_digest: &'a Sha256Digest,
    /// Exact evaluator executable artifact identity.
    pub evaluator_artifact_digest: &'a Sha256Digest,
    /// Exact diagnostic completion timestamp.
    pub derived_at: &'a str,
    /// Exact execution-clock identity.
    pub clock_identity: &'a Sha256Digest,
    /// Digest of the exact clock-qualification object.
    pub clock_qualification_digest: &'a Sha256Digest,
}

#[derive(Serialize)]
struct GovernedDerivationIdentityPreimage<'a> {
    schema: &'static str,
    diagnostic_artifact_id: &'a Sha256Digest,
    diagnostic_file_bytes_digest: &'a Sha256Digest,
    provider_intake: GovernedDerivationRecordRef<'a>,
    execution_launch: GovernedDerivationRecordRef<'a>,
    dependency_generation_id: &'a Sha256Digest,
    dependency_generation_custody_digest: &'a Sha256Digest,
    trust_anchor_id: &'a Sha256Digest,
    profile_semantic_id: &'a Sha256Digest,
    evaluator_semantic_digest: &'a Sha256Digest,
    evaluator_artifact_digest: &'a Sha256Digest,
    derived_at: &'a str,
    clock_identity: &'a Sha256Digest,
    clock_qualification_digest: &'a Sha256Digest,
}

/// Derive the exact canonical identity shared by Core and Store.
///
/// This function performs no admission, reliance, authorization, scheduling,
/// or execution. It only seals the identity of already-selected exact inputs.
///
/// # Errors
///
/// Returns a canonicalization error if the closed derivation preimage cannot
/// be encoded by the production canonical serializer.
pub fn governed_derivation_identity(
    input: &GovernedDerivationIdentityInput<'_>,
) -> Result<Sha256Digest, CanonicalizationError> {
    semantic_digest(&GovernedDerivationIdentityPreimage {
        schema: GOVERNED_DERIVATION_IDENTITY_SCHEMA,
        diagnostic_artifact_id: input.diagnostic_artifact_id,
        diagnostic_file_bytes_digest: input.diagnostic_file_bytes_digest,
        provider_intake: input.provider_intake,
        execution_launch: input.execution_launch,
        dependency_generation_id: input.dependency_generation_id,
        dependency_generation_custody_digest: input.dependency_generation_custody_digest,
        trust_anchor_id: input.trust_anchor_id,
        profile_semantic_id: input.profile_semantic_id,
        evaluator_semantic_digest: input.evaluator_semantic_digest,
        evaluator_artifact_digest: input.evaluator_artifact_digest,
        derived_at: input.derived_at,
        clock_identity: input.clock_identity,
        clock_qualification_digest: input.clock_qualification_digest,
    })
}
