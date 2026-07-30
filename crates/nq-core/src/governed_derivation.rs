//! Core-owned identity for one governed diagnostic derivation occurrence.
//!
//! The custody layer retains this claim but does not decide its identity.
//! This module derives that identity from the exact diagnostic, provider
//! occurrence, launch, and authenticated dependency generation. It grants no
//! reliance, authorization, recurrence, or execution authority.

use chrono::SecondsFormat;
use nq_host_role_contract::{RecordRef, RuntimeSchema};
use nq_host_role_runtime::RuntimeDependencies;
use nq_protocol::{
    GovernedDerivationIdentityInput, GovernedDerivationRecordRef, Sha256Digest,
    governed_derivation_identity, semantic_digest, sha256_bytes,
};
use nq_store::GovernedDerivationCustodyClaim;

use crate::{DiagnosticExecutionV2, engine::EngineError};

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";

fn correspondence(detail: impl Into<String>) -> EngineError {
    EngineError::Invariant(format!(
        "governed derivation identity cannot be established: {}",
        detail.into()
    ))
}

/// Construct the only derivation-custody claim accepted for one governed V2
/// occurrence.
///
/// Every semantic field comes from the already canonical diagnostic. The
/// provider, launch, dependency generation, and evaluator executable remain
/// distinct exact identities in the derivation preimage.
pub(crate) fn construct_governed_derivation_claim(
    diagnostic: &DiagnosticExecutionV2,
    provider_intake: &RecordRef,
    execution_launch: &RecordRef,
    dependencies: &RuntimeDependencies,
    evaluator_artifact_digest: &Sha256Digest,
) -> Result<GovernedDerivationCustodyClaim, EngineError> {
    if provider_intake.schema.as_str() != PROVIDER_INTAKE_SCHEMA {
        return Err(correspondence(format!(
            "provider occurrence uses schema {}",
            provider_intake.schema.as_str()
        )));
    }
    if execution_launch.schema.as_str() != RuntimeSchema::ExecutionLaunchV1.as_str() {
        return Err(correspondence(format!(
            "launch occurrence uses schema {}",
            execution_launch.schema.as_str()
        )));
    }

    let diagnostic_bytes = diagnostic
        .canonical_bytes()
        .map_err(|error| correspondence(error.to_string()))?;
    let diagnostic_file_bytes_digest = sha256_bytes(&diagnostic_bytes);
    let dependency_generation_id = dependencies.generation_id().clone();
    let dependency_generation_custody_digest = dependencies
        .custody()
        .custody_digest()
        .map_err(|error| correspondence(error.to_string()))?;
    let trust_anchor_id = dependencies
        .custody()
        .trust_anchor_id()
        .map_err(|error| correspondence(error.to_string()))?;
    let derived_at = diagnostic
        .completed_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let clock_qualification_digest = semantic_digest(&diagnostic.attempt_interval.qualification)
        .map_err(|error| correspondence(error.to_string()))?;

    let mut claim = GovernedDerivationCustodyClaim {
        derivation_id: sha256_bytes(b"governed-derivation-identity-unsealed"),
        dependency_generation_id,
        dependency_generation_custody_digest,
        trust_anchor_id,
        evaluation_id: None,
        profile_semantic_id: diagnostic.profile_semantic_id.clone(),
        evaluator_identity_digest: diagnostic.evaluator.digest.clone(),
        evaluator_artifact_digest: evaluator_artifact_digest.clone(),
        derived_at,
        clock_identity: diagnostic.execution_clock.digest.clone(),
        clock_qualification_digest,
    };
    claim.derivation_id = governed_derivation_identity(&GovernedDerivationIdentityInput {
        diagnostic_artifact_id: diagnostic.artifact_id.as_digest(),
        diagnostic_file_bytes_digest: &diagnostic_file_bytes_digest,
        provider_intake: GovernedDerivationRecordRef {
            schema: provider_intake.schema.as_str(),
            record_id: &provider_intake.record_id,
            bytes_digest: &provider_intake.bytes_digest,
        },
        execution_launch: GovernedDerivationRecordRef {
            schema: execution_launch.schema.as_str(),
            record_id: &execution_launch.record_id,
            bytes_digest: &execution_launch.bytes_digest,
        },
        dependency_generation_id: &claim.dependency_generation_id,
        dependency_generation_custody_digest: &claim.dependency_generation_custody_digest,
        trust_anchor_id: &claim.trust_anchor_id,
        profile_semantic_id: &claim.profile_semantic_id,
        evaluator_semantic_digest: &claim.evaluator_identity_digest,
        evaluator_artifact_digest: &claim.evaluator_artifact_digest,
        derived_at: &claim.derived_at,
        clock_identity: &claim.clock_identity,
        clock_qualification_digest: &claim.clock_qualification_digest,
    })
    .map_err(|error| correspondence(error.to_string()))?;
    Ok(claim)
}
