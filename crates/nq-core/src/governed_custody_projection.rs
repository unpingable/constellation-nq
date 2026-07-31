//! Core-owned projection of one qualified governed V2 execution into Store carriers.
//!
//! This module is deliberately pure. It joins already-qualified runtime,
//! provider, derivation, and diagnostic artifacts into the exact opaque
//! carriers accepted by Store. It does not append records, seal physical
//! custody, assign diagnostic standing, grant reliance, authorize an
//! operation, or perform an effect.

use nq_host_role_contract::{RecordRef, RuntimeSchema};
use nq_host_role_runtime::{PreparedGovernedInvocation, QualifiedGovernedFinalBatch};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use nq_store::{
    CanonicalDocument, DiagnosticArtifactCommitInput, DiagnosticArtifactExecutionBindingInput,
    DiagnosticArtifactLocalOriginInput, DiagnosticArtifactProviderAttemptBindingInput,
    GovernedClosureAcquisitionInput, GovernedClosureCheckpointInput,
    GovernedClosureDependencyGenerationInput, GovernedClosureDerivationInput,
    GovernedClosureLocalOriginInput, GovernedClosurePrelaunchInput, GovernedClosureRecordReference,
    GovernedDerivationCustodyClaim, GovernedExecutionCustodyClosureV2,
    GovernedExecutionCustodyClosureV2Input, GovernedExecutionCustodyClosureV3,
    GovernedExecutionCustodyClosureV3Input, GovernedProjectionCapsule, RuntimeRecordInput,
    runtime_record_batch_digest,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    DIAGNOSTIC_EXECUTION_V2_SCHEMA, DiagnosticExecutionError, DiagnosticExecutionV2,
    governed_derivation::construct_governed_derivation_claim,
};

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";

/// Exact Store carriers for one already-qualified governed V2 occurrence.
///
/// These values remain inert until the caller separately seals the closure and
/// commits the diagnostic through Store's atomic projection APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedCustodyProjectionV2 {
    pub(crate) closure: GovernedExecutionCustodyClosureV2,
    pub(crate) diagnostic: DiagnosticArtifactCommitInput,
    closure_input: GovernedExecutionCustodyClosureV2Input,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedCustodyProjectionV3 {
    pub(crate) closure: GovernedExecutionCustodyClosureV3,
    pub(crate) diagnostic: DiagnosticArtifactCommitInput,
}

impl GovernedCustodyProjectionV2 {
    pub(crate) fn bind_projection_capsule(
        self,
        projection_capsule: GovernedProjectionCapsule,
        projection_capsule_capacity_bytes: u64,
    ) -> Result<GovernedCustodyProjectionV3> {
        let closure =
            GovernedExecutionCustodyClosureV3::build(GovernedExecutionCustodyClosureV3Input {
                v2: self.closure_input,
                projection_capsule,
                projection_capsule_capacity_bytes,
            })?;
        Ok(GovernedCustodyProjectionV3 {
            closure,
            diagnostic: self.diagnostic,
        })
    }
}

/// A refusal to establish exact correspondence among the governed V2 inputs.
///
/// This is projection failure, not an adverse diagnostic result.
#[derive(Debug, Error)]
pub(crate) enum GovernedCustodyProjectionError {
    /// The supplied diagnostic is not a canonical, contract-valid V2 artifact.
    #[error("governed custody projection diagnostic refused: {0}")]
    Diagnostic(#[from] DiagnosticExecutionError),
    /// Store's canonical carrier or closed storage-shape validation refused.
    #[error("governed custody projection storage carrier refused: {0}")]
    Store(#[from] nq_store::StoreError),
    /// Exact runtime, provider, derivation, or diagnostic identities did not join.
    #[error("governed custody projection correspondence refused: {0}")]
    Correspondence(String),
}

type Result<T> = std::result::Result<T, GovernedCustodyProjectionError>;

fn correspondence(detail: impl Into<String>) -> GovernedCustodyProjectionError {
    GovernedCustodyProjectionError::Correspondence(detail.into())
}

fn parse_digest(label: &str, value: &str) -> Result<Sha256Digest> {
    Sha256Digest::parse(value.to_owned())
        .map_err(|error| correspondence(format!("{label} is not a SHA-256 identity: {error}")))
}

fn closure_reference(reference: &RecordRef) -> GovernedClosureRecordReference {
    GovernedClosureRecordReference {
        schema: reference.schema.as_str().to_owned(),
        record_id: reference.record_id.clone(),
        bytes_digest: reference.bytes_digest.clone(),
    }
}

fn checkpoint_input(
    label: &str,
    checkpoint: &nq_store::RuntimeLedgerCheckpoint,
    records: &[RecordRef],
) -> Result<GovernedClosureCheckpointInput> {
    let checkpoint_id = parse_digest(label, &checkpoint.checkpoint_id)?;
    let record_count = u64::try_from(records.len())
        .map_err(|_| correspondence(format!("{label} membership length overflowed u64")))?;
    if checkpoint.record_count != record_count {
        return Err(correspondence(format!(
            "{label} declares {} records but carries {record_count} exact references",
            checkpoint.record_count
        )));
    }
    Ok(GovernedClosureCheckpointInput {
        checkpoint_id,
        batch_digest: checkpoint.batch_digest.clone(),
        runtime_records: records.iter().map(closure_reference).collect(),
    })
}

fn runtime_record_reference(record: &RuntimeRecordInput) -> Result<RecordRef> {
    Ok(RecordRef {
        schema: nq_host_role_contract::Token::parse(record.record_schema.clone()).map_err(
            |error| {
                correspondence(format!(
                    "terminal runtime record schema is not a contract token: {error}"
                ))
            },
        )?,
        record_id: parse_digest("terminal runtime record identity", &record.record_id)?,
        bytes_digest: parse_digest(
            "terminal runtime record canonical bytes",
            record.canonical_bytes.digest(),
        )?,
    })
}

fn exact_batch_record<'a>(
    qualified: &'a QualifiedGovernedFinalBatch,
    expected: &RecordRef,
) -> Result<&'a RuntimeRecordInput> {
    let matches = qualified
        .batch()
        .records
        .iter()
        .filter_map(|record| {
            runtime_record_reference(record)
                .ok()
                .filter(|reference| reference == expected)
                .map(|_| record)
        })
        .collect::<Vec<_>>();
    let [record] = matches.as_slice() else {
        return Err(correspondence(format!(
            "terminal batch contains {} exact instances of {} {} rather than one",
            matches.len(),
            expected.schema.as_str(),
            expected.record_id
        )));
    };
    Ok(*record)
}

fn exact_json_string<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| correspondence(format!("{label} lacks string field {field}")))
}

fn expected_native_provider_request_id(prepared: &PreparedGovernedInvocation) -> Result<String> {
    let digest = semantic_digest(&serde_json::json!({
        "schema": "nq.governed_native_child_request.v1",
        "outer_request_id": prepared.request_id(),
        "execution_launch": prepared.execution_launch(),
    }))
    .map_err(|error| {
        correspondence(format!(
            "native provider request identity cannot be reproduced: {error}"
        ))
    })?;
    let suffix = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        correspondence("native provider request digest lacks its algorithm qualifier")
    })?;
    let child = format!("nq-provider-{suffix}");
    if child == prepared.request_id() {
        return Err(correspondence(
            "native provider request identity collapsed into the outer diagnostic request",
        ));
    }
    Ok(child)
}

fn require_provider_correspondence(
    record: &RuntimeRecordInput,
    provider_intake: &RecordRef,
    intake_id: &str,
    raw_provider_bytes_digest: &Sha256Digest,
    prepared: &PreparedGovernedInvocation,
    diagnostic: &DiagnosticExecutionV2,
    derivation: &GovernedDerivationCustodyClaim,
) -> Result<()> {
    if provider_intake.schema.as_str() != PROVIDER_INTAKE_SCHEMA
        || record.record_schema != PROVIDER_INTAKE_SCHEMA
    {
        return Err(correspondence(
            "provider occurrence is not nq.provider_intake.v1",
        ));
    }
    let value: Value = serde_json::from_slice(record.canonical_bytes.as_bytes())
        .map_err(|error| correspondence(format!("provider intake is not JSON: {error}")))?;
    let provider = value
        .get("provider")
        .and_then(Value::as_object)
        .ok_or_else(|| correspondence("provider intake lacks typed provider identity"))?;
    let expected_provider_request_id = expected_native_provider_request_id(prepared)?;
    if exact_json_string(&value, "schema", "provider intake")? != PROVIDER_INTAKE_SCHEMA
        || exact_json_string(&value, "intake_id", "provider intake")? != intake_id
        || exact_json_string(&value, "run_id", "provider intake")? != diagnostic.run_id.as_str()
        || exact_json_string(&value, "request_id", "provider intake")?
            != expected_provider_request_id
        || exact_json_string(&value, "raw_sha256", "provider intake")?
            != raw_provider_bytes_digest.as_str()
        || provider.get("profile_semantic_id").and_then(Value::as_str)
            != Some(derivation.profile_semantic_id.as_str())
        || provider
            .get("evaluator_artifact_digest")
            .and_then(Value::as_str)
            != Some(derivation.evaluator_artifact_digest.as_str())
    {
        return Err(correspondence(
            "provider intake schema, occurrence, raw bytes, profile, or evaluator artifact differs",
        ));
    }
    Ok(())
}

fn require_binding_correspondence(
    record: &RuntimeRecordInput,
    prepared: &PreparedGovernedInvocation,
    provider_intake: &RecordRef,
    diagnostic: &DiagnosticExecutionV2,
    diagnostic_bytes_digest: &Sha256Digest,
) -> Result<()> {
    if record.record_schema != RuntimeSchema::ExecutionIdentityBindingV2.as_str() {
        return Err(correspondence(
            "execution binding is not nq.execution_identity_binding.v2",
        ));
    }
    let value: Value = serde_json::from_slice(record.canonical_bytes.as_bytes())
        .map_err(|error| correspondence(format!("execution binding is not JSON: {error}")))?;
    let diagnostic_binding = value
        .get("diagnostic")
        .and_then(Value::as_object)
        .ok_or_else(|| correspondence("execution binding lacks diagnostic object"))?;
    if diagnostic_binding.get("schema").and_then(Value::as_str)
        != Some(DIAGNOSTIC_EXECUTION_V2_SCHEMA)
        || diagnostic_binding
            .get("artifact_id")
            .and_then(Value::as_str)
            != Some(diagnostic.artifact_id.as_digest().as_str())
        || diagnostic_binding
            .get("file_bytes_digest")
            .and_then(Value::as_str)
            != Some(diagnostic_bytes_digest.as_str())
        || diagnostic_binding.get("request_id").and_then(Value::as_str)
            != Some(diagnostic.request_id.as_str())
    {
        return Err(correspondence(
            "execution binding diagnostic identity or exact-byte digest differs",
        ));
    }

    for (field, expected) in [
        ("outer_request", prepared.outer_request()),
        ("invocation_decision", prepared.invocation_decision()),
        ("execution_launch", prepared.execution_launch()),
    ] {
        let actual = value
            .get(field)
            .ok_or_else(|| correspondence(format!("execution binding lacks {field}")))?;
        let expected = serde_json::to_value(expected).map_err(|error| {
            correspondence(format!(
                "exact {field} reference cannot be encoded: {error}"
            ))
        })?;
        if actual != &expected {
            return Err(correspondence(format!(
                "execution binding substituted exact {field}"
            )));
        }
    }

    let attempts = value
        .get("provider_attempts")
        .and_then(Value::as_array)
        .ok_or_else(|| correspondence("execution binding lacks provider_attempts array"))?;
    let expected_provider = serde_json::to_value(provider_intake).map_err(|error| {
        correspondence(format!(
            "exact provider-intake reference cannot be encoded: {error}"
        ))
    })?;
    if attempts.as_slice() != [expected_provider] {
        return Err(correspondence(
            "execution binding does not select exactly the supplied provider intake",
        ));
    }
    Ok(())
}

fn require_derivation_correspondence(
    prepared: &PreparedGovernedInvocation,
    diagnostic: &DiagnosticExecutionV2,
    provider_intake: &RecordRef,
    claim: &GovernedDerivationCustodyClaim,
    completed_at: &str,
) -> Result<()> {
    let reservation = prepared.custody_reservation_spec();
    if diagnostic.request_id.as_str() != prepared.request_id()
        || diagnostic.producer.node_id != prepared.production_identity().node().id.as_str()
        || diagnostic.subject.id != prepared.production_identity().subject().id.as_str()
        || diagnostic.vantage.id != prepared.production_identity().vantage().id.as_str()
        || diagnostic.producer.cohort.id != prepared.production_identity().cohort().id.as_str()
    {
        return Err(correspondence(
            "diagnostic request or production identity differs from the prepared occurrence",
        ));
    }
    if claim.dependency_generation_id != *prepared.dependencies().generation_id()
        || claim.dependency_generation_id != reservation.dependency_generation_id
        || claim.dependency_generation_custody_digest
            != reservation.dependency_generation_custody_digest
        || claim.trust_anchor_id != reservation.trust_anchor_id
        || claim.evaluation_id.is_some()
        || claim.profile_semantic_id != diagnostic.profile_semantic_id
        || claim.evaluator_identity_digest != diagnostic.evaluator.digest
        || claim.derived_at != completed_at
        || claim.clock_identity != diagnostic.execution_clock.digest
    {
        return Err(correspondence(
            "derivation claim differs from the prepared generation or exact diagnostic semantics",
        ));
    }
    if sha256_bytes(prepared.dependency_custody_bytes())
        != claim.dependency_generation_custody_digest
    {
        return Err(correspondence(
            "prepared dependency custody bytes differ from the derivation claim",
        ));
    }
    let expected = construct_governed_derivation_claim(
        diagnostic,
        provider_intake,
        prepared.execution_launch(),
        prepared.dependencies(),
        &claim.evaluator_artifact_digest,
    )
    .map_err(|error| {
        correspondence(format!(
            "core derivation identity could not be reconstructed: {error}"
        ))
    })?;
    if &expected != claim {
        return Err(correspondence(
            "derivation claim is not the exact core-derived occurrence",
        ));
    }
    Ok(())
}

fn require_qualified_batch_correspondence(
    prepared: &PreparedGovernedInvocation,
    qualified: &QualifiedGovernedFinalBatch,
    provider_intake: &RecordRef,
) -> Result<()> {
    if qualified.provider_intake() != provider_intake {
        return Err(correspondence(
            "supplied provider intake differs from the qualified terminal batch",
        ));
    }
    if *qualified.runtime_records()
        != [
            qualified.provider_intake().clone(),
            qualified.execution_binding().clone(),
        ]
        || qualified.batch().records.len() != 2
    {
        return Err(correspondence(
            "qualified terminal membership is not exactly provider intake then execution binding",
        ));
    }
    let actual_records = qualified
        .batch()
        .records
        .iter()
        .map(runtime_record_reference)
        .collect::<Result<Vec<_>>>()?;
    if actual_records.as_slice() != qualified.runtime_records() {
        return Err(correspondence(
            "terminal batch bytes differ from its qualified ordered membership",
        ));
    }
    if qualified
        .batch()
        .expected_predecessor_checkpoint_id
        .as_deref()
        != Some(prepared.launch_checkpoint().checkpoint_id.as_str())
        || qualified.batch().expected_predecessor_ledger_root.as_ref()
            != Some(&prepared.launch_checkpoint().checkpoint_ledger_root)
        || qualified.batch().dependency.dependency_generation_id
            != *prepared.dependencies().generation_id()
        || qualified.batch().dependency.trust_anchor_id
            != prepared.custody_reservation_spec().trust_anchor_id
        || qualified.batch().dependency.canonical_custody.as_bytes()
            != prepared.dependency_custody_bytes()
    {
        return Err(correspondence(
            "terminal batch predecessor or dependency generation differs from the prepared launch",
        ));
    }
    if runtime_record_batch_digest(qualified.batch())? != *qualified.batch_digest() {
        return Err(correspondence(
            "qualified terminal batch digest does not match its exact bytes",
        ));
    }
    Ok(())
}

/// Build the exact Store custody closure and local diagnostic commitment for
/// one already-qualified governed V2 occurrence.
///
/// The caller must have separately acquired and retained the raw provider
/// bytes whose digest is supplied here, claimed the exact derivation, and
/// obtained `qualified` from `PreparedGovernedInvocation::qualify_final_batch`.
/// This function checks all joins available from those immutable carriers and
/// emits no side effects.
///
/// # Errors
///
/// Refuses noncanonical diagnostics, substitutions across any exact reference,
/// checkpoint or dependency mismatch, a diagnostic exceeding its pre-effect
/// bound, provider/diagnostic mismatch, derivation mismatch, or a Store
/// closure-shape violation.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn construct_governed_custody_projection_v2(
    prepared: &PreparedGovernedInvocation,
    qualified: &QualifiedGovernedFinalBatch,
    diagnostic: &DiagnosticExecutionV2,
    provider_intake: &RecordRef,
    intake_id: &str,
    raw_provider_bytes_digest: &Sha256Digest,
    derivation: &GovernedDerivationCustodyClaim,
) -> Result<GovernedCustodyProjectionV2> {
    let diagnostic_bytes = diagnostic.canonical_bytes()?;
    let diagnostic_length = u64::try_from(diagnostic_bytes.len())
        .map_err(|_| correspondence("diagnostic canonical length overflowed u64"))?;
    if diagnostic_length > prepared.diagnostic_artifact_capacity_bytes() {
        return Err(correspondence(format!(
            "diagnostic requires {diagnostic_length} bytes but the exact pre-effect bound is {}",
            prepared.diagnostic_artifact_capacity_bytes()
        )));
    }
    let diagnostic_bytes_digest = sha256_bytes(&diagnostic_bytes);
    let diagnostic_document = CanonicalDocument::from_canonical_bytes(diagnostic_bytes)?;
    let diagnostic_value: Value = serde_json::from_slice(diagnostic_document.as_bytes())
        .map_err(|error| correspondence(format!("canonical diagnostic is not JSON: {error}")))?;
    let completed_at =
        exact_json_string(&diagnostic_value, "completed_at", "diagnostic execution")?.to_owned();

    require_qualified_batch_correspondence(prepared, qualified, provider_intake)?;
    require_derivation_correspondence(
        prepared,
        diagnostic,
        provider_intake,
        derivation,
        &completed_at,
    )?;

    let provider_record = exact_batch_record(qualified, provider_intake)?;
    require_provider_correspondence(
        provider_record,
        provider_intake,
        intake_id,
        raw_provider_bytes_digest,
        prepared,
        diagnostic,
        derivation,
    )?;
    let binding_record = exact_batch_record(qualified, qualified.execution_binding())?;
    require_binding_correspondence(
        binding_record,
        prepared,
        provider_intake,
        diagnostic,
        &diagnostic_bytes_digest,
    )?;

    let reservation = prepared.custody_reservation_spec();
    if reservation.reservation_record_id != prepared.custody_reservation().record_id
        || reservation.reservation_manifest_digest != prepared.custody_reservation().bytes_digest
        || reservation.outer_request_record_id != prepared.outer_request().record_id
        || reservation.outer_request_digest != prepared.outer_request().bytes_digest
        || reservation.prelaunch_checkpoint_id
            != parse_digest(
                "reservation checkpoint identity",
                &prepared.reservation_checkpoint().checkpoint_id,
            )?
        || reservation.prelaunch_checkpoint_digest != prepared.reservation_checkpoint().batch_digest
    {
        return Err(correspondence(
            "custody reservation specification differs from exact prepared records or checkpoint",
        ));
    }

    let prelaunch = GovernedClosurePrelaunchInput {
        outer_request: closure_reference(prepared.outer_request()),
        invocation_decision: closure_reference(prepared.invocation_decision()),
        reservation_checkpoint: checkpoint_input(
            "reservation checkpoint",
            prepared.reservation_checkpoint(),
            prepared.reservation_checkpoint_records(),
        )?,
        launch_checkpoint: checkpoint_input(
            "launch checkpoint",
            prepared.launch_checkpoint(),
            prepared.launch_checkpoint_records(),
        )?,
    };
    let local_origin = GovernedClosureLocalOriginInput {
        run_id: diagnostic.run_id.as_str().to_owned(),
        evaluation_id: None,
        completed_at: completed_at.clone(),
    };
    let final_checkpoint_id = parse_digest(
        "terminal checkpoint identity",
        &qualified.batch().checkpoint_id,
    )?;
    let dependency_generation = GovernedClosureDependencyGenerationInput {
        checkpoint_id: final_checkpoint_id,
        checkpoint_digest: qualified.batch_digest().clone(),
        generation_id: derivation.dependency_generation_id.clone(),
        trust_anchor_id: derivation.trust_anchor_id.clone(),
        custody_bytes_digest: derivation.dependency_generation_custody_digest.clone(),
    };
    let closure_input = GovernedExecutionCustodyClosureV2Input {
        reservation: closure_reference(prepared.custody_reservation()),
        prelaunch,
        acquisition: GovernedClosureAcquisitionInput {
            execution_launch_record_id: prepared.execution_launch().record_id.clone(),
            provider_intake: closure_reference(provider_intake),
            intake_id: intake_id.to_owned(),
            raw_provider_bytes_digest: raw_provider_bytes_digest.clone(),
        },
        derivation: GovernedClosureDerivationInput {
            derivation_id: derivation.derivation_id.clone(),
            dependency_generation_id: derivation.dependency_generation_id.clone(),
            dependency_generation_custody_digest: derivation
                .dependency_generation_custody_digest
                .clone(),
            trust_anchor_id: derivation.trust_anchor_id.clone(),
            evaluation_id: None,
            profile_semantic_id: derivation.profile_semantic_id.clone(),
            evaluator_semantic_digest: derivation.evaluator_identity_digest.clone(),
            evaluator_artifact_digest: derivation.evaluator_artifact_digest.clone(),
            derived_at: completed_at.clone(),
            clock_identity: derivation.clock_identity.clone(),
            clock_qualification_digest: derivation.clock_qualification_digest.clone(),
        },
        diagnostic: diagnostic_document.clone(),
        diagnostic_artifact_capacity_bytes: prepared.diagnostic_artifact_capacity_bytes(),
        local_origin: local_origin.clone(),
        execution_binding: closure_reference(qualified.execution_binding()),
        runtime_records: qualified
            .runtime_records()
            .iter()
            .map(closure_reference)
            .collect(),
        dependency_generation,
    };
    let closure = GovernedExecutionCustodyClosureV2::build(closure_input.clone())?;
    let closure_length = u64::try_from(closure.canonical_bytes().as_bytes().len())
        .map_err(|_| correspondence("final custody closure length overflowed u64"))?;
    if closure_length > reservation.final_capacity_bytes {
        return Err(correspondence(format!(
            "final custody closure requires {closure_length} bytes but the exact pre-effect bound is {}",
            reservation.final_capacity_bytes
        )));
    }

    let diagnostic_commit = DiagnosticArtifactCommitInput {
        artifact_id: diagnostic.artifact_id.as_digest().clone(),
        contract_schema: DIAGNOSTIC_EXECUTION_V2_SCHEMA.to_owned(),
        canonical_bytes: diagnostic_document,
        local_origin: DiagnosticArtifactLocalOriginInput {
            run_id: local_origin.run_id,
            evaluation_id: None,
            completed_at: local_origin.completed_at,
            execution_binding: Some(DiagnosticArtifactExecutionBindingInput {
                runtime_records: qualified.batch().clone(),
                execution_binding_record_id: qualified.execution_binding().record_id.to_string(),
                outer_request_record_id: prepared.outer_request().record_id.to_string(),
                invocation_decision_record_id: prepared.invocation_decision().record_id.to_string(),
                execution_launch_record_id: prepared.execution_launch().record_id.to_string(),
                outer_request_id: prepared.request_id().to_owned(),
                provider_attempts: vec![DiagnosticArtifactProviderAttemptBindingInput {
                    provider_attempt_record_id: provider_intake.record_id.to_string(),
                    intake_id: intake_id.to_owned(),
                }],
            }),
        },
    };

    Ok(GovernedCustodyProjectionV2 {
        closure,
        diagnostic: diagnostic_commit,
        closure_input,
    })
}
