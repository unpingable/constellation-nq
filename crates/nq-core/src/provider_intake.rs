//! Versioned boundary between acquisition providers and NQ judgment.
//!
//! The runtime authorization object in this module is deliberately sealed. A
//! serializable provider identity is historical evidence; it is not sufficient
//! to authorize a provider. Only the engine can construct `VerifiedProvider`
//! after independently checking the active admission and the exact opened
//! executable identity.

use std::collections::BTreeSet;

use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use nq_profiles::ProfileSemanticId;
use nq_protocol::{HelperRequest, HelperResponse, Sha256Digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::admission::{
    AdmissionLock, AdmissionManager, AdmissionVerification, ConformanceReceipt,
};
use crate::config::ResourceLimits;
use crate::engine::{
    JsonErrorCategory, ProtocolCanonicalizationFailure, ProtocolRejection,
    ProtocolRejectionBoundary, ProtocolRejectionCode, ProtocolRejectionFailure,
    ProtocolValidationFailure, RunHardLimits, RunResourceOutcomeSchema, RunResourceOutcomeV1,
    StructuredJsonError, protocol_rejection,
};
use crate::identity::ExecutionIdentity;
use crate::runner::{AcquisitionOutcome, MAX_ACQUISITION_DETAIL_BYTES, RunCapture};

/// Exact schema of an independently derived provider identity record.
pub const PROVIDER_IDENTITY_SCHEMA: &str = "nq.provider_identity.v1";
/// Exact schema of a provider attempt submitted to NQ custody and judgment.
pub const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";
/// Exact schema of the NQ-owned context bound to a provider intake.
pub const PROVIDER_INTAKE_CONTEXT_SCHEMA: &str = "nq.provider_intake_context.v1";
/// Semantic contract implemented by the first, local-helper provider.
pub const LOCAL_HELPER_PROVIDER_SEMANTICS_SCHEMA: &str = nq_store::LOCAL_PROVIDER_SEMANTIC_SCHEMA;

const MAX_JCS_STRING_BYTES_PER_INPUT_BYTE: usize = 6;
const MAX_SAFE_JCS_INTEGER: u64 = 9_007_199_254_740_991;

/// Closed provider-identity schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderIdentitySchema {
    /// First provider identity record.
    #[serde(rename = "nq.provider_identity.v1")]
    V1,
}

/// Closed intake-record schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderIntakeSchema {
    /// First provider intake record.
    #[serde(rename = "nq.provider_intake.v1")]
    V1,
}

/// Closed NQ-owned intake-context schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderIntakeContextSchema {
    /// First exact provider intake context.
    #[serde(rename = "nq.provider_intake_context.v1")]
    V1,
}

/// Provider implementation family. This is intentionally not a plugin
/// registry; the only live producer is the existing NQ-controlled helper.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Descriptor-bound local helper over an admitted NQ helper protocol.
    LocalHelper,
}

/// Independently derived identity of the provider permitted to produce one
/// candidate intake. Deserializing this record never grants submission rights.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentityV1 {
    /// Closed identity schema.
    pub schema: ProviderIdentitySchema,
    /// Closed provider family.
    pub kind: ProviderKind,
    /// NQ-derived semantic identity of the provider contract.
    pub provider_semantic_id: Sha256Digest,
    /// Exact NQ-derived local-provider admission contract identity.
    pub provider_admission_id: Sha256Digest,
    /// Existing helper/instance admission from which NQ derived the distinct
    /// provider admission. This is not an individual report admission.
    pub source_admission_id: String,
    /// Digest of the complete active admission lock.
    pub binding_digest: Sha256Digest,
    /// Root executable artifact digest independently observed by NQ.
    pub artifact_digest: Sha256Digest,
    /// Digest of the complete descriptor-bound execution identity.
    pub execution_identity_digest: Sha256Digest,
    /// NQ-derived configured-instance identity.
    pub configuration_digest: Sha256Digest,
    /// Exact provider protocol identity.
    pub protocol_identity: String,
    /// Exact conformance corpus admitted for the provider.
    pub conformance_corpus_digest: Sha256Digest,
    /// Exact verifier implementation used for provider conformance.
    pub conformance_tool_version: String,
    /// Complete canonical provider-conformance evidence used by the shared
    /// store/core semantic-identity law.
    pub conformance: ConformanceReceipt,
    /// Compiled semantic identity under which candidate reports are judged.
    pub profile_semantic_id: Sha256Digest,
    /// Evaluator artifact identity ratified by the source admission context.
    /// This is not the identity of the `nq`/`nqd` front end transporting the
    /// intake; actual detector evaluations remain independently bound to it.
    pub evaluator_artifact_digest: Sha256Digest,
    /// Durable admission-context identity binding the judging mechanism.
    pub admission_context_digest: Sha256Digest,
}

/// Runtime proof that NQ, rather than a provider-supplied field, established a
/// provider identity. Private fields and the absence of `Deserialize` are
/// load-bearing: historical bytes cannot be promoted into live authority.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedProvider {
    identity: ProviderIdentityV1,
}

impl VerifiedProvider {
    /// Construct the local provider only from facts already independently
    /// checked by admission and retained-descriptor launch. The evaluator
    /// identity here is the source admission's durable judging identity, not
    /// the digest of whichever `nq` or `nqd` front end performs this intake.
    pub(crate) fn local_helper(
        lock: &AdmissionLock,
        verification: &AdmissionVerification,
        execution: &ExecutionIdentity,
        profile_semantic_id: &ProfileSemanticId,
        admission_evaluator_artifact_digest: Sha256Digest,
        admission_context_digest: &str,
        provider_admission: &nq_store::LocalProviderAdmissionRow,
    ) -> Result<Self, ProviderIntakeError> {
        if lock.execution != *execution {
            return Err(ProviderIntakeError::Identity(
                "opened execution differs from the verified admission lock".into(),
            ));
        }
        let binding_digest = digest("binding_digest", &verification.binding_digest)?;
        let artifact_digest = digest("artifact_digest", &execution.sha256)?;
        let configuration_digest = digest("configuration_digest", &lock.config_digest)?;
        let conformance_corpus_digest = digest(
            "conformance_corpus_digest",
            &lock.conformance.protocol_corpus_digest,
        )?;
        let profile_semantic_id = digest("profile_semantic_id", profile_semantic_id.as_str())?;
        let admission_context_digest =
            digest("admission_context_digest", admission_context_digest)?;
        let execution_identity_digest = nq_protocol::semantic_digest(execution)
            .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let provider_semantic_id = local_helper_semantic_id(lock)?;
        let provider_admission_document = nq_store::CanonicalDocument::from_canonical_bytes(
            provider_admission.contract_json.clone(),
        )
        .map_err(|error| ProviderIntakeError::Identity(error.to_string()))?;
        let provider_admission_id = digest(
            "provider_admission_id",
            &provider_admission.provider_admission_id,
        )?;
        if provider_admission.source_admission_id != lock.admission_id
            || provider_admission.provider_semantic_id != provider_semantic_id.as_str()
            || provider_admission.provider_artifact_digest != execution.sha256
            || provider_admission.provider_protocol_identity != lock.protocol_version
            || provider_admission.provider_config_digest != lock.config_digest
            || provider_admission.contract_digest != provider_admission.provider_admission_id
            || provider_admission_document.digest() != provider_admission.provider_admission_id
            || provider_admission.source_admitted_at
                != lock
                    .admitted_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
        {
            return Err(ProviderIntakeError::Identity(
                "derived local-provider admission differs from the verified helper admission"
                    .into(),
            ));
        }
        let identity = ProviderIdentityV1 {
            schema: ProviderIdentitySchema::V1,
            kind: ProviderKind::LocalHelper,
            provider_semantic_id,
            provider_admission_id,
            source_admission_id: lock.admission_id.clone(),
            binding_digest,
            artifact_digest,
            execution_identity_digest,
            configuration_digest,
            protocol_identity: lock.protocol_version.clone(),
            conformance_corpus_digest,
            conformance_tool_version: lock.conformance.tool_version.clone(),
            conformance: lock.conformance.clone(),
            profile_semantic_id,
            evaluator_artifact_digest: admission_evaluator_artifact_digest,
            admission_context_digest,
        };
        identity.verify_historical()?;
        Ok(Self { identity })
    }

    /// Inspect the historical identity record carried into an intake.
    pub(crate) fn identity(&self) -> &ProviderIdentityV1 {
        &self.identity
    }
}

impl ProviderIdentityV1 {
    /// Verify the internal identities of a historical provider record.
    ///
    /// This authenticates record consistency only. It does not establish a
    /// current provider admission or construct live provider authority.
    ///
    /// # Errors
    ///
    /// Returns when the schema, protocol, conformance projections, or derived
    /// provider semantic identity disagree.
    pub fn verify_historical(&self) -> Result<(), ProviderIntakeError> {
        if self.schema != ProviderIdentitySchema::V1
            || self.kind != ProviderKind::LocalHelper
            || self.source_admission_id.is_empty()
            || self.protocol_identity != nq_protocol::HELPER_PROTOCOL_VERSION
            || self.conformance_tool_version.is_empty()
            || self.conformance_tool_version != self.conformance.tool_version
            || self.conformance_corpus_digest.as_str() != self.conformance.protocol_corpus_digest
        {
            return Err(ProviderIntakeError::Identity(
                "provider identity has an unsupported schema, kind, admission, or protocol".into(),
            ));
        }
        let expected = local_helper_semantic_id_from_record(self)?;
        if self.provider_semantic_id != expected {
            return Err(ProviderIntakeError::Identity(
                "provider semantic identity does not match its exact contract preimage".into(),
            ));
        }
        Ok(())
    }
}

fn local_helper_semantic_id(lock: &AdmissionLock) -> Result<Sha256Digest, ProviderIntakeError> {
    let conformance = nq_store::CanonicalDocument::from_serializable(&lock.conformance)
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
    nq_store::local_provider_semantic_id(&lock.protocol_version, &conformance)
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))
}

fn local_helper_semantic_id_from_record(
    identity: &ProviderIdentityV1,
) -> Result<Sha256Digest, ProviderIntakeError> {
    let conformance = nq_store::CanonicalDocument::from_serializable(&identity.conformance)
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
    nq_store::local_provider_semantic_id(&identity.protocol_identity, &conformance)
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))
}

/// Exact NQ-owned context of one provider attempt, fixed before acquisition.
#[derive(Clone, Debug)]
pub(crate) struct ProviderAttempt {
    intake_id: String,
    attempt_id: String,
    run_id: String,
    request: HelperRequest,
    provider: VerifiedProvider,
    origin_carrier: String,
    deadline: ProviderAttemptDeadline,
    checkpoint_contract_digest: Sha256Digest,
}

/// Origin of the wall-clock deadline retained in one provider-intake artifact.
///
/// The legacy collection path begins its deadline when the runner starts. A
/// governed invocation has already fixed its absolute deadline before any
/// effect, so deriving another deadline from a later runner start would widen
/// the authorized occurrence window.
#[derive(Clone, Debug)]
enum ProviderAttemptDeadline {
    RelativeToCaptureStart { duration_ms: u64 },
    FixedAbsolute { deadline_at: DateTime<Utc> },
}

impl ProviderAttempt {
    /// Bind distinct attempt, run, and request identities before dispatch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        intake_id: String,
        attempt_id: String,
        run_id: String,
        request: HelperRequest,
        provider: VerifiedProvider,
        origin_carrier: String,
        deadline_ms: u64,
        checkpoint_contract_digest: &str,
    ) -> Result<Self, ProviderIntakeError> {
        if deadline_ms == 0 {
            return Err(ProviderIntakeError::Identity(
                "local provider relative deadline must be nonzero".into(),
            ));
        }
        Self::new_with_deadline(
            intake_id,
            attempt_id,
            run_id,
            request,
            provider,
            origin_carrier,
            ProviderAttemptDeadline::RelativeToCaptureStart {
                duration_ms: deadline_ms,
            },
            checkpoint_contract_digest,
        )
    }

    /// Bind a governed attempt to the absolute deadline fixed before effect.
    ///
    /// The runtime may and should recompute a shorter monotonic watchdog
    /// duration immediately before spawning the provider. That watchdog is an
    /// execution mechanism, not the artifact's deadline: a later start or
    /// recomputation must never move `deadline_at`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_governed(
        intake_id: String,
        attempt_id: String,
        run_id: String,
        request: HelperRequest,
        provider: VerifiedProvider,
        origin_carrier: String,
        absolute_deadline: DateTime<Utc>,
        checkpoint_contract_digest: &str,
    ) -> Result<Self, ProviderIntakeError> {
        Self::new_with_deadline(
            intake_id,
            attempt_id,
            run_id,
            request,
            provider,
            origin_carrier,
            ProviderAttemptDeadline::FixedAbsolute {
                deadline_at: absolute_deadline,
            },
            checkpoint_contract_digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_deadline(
        intake_id: String,
        attempt_id: String,
        run_id: String,
        request: HelperRequest,
        provider: VerifiedProvider,
        origin_carrier: String,
        deadline: ProviderAttemptDeadline,
        checkpoint_contract_digest: &str,
    ) -> Result<Self, ProviderIntakeError> {
        if intake_id.is_empty()
            || attempt_id.is_empty()
            || run_id.is_empty()
            || intake_id == attempt_id
            || intake_id == run_id
            || intake_id == request.request_id.as_str()
            || attempt_id == run_id
            || attempt_id == request.request_id.as_str()
            || run_id == request.request_id.as_str()
        {
            return Err(ProviderIntakeError::Identity(
                "attempt, watcher run, and request identities must be nonempty and distinct".into(),
            ));
        }
        if !matches!(origin_carrier.as_str(), "stdio" | "unix") {
            return Err(ProviderIntakeError::Identity(
                "local provider carrier must be exact and bounded".into(),
            ));
        }
        let checkpoint_contract_digest =
            digest("checkpoint_contract_digest", checkpoint_contract_digest)?;
        Ok(Self {
            intake_id,
            attempt_id,
            run_id,
            request,
            provider,
            origin_carrier,
            deadline,
            checkpoint_contract_digest,
        })
    }

    fn deadline_at(
        &self,
        capture_started_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, ProviderIntakeError> {
        match self.deadline {
            ProviderAttemptDeadline::RelativeToCaptureStart { duration_ms } => {
                let duration_ms = i64::try_from(duration_ms).unwrap_or(i64::MAX);
                capture_started_at
                    .checked_add_signed(chrono::Duration::milliseconds(duration_ms))
                    .ok_or_else(|| {
                        ProviderIntakeError::Invariant(
                            "provider relative deadline exceeds the representable UTC range".into(),
                        )
                    })
            }
            ProviderAttemptDeadline::FixedAbsolute { deadline_at } => Ok(deadline_at),
        }
    }
}

/// NQ's interpretation of provider bytes before profile admission.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
// The validated response is the normal live path. Boxing it would add an
// allocation to every successful intake solely to shrink the refusal variant.
#[allow(clippy::large_enum_variant)]
pub enum ProviderResponseInterpretationV1 {
    /// No complete protocol response was available for parsing.
    NotAvailable,
    /// NQ rejected the bytes at the exact protocol boundary.
    ProtocolRejected {
        /// Complete typed protocol rejection.
        rejection: ProtocolRejection,
    },
    /// A response passed framing, strict decoding, correlation, and common
    /// protocol checks. Its report or refusal is still pre-admission testimony.
    Validated {
        /// Exact parsed response; never a substitute for `raw_bytes`.
        response: HelperResponse,
    },
}

impl ProviderResponseInterpretationV1 {
    /// Stable coarse index used only for storage lookup. This never substitutes
    /// for the complete canonical interpretation document.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::NotAvailable => "unavailable",
            Self::ProtocolRejected { .. } => "protocol_rejected",
            Self::Validated {
                response:
                    HelperResponse {
                        outcome: nq_protocol::ResponseOutcome::Refusal { .. },
                        ..
                    },
            } => "provider_refusal",
            Self::Validated {
                response:
                    HelperResponse {
                        outcome: nq_protocol::ResponseOutcome::Report { .. },
                        ..
                    },
            } => "candidate_report",
        }
    }
}

/// Exact NQ-controlled request and judging context bound to an intake.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIntakeContextV1 {
    /// Closed context schema.
    pub schema: ProviderIntakeContextSchema,
    /// Stable identity of this exact intake artifact.
    pub intake_id: String,
    /// NQ-owned provider attempt and idempotency identity.
    pub attempt_id: String,
    /// Current local watcher-run subtype identity.
    pub run_id: String,
    /// Complete NQ-owned request, including subject, scope, vantage,
    /// capabilities, profile, checkpoint, deadline, and bounds.
    pub request: HelperRequest,
    /// Independently established provider identity.
    pub provider: ProviderIdentityV1,
    /// Exact current local-provider carrier. This is invocation context, not a
    /// provider assertion or a future remote transport contract.
    pub origin_carrier: String,
    /// NQ wall-clock deadline derived from the fixed pre-dispatch budget.
    pub deadline_at: DateTime<Utc>,
    /// Exact checkpoint portability namespace.
    pub checkpoint_contract_digest: Sha256Digest,
}

/// Serializable metadata for one provider intake. The separately retained raw
/// bytes are authenticated by `raw_sha256` and remain authoritative custody.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIntakeRecordV1 {
    /// Closed intake schema.
    pub schema: ProviderIntakeSchema,
    /// Stable identity of this exact intake artifact.
    pub intake_id: String,
    /// NQ-owned provider-attempt/idempotency identity.
    pub attempt_id: String,
    /// Application-level replay key derived from the NQ attempt and provider
    /// admission identities.
    pub idempotency_key: String,
    /// Current local watcher-run subtype identity.
    pub run_id: String,
    /// Exact request identity sent to the provider.
    pub request_id: String,
    /// Exact NQ-owned request and complete bound collection context.
    pub request: HelperRequest,
    /// Independently established provider identity.
    pub provider: ProviderIdentityV1,
    /// Exact local-provider invocation carrier.
    pub origin_carrier: String,
    /// NQ wall-clock deadline for this attempt.
    pub deadline_at: DateTime<Utc>,
    /// Digest of the exact complete request.
    pub request_digest: Sha256Digest,
    /// Digest binding request, provider, judging context, and checkpoint domain.
    pub context_digest: Sha256Digest,
    /// Exact checkpoint portability namespace.
    pub checkpoint_contract_digest: Sha256Digest,
    /// NQ wall-clock attempt start.
    pub started_at: DateTime<Utc>,
    /// NQ wall-clock attempt end.
    pub finished_at: DateTime<Utc>,
    /// NQ receive time for the captured provider bytes.
    pub received_at: DateTime<Utc>,
    /// Exact bounded native acquisition/resource outcome.
    pub native_outcome: RunResourceOutcomeV1,
    /// Number of exact raw provider bytes retained.
    pub raw_length: usize,
    /// Digest derived from the exact retained bytes.
    pub raw_sha256: Sha256Digest,
    /// Optional provider-local sequence. The local helper has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_sequence: Option<String>,
    /// NQ protocol interpretation, still before report admission.
    pub interpretation: ProviderResponseInterpretationV1,
}

impl ProviderIntakeRecordV1 {
    /// Reconstruct and verify the typed provider-intake carrier from one
    /// independently reopened store row and its separately retained raw bytes.
    ///
    /// This is the single production bridge from durable storage back to the
    /// typed request/provider/native-outcome interpretation. It verifies every
    /// duplicated projection before delegating to [`Self::verify_historical_raw`].
    /// It never grants current provider admission.
    ///
    /// # Errors
    ///
    /// Returns when typed decoding, any duplicated identity, raw custody, or
    /// raw-to-interpretation correspondence differs.
    #[allow(clippy::too_many_lines)] // One fail-closed audit of every durable projection is intentional.
    pub fn reopen_store_row(
        row: &nq_store::ProviderIntakeRow,
        raw_bytes: &[u8],
    ) -> Result<Self, ProviderIntakeError> {
        let context: ProviderIntakeContextV1 =
            serde_json::from_slice(&row.context_json).map_err(|error| {
                ProviderIntakeError::Invariant(format!(
                    "stored provider intake context is not typed v1: {error}"
                ))
            })?;
        let interpretation: ProviderResponseInterpretationV1 =
            serde_json::from_slice(&row.interpretation_json).map_err(|error| {
                ProviderIntakeError::Invariant(format!(
                    "stored provider interpretation is not typed v1: {error}"
                ))
            })?;
        let native_outcome: RunResourceOutcomeV1 = serde_json::from_slice(&row.native_outcome_json)
            .map_err(|error| {
                ProviderIntakeError::Invariant(format!(
                    "stored provider native outcome is not typed v1: {error}"
                ))
            })?;
        let parse_time = |field: &'static str, value: &str| {
            DateTime::parse_from_rfc3339(value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|error| {
                    ProviderIntakeError::Invariant(format!(
                        "stored provider {field} is not RFC3339: {error}"
                    ))
                })
        };
        let started_at = parse_time("start time", &row.started_at)?;
        let finished_at = parse_time("finish time", &row.finished_at)?;
        let received_at = parse_time("receive time", &row.received_at)?;
        let deadline_at = parse_time("deadline", &row.deadline_at)?;
        let provider = &context.provider;
        let request = &context.request;
        let source_capability_grant_document = nq_store::CanonicalDocument::from_canonical_bytes(
            row.source_capability_grant_json.clone(),
        )
        .map_err(|error| {
            ProviderIntakeError::Invariant(format!(
                "stored source provider capability grant is not canonical: {error}"
            ))
        })?;
        let source_capability_grant: BTreeSet<String> = serde_json::from_slice(
            source_capability_grant_document.as_bytes(),
        )
        .map_err(|error| {
            ProviderIntakeError::Invariant(format!(
                "stored source provider capability grant is not a string set: {error}"
            ))
        })?;
        let source_lock_document =
            nq_store::CanonicalDocument::from_canonical_bytes(row.source_lock_json.clone())
                .map_err(|error| {
                    ProviderIntakeError::Invariant(format!(
                        "stored source provider admission lock is not canonical: {error}"
                    ))
                })?;
        let source_lock: AdmissionLock = serde_json::from_slice(source_lock_document.as_bytes())
            .map_err(|error| {
                ProviderIntakeError::Invariant(format!(
                    "stored source provider admission lock is not typed: {error}"
                ))
            })?;
        let source_binding_digest =
            AdmissionManager
                .binding_digest(&source_lock)
                .map_err(|error| {
                    ProviderIntakeError::Invariant(format!(
                        "stored source provider admission lock is invalid: {error}"
                    ))
                })?;
        let source_lock_capability_grant =
            nq_store::CanonicalDocument::from_serializable(&source_lock.granted_capabilities)
                .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let source_execution_identity_digest = nq_protocol::semantic_digest(&source_lock.execution)
            .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let requested_capabilities = request
            .granted_capabilities
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let context_mismatches = [
            ("schema", context.schema != ProviderIntakeContextSchema::V1),
            ("intake_id", context.intake_id != row.intake_id),
            ("attempt_id", context.attempt_id != row.attempt_id),
            ("run_id", context.run_id != row.run_id),
            (
                "origin_carrier",
                context.origin_carrier != row.origin_carrier,
            ),
            ("deadline_at", context.deadline_at != deadline_at),
            (
                "checkpoint_contract_digest",
                context.checkpoint_contract_digest.as_str() != row.checkpoint_contract_digest,
            ),
            ("request_id", request.request_id.as_str() != row.request_id),
            (
                "instance_id",
                request.instance_id.as_str() != row.instance_id,
            ),
            ("profile_id", request.profile.id.as_str() != row.profile_id),
            (
                "profile_version",
                request.profile.version.as_str() != row.profile_version,
            ),
            (
                "profile_digest",
                request.profile.digest.as_str() != row.profile_digest,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        if !context_mismatches.is_empty() {
            return Err(ProviderIntakeError::Invariant(format!(
                "stored provider intake typed request/context disagrees with durable projections: {}",
                context_mismatches.join(", ")
            )));
        }
        if provider.provider_admission_id.as_str() != row.provider_admission_id
            || provider.source_admission_id != row.source_admission_id
            || provider.provider_semantic_id.as_str() != row.provider_semantic_id
            || provider.artifact_digest.as_str() != row.provider_artifact_digest
            || provider.execution_identity_digest.as_str() != row.execution_identity_digest
            || provider.configuration_digest.as_str() != row.provider_config_digest
            || provider.protocol_identity != row.provider_protocol_identity
            || provider.binding_digest.as_str() != row.binding_digest
            || provider.profile_semantic_id.as_str() != row.profile_semantic_id
            || provider.evaluator_artifact_digest.as_str() != row.evaluator_artifact_digest
            || provider.admission_context_digest.as_str() != row.admission_context_digest
        {
            return Err(ProviderIntakeError::Invariant(
                "stored provider identity disagrees with its durable projections".into(),
            ));
        }
        if requested_capabilities != source_capability_grant
            || request.granted_capabilities.len() != source_capability_grant.len()
            || source_lock.granted_capabilities != source_capability_grant
            || source_lock_capability_grant != source_capability_grant_document
            || source_lock.admission_id != row.source_admission_id
            || source_lock.instance_id != row.instance_id
            || source_lock.config_digest != row.provider_config_digest
            || source_lock.execution.sha256 != row.provider_artifact_digest
            || source_execution_identity_digest.as_str() != row.execution_identity_digest
            || source_lock.profile.id != row.profile_id
            || source_lock.profile.version.to_string() != row.profile_version
            || source_lock.profile.digest != row.profile_digest
            || source_lock.protocol_version != row.provider_protocol_identity
            || source_lock.conformance != provider.conformance
            || source_binding_digest != row.binding_digest
        {
            return Err(ProviderIntakeError::Invariant(
                "stored provider identity disagrees with its exact source admission lock".into(),
            ));
        }
        if row.acknowledgment.intake_id != row.intake_id
            || row.acknowledgment.attempt_id != row.attempt_id
            || row.acknowledgment.run_id != row.run_id
            || row.acknowledgment.provider_admission_id != row.provider_admission_id
            || row.acknowledgment.intake_digest != row.intake_digest
            || row.acknowledgment.raw_sha256 != row.raw_sha256
        {
            return Err(ProviderIntakeError::Invariant(
                "stored provider acknowledgment disagrees with its exact intake".into(),
            ));
        }
        if interpretation.kind() != row.interpretation_kind
            || crate::engine::acquisition_code(&native_outcome.outcome) != row.native_outcome_kind
        {
            return Err(ProviderIntakeError::Invariant(
                "stored provider outcome types disagree with their durable projections".into(),
            ));
        }
        let request_digest = nq_protocol::semantic_digest(request)
            .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let record = Self {
            schema: ProviderIntakeSchema::V1,
            intake_id: row.intake_id.clone(),
            attempt_id: row.attempt_id.clone(),
            idempotency_key: row.idempotency_key.clone(),
            run_id: row.run_id.clone(),
            request_id: row.request_id.clone(),
            request: request.clone(),
            provider: provider.clone(),
            origin_carrier: row.origin_carrier.clone(),
            deadline_at,
            request_digest,
            context_digest: digest("context_digest", &row.context_digest)?,
            checkpoint_contract_digest: digest(
                "checkpoint_contract_digest",
                &row.checkpoint_contract_digest,
            )?,
            started_at,
            finished_at,
            received_at,
            native_outcome,
            raw_length: raw_bytes.len(),
            raw_sha256: digest("raw_sha256", &row.raw_sha256)?,
            provider_sequence: row.provider_sequence.clone(),
            interpretation,
        };
        record.verify_historical_raw(raw_bytes)?;
        Ok(record)
    }

    /// Recompute every historical association that can be proved from this
    /// typed record and the separately retained exact raw bytes.
    ///
    /// This is a read-only integrity check. It never re-admits the provider,
    /// report, or evaluation and cannot manufacture live provider authority.
    ///
    /// # Errors
    ///
    /// Returns when an identity, digest, parse result, native outcome, raw
    /// length, or timestamp association was substituted.
    pub fn verify_historical_raw(&self, raw_bytes: &[u8]) -> Result<(), ProviderIntakeError> {
        ProviderIntakeV1 {
            record: self.clone(),
            raw_bytes: raw_bytes.to_vec(),
        }
        .validate()
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderIntakeCapacityBound {
    pub canonical_record_bytes: u64,
    pub raw_capture_bytes: u64,
    pub stderr_hex_bytes: u64,
    pub native_detail_bytes: u64,
    pub interpretation_bytes: u64,
}

fn capacity_error(detail: impl Into<String>) -> ProviderIntakeError {
    ProviderIntakeError::Capacity(detail.into())
}

fn checked_capacity_add(
    left: usize,
    right: usize,
    label: &str,
) -> Result<usize, ProviderIntakeError> {
    left.checked_add(right)
        .ok_or_else(|| capacity_error(format!("{label} addition overflowed")))
}

fn checked_capacity_multiply(
    left: usize,
    right: usize,
    label: &str,
) -> Result<usize, ProviderIntakeError> {
    left.checked_mul(right)
        .ok_or_else(|| capacity_error(format!("{label} multiplication overflowed")))
}

fn protocol_rejection_static_bound(
    responsible_instance_id: &str,
) -> Result<usize, ProviderIntakeError> {
    let structured = || StructuredJsonError {
        category: JsonErrorCategory::Data,
        line: usize::try_from(MAX_SAFE_JCS_INTEGER).unwrap_or(usize::MAX),
        column: usize::try_from(MAX_SAFE_JCS_INTEGER).unwrap_or(usize::MAX),
        diagnostic: String::new(),
    };
    let canonical_serialization = || ProtocolCanonicalizationFailure::Serialization {
        error: structured(),
    };
    let field = "report.observations[].observation_ordinal".to_owned();
    let maximum_count = usize::try_from(MAX_SAFE_JCS_INTEGER).unwrap_or(usize::MAX);
    let failures = vec![
        ProtocolRejectionFailure::FrameTooLarge {
            limit: maximum_count,
            actual: maximum_count,
        },
        ProtocolRejectionFailure::InvalidFraming,
        ProtocolRejectionFailure::InvalidJson {
            error: structured(),
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::InvalidSchema {
                document: "response".to_owned(),
                expected: nq_protocol::HELPER_RESPONSE_SCHEMA.to_owned(),
                actual: String::new(),
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::InvalidProtocolVersion {
                expected: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                actual: String::new(),
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::InvalidField {
                field: field.clone(),
                reason: String::new(),
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::BoundExceeded {
                field: field.clone(),
                limit: maximum_count,
                actual: maximum_count,
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::Duplicate {
                field: field.clone(),
                value: String::new(),
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::EchoMismatch {
                field: field.clone(),
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::CapabilityEscape {
                capability: nq_protocol::Capability::new("capacity-bound")
                    .expect("fixed capability is valid"),
            },
        },
        ProtocolRejectionFailure::Validation {
            error: ProtocolValidationFailure::Canonicalization {
                field,
                source: canonical_serialization(),
            },
        },
        ProtocolRejectionFailure::Canonicalization {
            error: canonical_serialization(),
        },
        ProtocolRejectionFailure::Canonicalization {
            error: ProtocolCanonicalizationFailure::UnsafeInteger {
                value: String::new(),
            },
        },
    ];
    failures
        .into_iter()
        .map(|failure| {
            nq_protocol::canonical_json_bytes(&ProviderResponseInterpretationV1::ProtocolRejected {
                rejection: ProtocolRejection {
                    responsible_instance_id: responsible_instance_id.to_owned(),
                    boundary: ProtocolRejectionBoundary::Response,
                    code: ProtocolRejectionCode::InvalidResponse,
                    failure,
                },
            })
            .map(|bytes| bytes.len())
            .map_err(|error| capacity_error(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lengths| lengths.into_iter().max().unwrap_or(0))
}

/// Compute a conservative pre-effect maximum for the exact canonical
/// `ProviderIntakeRecordV1` that this request/provider pair can produce.
///
/// The exact request and independently verified provider identity form the
/// fixed portion. The variable portion includes the full response bound, the
/// worst RFC 8785 string escaping of one raw-derived rejection field, the
/// runner's separately enforced dynamic-detail bound, and exact stderr hex
/// expansion. The raw response bytes themselves remain a separate custody
/// payload and are reported independently.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn provider_intake_capacity_bound(
    request: &HelperRequest,
    provider: &VerifiedProvider,
    limits: &ResourceLimits,
    intake_id: &str,
    attempt_id: &str,
    run_id: &str,
    origin_carrier: &str,
    checkpoint_contract_digest: &Sha256Digest,
) -> Result<ProviderIntakeCapacityBound, ProviderIntakeError> {
    if request.bounds.max_response_bytes as usize != limits.max_response_bytes {
        return Err(capacity_error(
            "request and runner response bounds do not correspond exactly",
        ));
    }

    let maximum_count = usize::try_from(MAX_SAFE_JCS_INTEGER).unwrap_or(usize::MAX);
    let digest = nq_protocol::sha256_bytes(b"provider-intake-capacity-bound");
    let idempotency_key = nq_store::provider_idempotency_key(
        provider.identity().provider_admission_id.as_str(),
        attempt_id,
    )
    .map_err(|error| capacity_error(error.to_string()))?;
    let maximum_time = DateTime::<Utc>::MAX_UTC;
    let unavailable = ProviderResponseInterpretationV1::NotAvailable;
    let specimen = ProviderIntakeRecordV1 {
        schema: ProviderIntakeSchema::V1,
        intake_id: intake_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        idempotency_key,
        run_id: run_id.to_owned(),
        request_id: request.request_id.to_string(),
        request: request.clone(),
        provider: provider.identity().clone(),
        origin_carrier: origin_carrier.to_owned(),
        deadline_at: maximum_time,
        request_digest: digest.clone(),
        context_digest: digest.clone(),
        checkpoint_contract_digest: checkpoint_contract_digest.clone(),
        started_at: maximum_time,
        finished_at: maximum_time,
        received_at: maximum_time,
        native_outcome: RunResourceOutcomeV1 {
            schema: RunResourceOutcomeSchema::V1,
            duration_ms: MAX_SAFE_JCS_INTEGER,
            exit_code: Some(i32::MIN),
            hard_limits: RunHardLimits {
                address_space_bytes_per_process: MAX_SAFE_JCS_INTEGER,
                cpu_seconds_per_process: MAX_SAFE_JCS_INTEGER,
                processes_per_execution_uid: MAX_SAFE_JCS_INTEGER,
                open_files_per_process: MAX_SAFE_JCS_INTEGER,
                file_bytes_per_regular_file: MAX_SAFE_JCS_INTEGER,
                core_bytes: MAX_SAFE_JCS_INTEGER,
            },
            stdout_bytes_retained: maximum_count,
            stderr_bytes_retained: maximum_count,
            stderr_hex: String::new(),
            outcome: AcquisitionOutcome::IoFailed {
                message: String::new(),
            },
        },
        raw_length: maximum_count,
        raw_sha256: digest,
        provider_sequence: None,
        interpretation: unavailable.clone(),
    };
    let fixed_record_bytes = nq_protocol::canonical_json_bytes(&specimen)
        .map_err(|error| capacity_error(error.to_string()))?
        .len();
    let unavailable_bytes = nq_protocol::canonical_json_bytes(&unavailable)
        .map_err(|error| capacity_error(error.to_string()))?
        .len();

    let validated_shell_bytes = nq_protocol::canonical_json_bytes(&serde_json::json!({
        "response": null,
        "state": "validated",
    }))
    .map_err(|error| capacity_error(error.to_string()))?
    .len()
    .checked_sub("null".len())
    .ok_or_else(|| capacity_error("validated interpretation shell underflowed"))?;
    let validated_bytes = checked_capacity_add(
        validated_shell_bytes,
        limits.max_response_bytes,
        "validated response representation",
    )?;

    let rejection_static_bytes = protocol_rejection_static_bound(request.instance_id.as_str())?;
    let rejection_raw_bytes = checked_capacity_multiply(
        limits.max_response_bytes,
        MAX_JCS_STRING_BYTES_PER_INPUT_BYTE,
        "protocol rejection raw-derived field",
    )?;
    let rejection_detail_bytes = checked_capacity_multiply(
        MAX_ACQUISITION_DETAIL_BYTES,
        MAX_JCS_STRING_BYTES_PER_INPUT_BYTE,
        "protocol rejection bounded detail",
    )?;
    let rejected_bytes = checked_capacity_add(
        checked_capacity_add(
            rejection_static_bytes,
            rejection_raw_bytes,
            "protocol rejection representation",
        )?,
        rejection_detail_bytes,
        "protocol rejection representation",
    )?;
    let interpretation_bytes = unavailable_bytes.max(validated_bytes).max(rejected_bytes);

    let stderr_hex_bytes = checked_capacity_multiply(
        limits.max_stderr_bytes,
        2,
        "stderr hexadecimal representation",
    )?;
    let native_detail_bytes = checked_capacity_multiply(
        MAX_ACQUISITION_DETAIL_BYTES,
        MAX_JCS_STRING_BYTES_PER_INPUT_BYTE,
        "native acquisition detail representation",
    )?;
    let without_unavailable = fixed_record_bytes
        .checked_sub(unavailable_bytes)
        .ok_or_else(|| capacity_error("provider-intake fixed representation underflowed"))?;
    let canonical_record_bytes = [interpretation_bytes, stderr_hex_bytes, native_detail_bytes]
        .into_iter()
        .try_fold(without_unavailable, |total, addition| {
            checked_capacity_add(total, addition, "provider-intake representation")
        })?;

    Ok(ProviderIntakeCapacityBound {
        canonical_record_bytes: u64::try_from(canonical_record_bytes)
            .map_err(|_| capacity_error("provider-intake bound exceeds u64"))?,
        raw_capture_bytes: u64::try_from(limits.max_response_bytes)
            .map_err(|_| capacity_error("raw response bound exceeds u64"))?,
        stderr_hex_bytes: u64::try_from(stderr_hex_bytes)
            .map_err(|_| capacity_error("stderr representation bound exceeds u64"))?,
        native_detail_bytes: u64::try_from(native_detail_bytes)
            .map_err(|_| capacity_error("native detail bound exceeds u64"))?,
        interpretation_bytes: u64::try_from(interpretation_bytes)
            .map_err(|_| capacity_error("interpretation bound exceeds u64"))?,
    })
}

/// One sealed runtime intake: immutable typed metadata plus exact raw custody.
/// This type has no `Deserialize`; decoding its record cannot manufacture the
/// raw-byte association or a live provider authorization.
#[derive(Clone, Debug)]
pub(crate) struct ProviderIntakeV1 {
    record: ProviderIntakeRecordV1,
    raw_bytes: Vec<u8>,
}

impl ProviderIntakeV1 {
    /// Finish one verified attempt from the runner's exact bounded capture.
    pub(crate) fn from_capture(
        attempt: ProviderAttempt,
        capture: RunCapture,
        limits: &ResourceLimits,
    ) -> Result<Self, ProviderIntakeError> {
        let interpretation = interpret_response(&attempt.request, &capture);
        // Durable SQL timestamps and canonical result carriers use millisecond
        // precision. Bind the intake context to that exact same value rather
        // than retaining sub-millisecond process-clock detail in only one copy.
        let started_at = millisecond_time(capture.started_at);
        let finished_at = millisecond_time(capture.finished_at);
        let raw_bytes = capture.stdout.clone();
        let raw_sha256 = nq_protocol::sha256_bytes(&raw_bytes);
        let request_digest = nq_protocol::semantic_digest(&attempt.request)
            .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let deadline_at = attempt.deadline_at(started_at)?;
        let context_digest = nq_protocol::semantic_digest(&ProviderIntakeContextV1 {
            schema: ProviderIntakeContextSchema::V1,
            intake_id: attempt.intake_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            run_id: attempt.run_id.clone(),
            request: attempt.request.clone(),
            provider: attempt.provider.identity().clone(),
            origin_carrier: attempt.origin_carrier.clone(),
            deadline_at,
            checkpoint_contract_digest: attempt.checkpoint_contract_digest.clone(),
        })
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let idempotency_key = nq_store::provider_idempotency_key(
            attempt.provider.identity().provider_admission_id.as_str(),
            &attempt.attempt_id,
        )
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let native_outcome = RunResourceOutcomeV1 {
            schema: RunResourceOutcomeSchema::V1,
            duration_ms: capture.duration_ms,
            exit_code: capture.exit_code,
            hard_limits: RunHardLimits {
                address_space_bytes_per_process: limits.max_address_space_bytes,
                cpu_seconds_per_process: limits.max_cpu_seconds,
                processes_per_execution_uid: limits.max_processes,
                open_files_per_process: limits.max_open_files,
                file_bytes_per_regular_file: limits.max_file_bytes,
                core_bytes: 0,
            },
            stdout_bytes_retained: raw_bytes.len(),
            stderr_bytes_retained: capture.stderr.len(),
            stderr_hex: hex::encode(&capture.stderr),
            outcome: capture.outcome,
        };
        let record = ProviderIntakeRecordV1 {
            schema: ProviderIntakeSchema::V1,
            intake_id: attempt.intake_id,
            idempotency_key,
            attempt_id: attempt.attempt_id,
            run_id: attempt.run_id,
            request_id: attempt.request.request_id.to_string(),
            request: attempt.request,
            provider: attempt.provider.identity,
            origin_carrier: attempt.origin_carrier,
            deadline_at,
            request_digest,
            context_digest,
            checkpoint_contract_digest: attempt.checkpoint_contract_digest,
            started_at,
            finished_at,
            received_at: finished_at,
            native_outcome,
            raw_length: raw_bytes.len(),
            raw_sha256,
            provider_sequence: None,
            interpretation,
        };
        let intake = Self { record, raw_bytes };
        intake.validate()?;
        Ok(intake)
    }

    /// Immutable metadata to persist and independently reopen.
    pub(crate) fn record(&self) -> &ProviderIntakeRecordV1 {
        &self.record
    }

    /// Exact raw capture; parsed candidate evidence can never replace it.
    pub(crate) fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Convert the sealed intake to the store's typed input. Every caller-visible
    /// digest in the store is recomputed there; this conversion carries exact
    /// source objects rather than accepting parallel projections.
    pub(crate) fn to_store_input(
        &self,
        run: &nq_store::RunInput,
    ) -> Result<nq_store::ProviderIntakeInput, ProviderIntakeError> {
        let context = ProviderIntakeContextV1 {
            schema: ProviderIntakeContextSchema::V1,
            intake_id: self.record.intake_id.clone(),
            attempt_id: self.record.attempt_id.clone(),
            run_id: self.record.run_id.clone(),
            request: self.record.request.clone(),
            provider: self.record.provider.clone(),
            origin_carrier: self.record.origin_carrier.clone(),
            deadline_at: self.record.deadline_at,
            checkpoint_contract_digest: self.record.checkpoint_contract_digest.clone(),
        };
        let context = nq_store::CanonicalDocument::from_serializable(&context)
            .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let native_outcome =
            nq_store::CanonicalDocument::from_serializable(&self.record.native_outcome)
                .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let interpretation =
            nq_store::CanonicalDocument::from_serializable(&self.record.interpretation)
                .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let execution_identity_digest =
            digest("execution_identity_digest", run.execution_identity.digest())?;
        if run.run_id != self.record.run_id
            || run.request_id != self.record.request_id
            || run.admission_id.as_deref()
                != Some(self.record.provider.source_admission_id.as_str())
            || run.binding_digest != self.record.provider.binding_digest.as_str()
            || run.checkpoint_contract_digest != self.record.checkpoint_contract_digest.as_str()
            || run.instance_id != self.record.request.instance_id.as_str()
            || run.profile_id != self.record.request.profile.id.as_str()
            || run.profile_version != self.record.request.profile.version.as_str()
            || run.profile_digest != self.record.request.profile.digest.as_str()
            || run.started_at != timestamp(self.record.started_at)
            || run.deadline_at != deadline_timestamp(self.record.deadline_at)
            || run.finished_at != timestamp(self.record.finished_at)
            || run.acquisition_outcome
                != crate::engine::acquisition_code(&self.record.native_outcome.outcome)
            || run.resource_outcome.as_bytes() != native_outcome.as_bytes()
            || execution_identity_digest != self.record.provider.execution_identity_digest
            || run.carrier != self.record.origin_carrier
        {
            return Err(ProviderIntakeError::Invariant(
                "provider intake does not match its exact local origin".into(),
            ));
        }
        Ok(nq_store::ProviderIntakeInput {
            intake_id: self.record.intake_id.clone(),
            attempt_id: self.record.attempt_id.clone(),
            idempotency_key: self.record.idempotency_key.clone(),
            request_id: self.record.request_id.clone(),
            provider_admission_id: self
                .record
                .provider
                .provider_admission_id
                .as_str()
                .to_owned(),
            source_admission_id: self.record.provider.source_admission_id.clone(),
            provider_sequence: self.record.provider_sequence.clone(),
            origin_carrier: self.record.origin_carrier.clone(),
            deadline_at: deadline_timestamp(self.record.deadline_at),
            checkpoint_contract_digest: self.record.checkpoint_contract_digest.to_string(),
            execution_identity_digest,
            admission_context_digest: self.record.provider.admission_context_digest.clone(),
            provider_semantic_id: self.record.provider.provider_semantic_id.clone(),
            provider_artifact_digest: self.record.provider.artifact_digest.clone(),
            provider_protocol_identity: self.record.provider.protocol_identity.clone(),
            provider_config_digest: self.record.provider.configuration_digest.clone(),
            binding_digest: self.record.provider.binding_digest.as_str().to_owned(),
            instance_id: self.record.request.instance_id.to_string(),
            profile_id: self.record.request.profile.id.to_string(),
            profile_version: self.record.request.profile.version.to_string(),
            profile_digest: self.record.request.profile.digest.as_str().to_owned(),
            profile_semantic_id: self.record.provider.profile_semantic_id.clone(),
            evaluator_artifact_digest: self.record.provider.evaluator_artifact_digest.clone(),
            context,
            native_outcome_kind: crate::engine::acquisition_code(
                &self.record.native_outcome.outcome,
            )
            .to_owned(),
            native_outcome,
            interpretation_kind: self.record.interpretation.kind().to_owned(),
            interpretation,
            raw_bytes: self.raw_bytes.clone(),
            started_at: timestamp(self.record.started_at),
            finished_at: timestamp(self.record.finished_at),
            received_at: timestamp(self.record.received_at),
        })
    }

    #[allow(clippy::too_many_lines)] // One fail-closed audit over identity, custody, timing, and interpretation.
    fn validate(&self) -> Result<(), ProviderIntakeError> {
        self.record.provider.verify_historical()?;
        let request_digest = nq_protocol::semantic_digest(&self.record.request)
            .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let context_digest = nq_protocol::semantic_digest(&ProviderIntakeContextV1 {
            schema: ProviderIntakeContextSchema::V1,
            intake_id: self.record.intake_id.clone(),
            attempt_id: self.record.attempt_id.clone(),
            run_id: self.record.run_id.clone(),
            request: self.record.request.clone(),
            provider: self.record.provider.clone(),
            origin_carrier: self.record.origin_carrier.clone(),
            deadline_at: self.record.deadline_at,
            checkpoint_contract_digest: self.record.checkpoint_contract_digest.clone(),
        })
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let idempotency_key = nq_store::provider_idempotency_key(
            self.record.provider.provider_admission_id.as_str(),
            &self.record.attempt_id,
        )
        .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let stderr = hex::decode(&self.record.native_outcome.stderr_hex).map_err(|error| {
            ProviderIntakeError::Invariant(format!(
                "native stderr is not exact lowercase hexadecimal: {error}"
            ))
        })?;
        if hex::encode(&stderr) != self.record.native_outcome.stderr_hex {
            return Err(ProviderIntakeError::Invariant(
                "native stderr hexadecimal is not canonical lowercase".into(),
            ));
        }
        let reconstructed = RunCapture {
            started_at: self.record.started_at,
            finished_at: self.record.finished_at,
            duration_ms: self.record.native_outcome.duration_ms,
            exit_code: self.record.native_outcome.exit_code,
            stdout: self.raw_bytes.clone(),
            stderr,
            outcome: self.record.native_outcome.outcome.clone(),
        };
        let expected_interpretation = interpret_response(&self.record.request, &reconstructed);
        let inconsistencies = [
            ("schema", self.record.schema != ProviderIntakeSchema::V1),
            ("intake_id", self.record.intake_id.is_empty()),
            ("attempt_id", self.record.attempt_id.is_empty()),
            (
                "idempotency_key",
                self.record.idempotency_key != idempotency_key,
            ),
            ("run_id", self.record.run_id.is_empty()),
            ("request_id_empty", self.record.request_id.is_empty()),
            (
                "request_id_binding",
                self.record.request_id != self.record.request.request_id.as_str(),
            ),
            (
                "request_digest",
                self.record.request_digest != request_digest,
            ),
            (
                "context_digest",
                self.record.context_digest != context_digest,
            ),
            (
                "attempt_run_identity",
                self.record.attempt_id == self.record.run_id,
            ),
            (
                "origin_carrier",
                !matches!(self.record.origin_carrier.as_str(), "stdio" | "unix"),
            ),
            ("provider_sequence", self.record.provider_sequence.is_some()),
            (
                "deadline_order",
                self.record.started_at > self.record.deadline_at,
            ),
            ("raw_length", self.record.raw_length != self.raw_bytes.len()),
            (
                "raw_digest",
                self.record.raw_sha256 != nq_protocol::sha256_bytes(&self.raw_bytes),
            ),
            (
                "stdout_length",
                self.record.native_outcome.stdout_bytes_retained != self.raw_bytes.len(),
            ),
            (
                "stderr_length",
                self.record.native_outcome.stderr_bytes_retained != reconstructed.stderr.len(),
            ),
            (
                "native_schema",
                self.record.native_outcome.schema != RunResourceOutcomeSchema::V1,
            ),
            (
                "attempt_time_order",
                self.record.started_at > self.record.finished_at,
            ),
            (
                "receive_time_order",
                self.record.finished_at > self.record.received_at,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        if !inconsistencies.is_empty() {
            return Err(ProviderIntakeError::Invariant(format!(
                "provider intake identity, raw custody, or timing is inconsistent: {}",
                inconsistencies.join(", ")
            )));
        }
        let stored_interpretation =
            nq_store::CanonicalDocument::from_serializable(&self.record.interpretation)
                .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        let expected_interpretation_document =
            nq_store::CanonicalDocument::from_serializable(&expected_interpretation)
                .map_err(|error| ProviderIntakeError::Canonical(error.to_string()))?;
        if stored_interpretation.as_bytes() != expected_interpretation_document.as_bytes() {
            return Err(ProviderIntakeError::Invariant(format!(
                "provider interpretation differs from reconstruction from exact raw custody on historical reopening: stored {} {} but reconstructed {} {}",
                self.record.interpretation.kind(),
                stored_interpretation.digest(),
                expected_interpretation.kind(),
                expected_interpretation_document.digest()
            )));
        }
        match (
            &self.record.native_outcome.outcome,
            &self.record.interpretation,
        ) {
            (
                AcquisitionOutcome::Response,
                ProviderResponseInterpretationV1::ProtocolRejected { .. }
                | ProviderResponseInterpretationV1::Validated { .. },
            )
            | (_, ProviderResponseInterpretationV1::NotAvailable) => Ok(()),
            (_, _) => Err(ProviderIntakeError::Invariant(
                "non-response acquisition cannot carry a parsed response interpretation".into(),
            )),
        }
    }
}

/// Interpret exact provider bytes under one exact request. This function is
/// also used by the admission-time dry exchange without pretending that its
/// candidate provider has already been admitted.
pub(crate) fn interpret_response(
    request: &HelperRequest,
    capture: &RunCapture,
) -> ProviderResponseInterpretationV1 {
    if capture.outcome != AcquisitionOutcome::Response {
        return ProviderResponseInterpretationV1::NotAvailable;
    }
    match nq_protocol::parse_response(request, &capture.stdout) {
        Ok(response) => ProviderResponseInterpretationV1::Validated { response },
        Err(error) => ProviderResponseInterpretationV1::ProtocolRejected {
            rejection: protocol_rejection(&request.instance_id.to_string(), error),
        },
    }
}

fn digest(field: &'static str, value: &str) -> Result<Sha256Digest, ProviderIntakeError> {
    Sha256Digest::parse(value.to_owned()).map_err(|error| {
        ProviderIntakeError::Identity(format!("{field} is not a strict SHA-256 identity: {error}"))
    })
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn deadline_timestamp(value: DateTime<Utc>) -> String {
    if value.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
        timestamp(value)
    } else {
        value.to_rfc3339_opts(SecondsFormat::Nanos, true)
    }
}

fn millisecond_time(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond(value.timestamp_subsec_millis() * 1_000_000)
        .expect("a millisecond timestamp is always a valid nanosecond value")
}

/// Failure to construct an identity-bound provider intake.
#[derive(Debug, Error)]
pub enum ProviderIntakeError {
    /// A trusted identity or association did not hold.
    #[error("provider identity invalid: {0}")]
    Identity(String),
    /// A canonical identity could not be derived.
    #[error("provider intake canonicalization failed: {0}")]
    Canonical(String),
    /// A pre-effect canonical custody maximum could not be represented.
    #[error("provider intake capacity bound failed: {0}")]
    Capacity(String),
    /// Cross-field intake invariants did not hold.
    #[error("provider intake invariant failed: {0}")]
    Invariant(String),
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use nq_profiles::{ProfileModule, ProfileRefusalCode, ReportInput, ValidationContext};
    use nq_protocol::{
        BackendIdentity, BackendProvenance, Capability, EvidenceReport, HelperRequest,
        HelperResponse, ImplementationName, InstanceId, MonotonicDeadline, ProfileBinding,
        ProfileId, ProfileVersion, Refusal, RefusalBoundary, RefusalCode, ReportStatus, RequestId,
        ResponseOutcome, ScopeBinding, ScopeKind, SubjectBinding, SubjectId, VantageBinding,
        VantageKind,
    };
    use serde_json::json;

    use super::*;
    use crate::runner::ExchangeTimeoutPhase;

    fn request() -> HelperRequest {
        HelperRequest::builder(
            RequestId::new("request-provider-intake").expect("request id"),
            InstanceId::new("provider-intake.instance").expect("instance id"),
            ProfileBinding {
                id: ProfileId::new("nq.provider-fixture").expect("profile id"),
                version: ProfileVersion::new("1").expect("profile version"),
                digest: nq_protocol::sha256_bytes(b"provider fixture profile"),
            },
            SubjectBinding {
                subject: SubjectId::new("fixture:provider-intake").expect("subject"),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").expect("scope kind"),
                    value: json!({"partition": "a"}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").expect("vantage kind"),
                    value: json!({"namespace": "host"}),
                },
            },
            MonotonicDeadline {
                clock: nq_protocol::MonotonicClock::LinuxBoottime,
                expires_at_ns: 10_000,
            },
        )
        .build()
        .expect("valid provider fixture request")
    }

    fn conformance_request() -> HelperRequest {
        let descriptor = nq_profiles::conformance::MODULE.descriptor();
        HelperRequest::builder(
            RequestId::new("request-provider-conformance").expect("request id"),
            InstanceId::new("provider-conformance.instance").expect("instance id"),
            ProfileBinding {
                id: ProfileId::new(descriptor.profile.id.clone()).expect("profile id"),
                version: ProfileVersion::new(descriptor.profile.version.to_string())
                    .expect("profile version"),
                digest: Sha256Digest::parse(
                    descriptor
                        .digest()
                        .expect("profile digest")
                        .as_str()
                        .to_owned(),
                )
                .expect("typed profile digest"),
            },
            SubjectBinding {
                subject: SubjectId::new("conformance:provider-intake").expect("subject"),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").expect("scope kind"),
                    value: json!({"id": "provider-intake", "nonce": "nq-owned-nonce"}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").expect("vantage kind"),
                    value: json!({}),
                },
            },
            MonotonicDeadline {
                clock: nq_protocol::MonotonicClock::LinuxBoottime,
                expires_at_ns: 10_000,
            },
        )
        .build()
        .expect("valid conformance request")
    }

    fn candidate_report(
        request: &HelperRequest,
        backend_name: &str,
        backend_digest: Sha256Digest,
        used_capabilities: Vec<Capability>,
    ) -> EvidenceReport {
        EvidenceReport {
            schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
            profile: request.profile.clone(),
            binding: request.binding.clone(),
            observed_at: DateTime::parse_from_rfc3339("2026-07-20T12:00:00.000Z")
                .expect("observation time")
                .with_timezone(&Utc),
            status: ReportStatus::Complete,
            coverage: Vec::new(),
            observations: Vec::new(),
            errors: Vec::new(),
            used_capabilities,
            backend: BackendProvenance {
                implementation: BackendIdentity {
                    name: ImplementationName::new(backend_name).expect("backend name"),
                    version: Some("self-declared-v999".to_owned()),
                    digest: Some(backend_digest),
                },
                tools: Vec::new(),
            },
            next_checkpoint: None,
        }
    }

    fn verified_provider() -> VerifiedProvider {
        let conformance = ConformanceReceipt {
            tool_version: "provider-intake-fixture-v1".to_owned(),
            protocol_passed: true,
            protocol_corpus_digest: nq_protocol::sha256_bytes(b"provider corpus").into_string(),
            protocol_fixtures_checked: 1,
            dry_collection_passed: true,
            dry_report_digest: Some(
                nq_protocol::sha256_bytes(b"provider dry report").into_string(),
            ),
        };
        let conformance_document = nq_store::CanonicalDocument::from_serializable(&conformance)
            .expect("canonical conformance");
        let provider_semantic_id = nq_store::local_provider_semantic_id(
            nq_protocol::HELPER_PROTOCOL_VERSION,
            &conformance_document,
        )
        .expect("provider semantic identity");
        let execution_identity = execution_identity_document();
        let identity = ProviderIdentityV1 {
            schema: ProviderIdentitySchema::V1,
            kind: ProviderKind::LocalHelper,
            provider_semantic_id,
            provider_admission_id: nq_protocol::sha256_bytes(b"provider admission contract"),
            source_admission_id: "source-admission-fixture".to_owned(),
            binding_digest: nq_protocol::sha256_bytes(b"provider binding"),
            artifact_digest: nq_protocol::sha256_bytes(b"provider artifact"),
            execution_identity_digest: Sha256Digest::parse(execution_identity.digest().to_owned())
                .expect("execution identity digest"),
            configuration_digest: nq_protocol::sha256_bytes(b"provider configuration"),
            protocol_identity: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            conformance_corpus_digest: Sha256Digest::parse(
                conformance.protocol_corpus_digest.clone(),
            )
            .expect("corpus digest"),
            conformance_tool_version: conformance.tool_version.clone(),
            conformance,
            profile_semantic_id: nq_protocol::sha256_bytes(b"profile semantics"),
            evaluator_artifact_digest: nq_protocol::sha256_bytes(b"evaluator artifact"),
            admission_context_digest: nq_protocol::sha256_bytes(b"admission context"),
        };
        identity
            .verify_historical()
            .expect("valid fixture provider");
        VerifiedProvider { identity }
    }

    fn execution_identity_document() -> nq_store::CanonicalDocument {
        nq_store::CanonicalDocument::from_serializable(&json!({
            "schema": "nq.test.execution_identity.v1",
            "artifact": "provider-fixture",
        }))
        .expect("canonical execution identity")
    }

    fn attempt(request: HelperRequest, suffix: &str) -> ProviderAttempt {
        ProviderAttempt::new(
            format!("intake-{suffix}"),
            format!("attempt-{suffix}"),
            format!("run-{suffix}"),
            request,
            verified_provider(),
            "stdio".to_owned(),
            1_000,
            nq_protocol::sha256_bytes(b"checkpoint contract").as_str(),
        )
        .expect("valid fixture attempt")
    }

    fn governed_attempt(
        request: HelperRequest,
        suffix: &str,
        absolute_deadline: DateTime<Utc>,
    ) -> ProviderAttempt {
        ProviderAttempt::new_governed(
            format!("intake-{suffix}"),
            format!("attempt-{suffix}"),
            format!("run-{suffix}"),
            request,
            verified_provider(),
            "stdio".to_owned(),
            absolute_deadline,
            nq_protocol::sha256_bytes(b"checkpoint contract").as_str(),
        )
        .expect("valid governed fixture attempt")
    }

    fn capture(stdout: Vec<u8>, outcome: AcquisitionOutcome) -> RunCapture {
        let started_at = DateTime::parse_from_rfc3339("2026-07-20T12:00:00.000Z")
            .expect("start time")
            .with_timezone(&Utc);
        RunCapture {
            started_at,
            finished_at: started_at + Duration::milliseconds(1),
            duration_ms: 1,
            exit_code: (outcome == AcquisitionOutcome::Response).then_some(0),
            stdout,
            stderr: b"provider diagnostic".to_vec(),
            outcome,
        }
    }

    #[test]
    fn governed_attempt_retains_fixed_deadline_across_later_watchdog_recomputation() {
        let absolute_deadline = DateTime::parse_from_rfc3339("2026-07-20T12:00:10.000Z")
            .expect("absolute deadline")
            .with_timezone(&Utc);
        let first_start = DateTime::parse_from_rfc3339("2026-07-20T12:00:04.000Z")
            .expect("first start")
            .with_timezone(&Utc);
        let later_start = DateTime::parse_from_rfc3339("2026-07-20T12:00:09.750Z")
            .expect("later start")
            .with_timezone(&Utc);
        let make_capture = |started_at| RunCapture {
            started_at,
            finished_at: started_at + Duration::milliseconds(1),
            duration_ms: 1,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            outcome: AcquisitionOutcome::Eof,
        };

        let first = ProviderIntakeV1::from_capture(
            governed_attempt(request(), "fixed-deadline-first", absolute_deadline),
            make_capture(first_start),
            &ResourceLimits::default(),
        )
        .expect("first governed intake");
        let later = ProviderIntakeV1::from_capture(
            governed_attempt(request(), "fixed-deadline-later", absolute_deadline),
            make_capture(later_start),
            &ResourceLimits::default(),
        )
        .expect("later governed intake");

        assert_eq!(first.record().deadline_at, absolute_deadline);
        assert_eq!(later.record().deadline_at, absolute_deadline);
        assert!(
            later_start + Duration::milliseconds(1_000) > absolute_deadline,
            "a stale relative watchdog would have widened the authorized window"
        );
        assert_ne!(first.record().started_at, later.record().started_at);
    }

    #[test]
    fn governed_attempt_preserves_submillisecond_deadline_identity() {
        let deadline = DateTime::parse_from_rfc3339("2026-07-20T12:00:10.000001Z")
            .expect("submillisecond deadline")
            .with_timezone(&Utc);
        let started_at = deadline - Duration::milliseconds(1);
        let intake = ProviderIntakeV1::from_capture(
            ProviderAttempt::new_governed(
                "intake-submillisecond".to_owned(),
                "attempt-submillisecond".to_owned(),
                "run-submillisecond".to_owned(),
                request(),
                verified_provider(),
                "stdio".to_owned(),
                deadline,
                nq_protocol::sha256_bytes(b"checkpoint contract").as_str(),
            )
            .expect("governed attempt"),
            RunCapture {
                started_at,
                finished_at: started_at + Duration::microseconds(500),
                duration_ms: 0,
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                outcome: AcquisitionOutcome::Eof,
            },
            &ResourceLimits::default(),
        )
        .expect("governed intake");

        assert_eq!(intake.record().deadline_at, deadline);
        assert_eq!(
            deadline_timestamp(intake.record().deadline_at),
            "2026-07-20T12:00:10.000001000Z"
        );
        let stored = intake
            .to_store_input(&local_run(&intake))
            .expect("exact governed store projection");
        assert_eq!(stored.deadline_at, "2026-07-20T12:00:10.000001000Z");
    }

    #[test]
    fn governed_attempt_cannot_admit_capture_started_after_fixed_deadline() {
        let absolute_deadline = DateTime::parse_from_rfc3339("2026-07-20T12:00:10.000Z")
            .expect("absolute deadline")
            .with_timezone(&Utc);
        let started_at = absolute_deadline + Duration::milliseconds(1);
        let result = ProviderIntakeV1::from_capture(
            governed_attempt(request(), "expired-fixed-deadline", absolute_deadline),
            RunCapture {
                started_at,
                finished_at: started_at + Duration::milliseconds(1),
                duration_ms: 1,
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                outcome: AcquisitionOutcome::Eof,
            },
            &ResourceLimits::default(),
        );

        assert!(matches!(
            result,
            Err(ProviderIntakeError::Invariant(detail)) if detail.contains("deadline_order")
        ));
    }

    fn local_run(intake: &ProviderIntakeV1) -> nq_store::RunInput {
        let record = intake.record();
        nq_store::RunInput {
            run_id: record.run_id.clone(),
            request_id: record.request_id.clone(),
            instance_id: record.request.instance_id.to_string(),
            admission_id: Some(record.provider.source_admission_id.clone()),
            binding_digest: record.provider.binding_digest.to_string(),
            checkpoint_contract_digest: record.checkpoint_contract_digest.to_string(),
            profile_id: record.request.profile.id.to_string(),
            profile_version: record.request.profile.version.to_string(),
            profile_digest: record.request.profile.digest.to_string(),
            carrier: record.origin_carrier.clone(),
            started_at: timestamp(record.started_at),
            deadline_at: deadline_timestamp(record.deadline_at),
            finished_at: timestamp(record.finished_at),
            acquisition_outcome: crate::engine::acquisition_code(&record.native_outcome.outcome)
                .to_owned(),
            execution_identity: execution_identity_document(),
            resource_outcome: nq_store::CanonicalDocument::from_serializable(
                &record.native_outcome,
            )
            .expect("canonical resource outcome"),
        }
    }

    fn fixture_capacity_bound(
        request: &HelperRequest,
        provider: &VerifiedProvider,
        limits: &ResourceLimits,
    ) -> Result<ProviderIntakeCapacityBound, ProviderIntakeError> {
        provider_intake_capacity_bound(
            request,
            provider,
            limits,
            "intake-capacity-fixture",
            "attempt-capacity-fixture",
            "run-capacity-fixture",
            "stdio",
            &nq_protocol::sha256_bytes(b"capacity checkpoint contract"),
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn conservative_capacity_covers_raw_stderr_native_and_interpretation_surfaces() {
        let request = request();
        let mut limits = ResourceLimits {
            max_response_bytes: request.bounds.max_response_bytes as usize,
            ..ResourceLimits::default()
        };
        let provider = verified_provider();
        let bound = fixture_capacity_bound(&request, &provider, &limits)
            .expect("live request/provider shape has a finite bound");
        assert_eq!(
            bound.raw_capture_bytes,
            u64::try_from(limits.max_response_bytes).expect("raw bound")
        );
        assert_eq!(
            bound.stderr_hex_bytes,
            u64::try_from(limits.max_stderr_bytes * 2).expect("stderr hex bound")
        );
        assert_eq!(
            bound.native_detail_bytes,
            u64::try_from(MAX_ACQUISITION_DETAIL_BYTES * MAX_JCS_STRING_BYTES_PER_INPUT_BYTE)
                .expect("native detail bound")
        );

        let response = HelperResponse::report(
            &request,
            candidate_report(
                &request,
                "capacity-valid-response",
                nq_protocol::sha256_bytes(b"capacity valid response"),
                Vec::new(),
            ),
        );
        let valid_raw = nq_protocol::encode_ndjson(&response).expect("valid response frame");
        let valid = ProviderIntakeV1::from_capture(
            attempt(request.clone(), "capacity-valid"),
            capture(valid_raw.clone(), AcquisitionOutcome::Response),
            &limits,
        )
        .expect("valid response intake");
        let valid_record_bytes = nq_protocol::canonical_json_bytes(valid.record())
            .expect("canonical valid intake")
            .len();
        assert!(
            u64::try_from(valid_record_bytes).expect("valid intake length")
                <= bound.canonical_record_bytes
        );

        let rejected_raw = br#"{"schema":"hostile","value":"\u0000"}"#.to_vec();
        let rejected = ProviderIntakeV1::from_capture(
            attempt(request.clone(), "capacity-rejected"),
            capture(rejected_raw, AcquisitionOutcome::Response),
            &limits,
        )
        .expect("protocol rejection intake");
        assert!(matches!(
            rejected.record().interpretation,
            ProviderResponseInterpretationV1::ProtocolRejected { .. }
        ));
        let rejected_record_bytes = nq_protocol::canonical_json_bytes(rejected.record())
            .expect("canonical rejected intake")
            .len();
        assert!(
            u64::try_from(rejected_record_bytes).expect("rejected intake length")
                <= bound.canonical_record_bytes
        );

        limits.max_stderr_bytes = 257;
        let bound =
            fixture_capacity_bound(&request, &provider, &limits).expect("stderr-adjusted bound");
        let started_at = DateTime::parse_from_rfc3339("2026-07-20T12:00:00.000Z")
            .expect("start time")
            .with_timezone(&Utc);
        let raw = vec![b'x'; limits.max_response_bytes];
        let failed = ProviderIntakeV1::from_capture(
            attempt(request, "capacity-native-failure"),
            RunCapture {
                started_at,
                finished_at: started_at + Duration::milliseconds(1),
                duration_ms: 1,
                exit_code: None,
                stdout: raw.clone(),
                stderr: vec![0xff; limits.max_stderr_bytes],
                outcome: AcquisitionOutcome::IoFailed {
                    message: "\0".repeat(MAX_ACQUISITION_DETAIL_BYTES),
                },
            },
            &limits,
        )
        .expect("bounded native failure intake");
        let failed_record_bytes = nq_protocol::canonical_json_bytes(failed.record())
            .expect("canonical failure intake")
            .len();
        assert!(
            u64::try_from(failed_record_bytes).expect("failure intake length")
                <= bound.canonical_record_bytes
        );
        let exact_carrier = nq_store::governed_acquisition_capacity_bound(
            u64::try_from(failed_record_bytes).expect("record length"),
            u64::try_from(raw.len()).expect("raw length"),
        )
        .expect("exact acquisition carrier");
        let conservative_carrier = nq_store::governed_acquisition_capacity_bound(
            bound.canonical_record_bytes,
            bound.raw_capture_bytes,
        )
        .expect("conservative acquisition carrier");
        assert!(exact_carrier <= conservative_carrier);
    }

    #[test]
    fn capacity_bound_rejects_mismatch_and_checked_arithmetic_overflow() {
        let request = request();
        let provider = verified_provider();
        let mismatched = ResourceLimits::default();
        assert!(matches!(
            fixture_capacity_bound(&request, &provider, &mismatched),
            Err(ProviderIntakeError::Capacity(message))
                if message.contains("do not correspond")
        ));

        let overflow = ResourceLimits {
            max_response_bytes: request.bounds.max_response_bytes as usize,
            max_stderr_bytes: usize::MAX,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            fixture_capacity_bound(&request, &provider, &overflow),
            Err(ProviderIntakeError::Capacity(message))
                if message.contains("overflowed")
        ));
    }

    #[test]
    fn exact_raw_refusal_and_context_are_one_validated_intake() {
        let request = request();
        let response = HelperResponse::refusal(
            &request,
            Refusal {
                responsible_instance_id: request.instance_id.clone(),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "provider-local acquisition failed".to_owned(),
                retriable: true,
                details: json!({"errno": "EAGAIN", "loss": {"dropped": 2}}),
            },
        );
        let raw = nq_protocol::encode_ndjson(&response).expect("framed response");
        let intake = ProviderIntakeV1::from_capture(
            attempt(request, "refusal"),
            capture(raw.clone(), AcquisitionOutcome::Response),
            &ResourceLimits::default(),
        )
        .expect("valid provider intake");

        assert_eq!(intake.raw_bytes(), raw);
        assert_eq!(intake.record().raw_sha256, nq_protocol::sha256_bytes(&raw));
        intake
            .record()
            .verify_historical_raw(&raw)
            .expect("historical record verifies without granting authority");
        let ProviderResponseInterpretationV1::Validated { response } =
            &intake.record().interpretation
        else {
            panic!("valid refusal remains a provider-native response")
        };
        let nq_protocol::ResponseOutcome::Refusal { refusal } = &response.outcome else {
            panic!("exact helper refusal retained")
        };
        assert!(refusal.retriable);
        assert_eq!(refusal.details["errno"], "EAGAIN");

        let stored = intake
            .to_store_input(&local_run(&intake))
            .expect("typed store intake");
        assert_eq!(stored.raw_bytes, raw);
        assert_eq!(stored.interpretation_kind, "provider_refusal");
        assert_eq!(
            stored.context.digest(),
            intake.record().context_digest.as_str()
        );

        let mut raw_substitution = intake.clone();
        raw_substitution.raw_bytes.push(b' ');
        assert!(matches!(
            raw_substitution.validate(),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("raw custody")
        ));

        let mut parsed_substitution = intake;
        let ProviderResponseInterpretationV1::Validated { response } =
            &mut parsed_substitution.record.interpretation
        else {
            panic!("validated response")
        };
        let nq_protocol::ResponseOutcome::Refusal { refusal } = &mut response.outcome else {
            panic!("helper refusal")
        };
        refusal.retriable = false;
        assert!(matches!(
            parsed_substitution.validate(),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("provider interpretation differs")
        ));
    }

    #[test]
    fn provider_cannot_inject_nq_judgment_or_authority_fields() {
        let request = request();
        let response = HelperResponse::refusal(
            &request,
            Refusal {
                responsible_instance_id: request.instance_id.clone(),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "provider refusal".to_owned(),
                retriable: false,
                details: json!({}),
            },
        );
        let mut hostile = serde_json::to_value(response).expect("response value");
        let object = hostile.as_object_mut().expect("response object");
        object.insert("finding".to_owned(), json!({"condition": "present"}));
        object.insert("severity".to_owned(), json!("critical"));
        object.insert("remediation".to_owned(), json!("act now"));
        object.insert("entitlement".to_owned(), json!(true));
        object.insert("authority".to_owned(), json!("granted"));
        let mut raw = nq_protocol::canonical_json_bytes(&hostile).expect("hostile canonical bytes");
        raw.push(b'\n');

        let intake = ProviderIntakeV1::from_capture(
            attempt(request, "injection"),
            capture(raw.clone(), AcquisitionOutcome::Response),
            &ResourceLimits::default(),
        )
        .expect("rejected provider bytes still enter raw custody");
        assert_eq!(intake.raw_bytes(), raw);
        assert!(matches!(
            &intake.record().interpretation,
            ProviderResponseInterpretationV1::ProtocolRejected {
                rejection: ProtocolRejection {
                    failure: crate::engine::ProtocolRejectionFailure::InvalidJson { .. },
                    ..
                }
            }
        ));
        assert_eq!(
            intake
                .to_store_input(&local_run(&intake))
                .expect("store rejected intake")
                .interpretation_kind,
            "protocol_rejected"
        );
    }

    #[test]
    fn declared_backend_identity_stays_candidate_data_and_success_is_not_admission() {
        let request = conformance_request();
        let declared_a = nq_protocol::sha256_bytes(b"provider self-asserted artifact a");
        let declared_b = nq_protocol::sha256_bytes(b"provider self-asserted artifact b");
        let make = |suffix: &str, name: &str, declared: Sha256Digest| {
            let response = HelperResponse::report(
                &request,
                candidate_report(&request, name, declared, Vec::new()),
            );
            let raw = nq_protocol::encode_ndjson(&response).expect("framed candidate response");
            ProviderIntakeV1::from_capture(
                attempt(request.clone(), suffix),
                capture(raw, AcquisitionOutcome::Response),
                &ResourceLimits::default(),
            )
            .expect("common protocol success enters candidate intake")
        };
        let intake_a = make("backend-a", "self-asserted-backend-a", declared_a.clone());
        let intake_b = make("backend-b", "self-asserted-backend-b", declared_b.clone());

        assert_eq!(intake_a.record().provider, intake_b.record().provider);
        assert_ne!(intake_a.record().provider.artifact_digest, declared_a);
        assert_ne!(intake_b.record().provider.artifact_digest, declared_b);
        for (intake, declared) in [(&intake_a, declared_a), (&intake_b, declared_b)] {
            let ProviderResponseInterpretationV1::Validated {
                response:
                    HelperResponse {
                        outcome: ResponseOutcome::Report { report },
                        ..
                    },
            } = &intake.record().interpretation
            else {
                panic!("correlated helper success remains only a candidate report")
            };
            assert_eq!(
                report.backend.implementation.digest.as_ref(),
                Some(&declared)
            );
            assert_eq!(intake.record().interpretation.kind(), "candidate_report");

            // Common protocol success is deliberately earlier than NQ's compiled
            // profile gate. This valid, correlated report omits mandatory echo
            // coverage and therefore cannot become an admitted report.
            let report_digest = nq_protocol::semantic_digest(report).expect("report digest");
            let normalized =
                ReportInput::from_protocol(report, &report_digest).expect("normalization");
            let context = ValidationContext::from_request(
                &request,
                intake.record().received_at,
                Duration::seconds(5),
            );
            let refusal = nq_profiles::conformance::MODULE
                .validate(&context, &normalized)
                .expect_err("provider success cannot self-assert profile admission");
            assert_eq!(refusal.code, ProfileRefusalCode::MissingCoverage);
            assert!(
                nq_profiles::conformance::MODULE.detectors().is_empty(),
                "a provider report cannot imply detector presence"
            );
        }
    }

    #[test]
    fn first_submission_capability_escape_keeps_raw_bytes_and_typed_rejection() {
        let request = conformance_request();
        let escaped = Capability::new("external_actuation").expect("capability");
        let response = HelperResponse::report(
            &request,
            candidate_report(
                &request,
                "capability-escape-provider",
                nq_protocol::sha256_bytes(b"self-declared capability provider"),
                vec![escaped.clone()],
            ),
        );
        let raw = nq_protocol::encode_ndjson(&response).expect("framed hostile response");
        let intake = ProviderIntakeV1::from_capture(
            attempt(request, "capability-escape"),
            capture(raw.clone(), AcquisitionOutcome::Response),
            &ResourceLimits::default(),
        )
        .expect("rejected first submission remains an intake artifact");

        assert_eq!(intake.raw_bytes(), raw);
        assert_eq!(intake.record().raw_sha256, nq_protocol::sha256_bytes(&raw));
        assert!(matches!(
            &intake.record().interpretation,
            ProviderResponseInterpretationV1::ProtocolRejected {
                rejection: ProtocolRejection {
                    failure: crate::engine::ProtocolRejectionFailure::Validation {
                        error: crate::engine::ProtocolValidationFailure::CapabilityEscape {
                            capability
                        }
                    },
                    ..
                }
            } if capability == &escaped
        ));
        let stored = intake
            .to_store_input(&local_run(&intake))
            .expect("typed rejected store intake");
        assert_eq!(stored.raw_bytes, raw);
        assert_eq!(stored.interpretation_kind, "protocol_rejected");
    }

    #[test]
    fn partial_timeout_bytes_remain_native_and_uninterpreted() {
        let request = request();
        let raw = br#"{"schema":"nq.helper.response.v1""#.to_vec();
        let intake = ProviderIntakeV1::from_capture(
            attempt(request, "timeout"),
            capture(
                raw.clone(),
                AcquisitionOutcome::ExchangeTimeout {
                    phase: ExchangeTimeoutPhase::ReadResponse,
                },
            ),
            &ResourceLimits::default(),
        )
        .expect("partial timeout intake");
        assert_eq!(intake.raw_bytes(), raw);
        assert!(matches!(
            intake.record().interpretation,
            ProviderResponseInterpretationV1::NotAvailable
        ));
        assert!(matches!(
            intake.record().native_outcome.outcome,
            AcquisitionOutcome::ExchangeTimeout {
                phase: ExchangeTimeoutPhase::ReadResponse
            }
        ));
        let stored = intake
            .to_store_input(&local_run(&intake))
            .expect("store timeout intake");
        assert_eq!(stored.native_outcome_kind, "timeout");
        assert_eq!(stored.interpretation_kind, "unavailable");
        assert_eq!(stored.raw_bytes, raw);
    }

    #[test]
    fn provider_finish_may_precede_nq_receive_without_reintroducing_process_locality() {
        let request = request();
        let response = HelperResponse::refusal(
            &request,
            Refusal {
                responsible_instance_id: request.instance_id.clone(),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "provider completed before delivery".to_owned(),
                retriable: true,
                details: json!({"buffered": true}),
            },
        );
        let raw = nq_protocol::encode_ndjson(&response).expect("framed response");
        let mut intake = ProviderIntakeV1::from_capture(
            attempt(request, "delayed-receive"),
            capture(raw, AcquisitionOutcome::Response),
            &ResourceLimits::default(),
        )
        .expect("local intake");
        intake.record.received_at = intake.record.finished_at + Duration::milliseconds(25);
        intake
            .validate()
            .expect("replaceable provider delivery may arrive after provider completion");

        intake.record.received_at = intake.record.finished_at - Duration::milliseconds(1);
        assert!(matches!(
            intake.validate(),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("timing")
        ));
    }
}
