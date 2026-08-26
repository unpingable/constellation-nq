use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, de};
use serde_json::Value;

use crate::{
    Capability, CoverageKind, ErrorCode, HELPER_RESPONSE_SCHEMA, ImplementationName, InstanceId,
    ObservationKind, ProfileId, ProfileVersion, RequestId, ScopeKind, Sha256Digest, SubjectId,
    VantageKind,
};

/// Exact compiled profile identity requested from a helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBinding {
    /// Stable profile name.
    pub id: ProfileId,
    /// Exact compiled profile version.
    pub version: ProfileVersion,
    /// SHA-256 digest of the canonical compiled descriptor.
    pub digest: Sha256Digest,
}

/// Profile-specific scope requested by NQ.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBinding {
    /// Profile-controlled scope vocabulary entry.
    pub kind: ScopeKind,
    /// Bounded, profile-validated scope parameters.
    pub value: Value,
}

/// Named observation vantage requested by NQ.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VantageBinding {
    /// Profile-controlled vantage vocabulary entry.
    pub kind: VantageKind,
    /// Bounded, profile-validated vantage parameters.
    pub value: Value,
}

/// Subject, scope, and vantage bound to a collection request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectBinding {
    /// Root subject named by the instance configuration.
    pub subject: SubjectId,
    /// Maximum collection scope. A helper may not expand it.
    pub scope: ScopeBinding,
    /// Exact observation vantage.
    pub vantage: VantageBinding,
}

/// Monotonic clock used to express an absolute request deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonotonicClock {
    /// Linux `CLOCK_BOOTTIME`, including time spent suspended.
    LinuxBoottime,
}

/// Absolute monotonic deadline for one bounded request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonotonicDeadline {
    /// Clock whose epoch applies to `expires_at_ns`.
    pub clock: MonotonicClock,
    /// Absolute clock reading in nanoseconds at which work must stop.
    ///
    /// The wire representation is a canonical non-negative decimal string so
    /// the full `u64` range survives I-JSON/JCS implementations without IEEE
    /// 754 precision loss.
    #[serde(with = "decimal_u64")]
    pub expires_at_ns: u64,
}

mod decimal_u64 {
    use super::{Deserialize, Serializer, de};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(de::Error::custom(
                "monotonic nanoseconds must be a canonical decimal u64 string",
            ));
        }
        value.parse().map_err(de::Error::custom)
    }
}

/// Negotiated response and cardinality limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionBounds {
    /// Maximum response frame bytes, including the newline delimiter.
    pub max_response_bytes: u32,
    /// Maximum number of observations in the report.
    pub max_observations: u32,
    /// Maximum canonical JSON bytes in one observation payload.
    pub max_payload_bytes: u32,
    /// Maximum number of coverage declarations.
    pub max_coverage_entries: u32,
    /// Maximum number of ordered structured report errors.
    pub max_report_errors: u32,
    /// Maximum canonical JSON bytes in a checkpoint value.
    pub max_checkpoint_bytes: u32,
}

impl Default for CollectionBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: 4 * 1_048_576,
            max_observations: 4_096,
            max_payload_bytes: 64 * 1_024,
            max_coverage_entries: 256,
            max_report_errors: 128,
            max_checkpoint_bytes: 64 * 1_024,
        }
    }
}

/// Opaque NQ-owned polling checkpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Versioned profile-specific cursor value.
    pub value: Value,
}

/// One request sent by NQ to an admitted helper instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequest {
    /// Must be [`crate::HELPER_REQUEST_SCHEMA`].
    pub schema: String,
    /// Must be [`crate::HELPER_PROTOCOL_VERSION`].
    pub protocol_version: String,
    /// NQ-owned request identity.
    pub request_id: RequestId,
    /// NQ-owned deployment instance identity.
    pub instance_id: InstanceId,
    /// Exact profile contract requested for this exchange.
    pub profile: ProfileBinding,
    /// Subject, maximum scope, and exact vantage.
    pub binding: SubjectBinding,
    /// Capability subset granted for this request.
    pub granted_capabilities: Vec<Capability>,
    /// Existing committed cursor, if this profile supports polling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
    /// Closed selection law for the one qualified passive host-load source.
    ///
    /// Ordinary helpers never receive this field. Its cutoff is fixed by NQ
    /// before provider launch, so a helper cannot turn an acquisition-triggered
    /// measurement into a nominally pre-existing sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_host_load_sample: Option<PassiveHostLoadSampleSelectionV1>,
    /// Deadline that the helper must not extend.
    pub deadline: MonotonicDeadline,
    /// Cardinality and response bounds.
    pub bounds: CollectionBounds,
}

impl HelperRequest {
    /// Creates a builder with safe default bounds and no capabilities.
    #[must_use]
    pub fn builder(
        request_id: RequestId,
        instance_id: InstanceId,
        profile: ProfileBinding,
        binding: SubjectBinding,
        deadline: MonotonicDeadline,
    ) -> crate::HelperRequestBuilder {
        crate::HelperRequestBuilder::new(request_id, instance_id, profile, binding, deadline)
    }
}

/// Fields a helper must echo exactly from its request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEcho {
    /// Exact helper protocol version.
    pub protocol_version: String,
    /// Original request identity.
    pub request_id: RequestId,
    /// Original instance identity.
    pub instance_id: InstanceId,
    /// Original compiled profile binding.
    pub profile: ProfileBinding,
    /// Original subject, scope, and vantage binding.
    pub binding: SubjectBinding,
    /// Original ordered capability grant.
    pub granted_capabilities: Vec<Capability>,
    /// Original checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
    /// Exact passive host-load selection law from the request, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_host_load_sample: Option<PassiveHostLoadSampleSelectionV1>,
    /// Original absolute deadline.
    pub deadline: MonotonicDeadline,
    /// Original negotiated bounds.
    pub bounds: CollectionBounds,
}

impl From<&HelperRequest> for RequestEcho {
    fn from(request: &HelperRequest) -> Self {
        Self {
            protocol_version: request.protocol_version.clone(),
            request_id: request.request_id.clone(),
            instance_id: request.instance_id.clone(),
            profile: request.profile.clone(),
            binding: request.binding.clone(),
            granted_capabilities: request.granted_capabilities.clone(),
            checkpoint: request.checkpoint.clone(),
            passive_host_load_sample: request.passive_host_load_sample.clone(),
            deadline: request.deadline.clone(),
            bounds: request.bounds.clone(),
        }
    }
}

/// Request-controlled selector for the closed passive host-load sample family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveHostLoadSampleSelectionV1 {
    /// Must be [`crate::PASSIVE_HOST_LOAD_SELECTION_SCHEMA_V1`].
    pub schema: String,
    /// Latest permissible source-observation time, fixed before provider launch.
    pub cutoff_at: DateTime<Utc>,
    /// Maximum permitted age at `cutoff_at`.
    pub max_age_ms: u64,
    /// Exact admitted passive-observer profile.
    pub observer_profile: String,
    /// Exact deployed sampler executable bytes.
    pub observer_artifact_digest: Sha256Digest,
    /// Exact deployed sampler configuration bytes.
    pub observer_config_digest: Sha256Digest,
    /// Exact expected sample producer issuer.
    pub producer_issuer: String,
    /// Exact expected sample producer key identity.
    pub producer_key_id: String,
    /// SHA-256 digest of the expected Ed25519 public key bytes.
    pub producer_public_key_digest: Sha256Digest,
    /// Qualified execution-context identity for `available_parallelism()`.
    pub capacity_context_id: Sha256Digest,
}

/// Unsigned, immutable raw facts produced by the bounded passive sampler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveHostLoadSamplePayloadV1 {
    /// Must be [`crate::PASSIVE_HOST_LOAD_SAMPLE_PAYLOAD_SCHEMA_V1`].
    pub schema: String,
    /// Unique occurrence identity assigned by the observer.
    pub sample_occurrence_id: String,
    /// Exact independently configured subject, scope, and vantage.
    pub binding: SubjectBinding,
    /// Actual wall-clock sampling time, never retrieval or acquisition time.
    pub observed_at: DateTime<Utc>,
    /// Monotonic sequence within the finite append-only sample store.
    pub sequence: u64,
    /// Observer-process occurrence; restart creates a new value, not missed samples.
    pub observer_run_id: String,
    /// Exact closed observer profile.
    pub observer_profile: String,
    /// Exact deployed observer executable digest.
    pub observer_artifact_digest: Sha256Digest,
    /// Exact deployed observer configuration digest.
    pub observer_config_digest: Sha256Digest,
    /// Raw first token read from `/proc/loadavg`.
    pub load_1m_token: String,
    /// Exact value returned by Rust `available_parallelism()`.
    pub logical_cpu_count: u32,
    /// Fixed semantic source identifier for the two raw quantities.
    pub source_basis: String,
    /// Qualified execution context for `available_parallelism()` and local vantage.
    pub capacity_context_id: Sha256Digest,
}

/// Ed25519-authenticated passive host-load sample occurrence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPassiveHostLoadSampleV1 {
    /// Must be [`crate::SIGNED_PASSIVE_HOST_LOAD_SAMPLE_SCHEMA_V1`].
    pub schema: String,
    /// Exact raw facts and occurrence binding.
    pub payload: PassiveHostLoadSamplePayloadV1,
    /// Canonical SHA-256 digest of `payload`; this is the sample replay identity.
    pub payload_digest: Sha256Digest,
    /// Authenticated deployment-owned sample producer identity.
    pub producer_issuer: String,
    /// Exact producer key identity.
    pub producer_key_id: String,
    /// Lowercase hexadecimal Ed25519 signature over the payload digest bytes.
    pub signature: String,
}

impl PassiveHostLoadSamplePayloadV1 {
    /// Validate the closed raw-fact shape without assigning trust to it.
    ///
    /// # Errors
    ///
    /// Returns a stable explanatory string for malformed or semantically
    /// impossible sample fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != crate::PASSIVE_HOST_LOAD_SAMPLE_PAYLOAD_SCHEMA_V1 {
            return Err("unsupported passive host-load payload schema".into());
        }
        for (field, value) in [
            ("sample_occurrence_id", self.sample_occurrence_id.as_str()),
            ("observer_run_id", self.observer_run_id.as_str()),
            ("observer_profile", self.observer_profile.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(format!("{field} must contain 1 through 256 UTF-8 bytes"));
            }
        }
        if self.sequence == 0 {
            return Err("passive host-load sample sequence must be non-zero".into());
        }
        if self.observer_profile != "nq.host_load_passive_sampler.v1" {
            return Err("unsupported passive host-load observer profile".into());
        }
        if self.source_basis != "linux_proc_loadavg_plus_rust_available_parallelism_v1" {
            return Err("unsupported passive host-load source basis".into());
        }
        if self.load_1m_token.is_empty() || self.load_1m_token.len() > 64 {
            return Err("load_1m_token must contain 1 through 64 bytes".into());
        }
        let load = self
            .load_1m_token
            .parse::<f64>()
            .map_err(|error| format!("load_1m_token is not a decimal float: {error}"))?;
        if !load.is_finite() || load.is_sign_negative() {
            return Err("load_1m_token must be finite and non-negative".into());
        }
        if self.logical_cpu_count == 0 {
            return Err("logical_cpu_count must be non-zero".into());
        }
        Ok(())
    }
}

impl SignedPassiveHostLoadSampleV1 {
    /// Validate the content-derived occurrence identity and signed-envelope
    /// shape. Signature authenticity is verified by the admitted provider and
    /// independently by NQ against deployment-pinned key material.
    ///
    /// # Errors
    ///
    /// Returns a stable explanatory string on malformed or substituted input.
    pub fn validate_structure(&self) -> Result<(), String> {
        if self.schema != crate::SIGNED_PASSIVE_HOST_LOAD_SAMPLE_SCHEMA_V1 {
            return Err("unsupported signed passive host-load sample schema".into());
        }
        self.payload.validate()?;
        for (field, value) in [
            ("producer_issuer", self.producer_issuer.as_str()),
            ("producer_key_id", self.producer_key_id.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(format!("{field} must contain 1 through 256 UTF-8 bytes"));
            }
        }
        let expected = crate::semantic_digest(&self.payload)
            .map_err(|error| format!("passive sample payload cannot canonicalize: {error}"))?;
        if expected != self.payload_digest {
            return Err("passive sample payload digest was substituted".into());
        }
        if self.signature.len() != 128
            || self.signature != self.signature.to_ascii_lowercase()
            || !self.signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("passive sample signature must be 64 lowercase hexadecimal bytes".into());
        }
        Ok(())
    }
}

/// Overall completeness of a valid helper report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// All profile-required collection completed.
    Complete,
    /// Some usable testimony exists but declared coverage is incomplete.
    Partial,
    /// The exchange succeeded, but collection itself failed.
    Failed,
}

/// State of one controlled coverage dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// The declared coverage dimension was fully observed.
    Complete,
    /// Only part of the declared coverage dimension was observed.
    Partial,
    /// No testimony was obtained for the declared coverage dimension.
    Unavailable,
}

/// One profile-controlled coverage declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDeclaration {
    /// Coverage vocabulary entry.
    pub kind: CoverageKind,
    /// Optional child subject to which this declaration applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectId>,
    /// Explicit completeness state.
    pub state: CoverageState,
    /// Optional bounded profile-specific detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

/// One admitted-candidate profile observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Zero-based, contiguous position in this report.
    pub ordinal: u32,
    /// Profile-controlled observation vocabulary entry.
    pub kind: ObservationKind,
    /// Profile-validated subject identity.
    pub subject: SubjectId,
    /// Time at which the underlying condition was observed.
    pub observed_at: DateTime<Utc>,
    /// Strictly bounded and profile-validated typed payload.
    pub payload: Value,
}

/// Severity of a structured collection error within a valid report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    /// Degradation that did not itself fail collection.
    Warning,
    /// Collection error relevant to report completeness.
    Error,
}

/// Ordered, structured error emitted as testimony inside a valid report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportError {
    /// Profile-controlled machine-readable code.
    pub code: ErrorCode,
    /// Error or warning classification.
    pub severity: ErrorSeverity,
    /// Bounded operator-facing explanation.
    pub message: String,
    /// Related subject, if narrower than the report root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectId>,
    /// Related observation ordinal, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_ordinal: Option<u32>,
    /// Whether a later independent collection may reasonably succeed.
    pub retriable: bool,
}

/// Untrusted identity of a helper or backend tool involved in collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    /// Implementation or tool name.
    pub name: ImplementationName,
    /// Bounded version/build string, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Digest of opened bytes, if the helper can report one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Sha256Digest>,
}

/// Untrusted helper and backend provenance retained with a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendProvenance {
    /// Helper implementation lineage/build.
    pub implementation: BackendIdentity,
    /// Ordered identities of invoked backend tools.
    pub tools: Vec<BackendIdentity>,
}

/// Immutable helper testimony produced by a successful protocol exchange.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReport {
    /// Must be [`crate::EVIDENCE_REPORT_SCHEMA`].
    pub schema: String,
    /// Profile under which the helper says this report was produced.
    pub profile: ProfileBinding,
    /// Subject, scope, and vantage under which it was produced.
    pub binding: SubjectBinding,
    /// Time represented by the report as a whole.
    pub observed_at: DateTime<Utc>,
    /// Helper-declared report completeness, distinct from run success.
    pub status: ReportStatus,
    /// Complete set of controlled coverage declarations.
    pub coverage: Vec<CoverageDeclaration>,
    /// Ordered profile observations.
    pub observations: Vec<Observation>,
    /// Ordered structured errors and limitations.
    pub errors: Vec<ReportError>,
    /// Capability subset actually used by the helper.
    pub used_capabilities: Vec<Capability>,
    /// Untrusted implementation and backend lineage.
    pub backend: BackendProvenance,
    /// Candidate cursor that NQ advances only after admission and commit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_checkpoint: Option<Checkpoint>,
}

impl EvidenceReport {
    /// Creates a report builder with empty coverage, observations, and errors.
    #[must_use]
    pub fn builder(
        profile: ProfileBinding,
        binding: SubjectBinding,
        observed_at: DateTime<Utc>,
        status: ReportStatus,
        backend: BackendProvenance,
    ) -> crate::EvidenceReportBuilder {
        crate::EvidenceReportBuilder::new(profile, binding, observed_at, status, backend)
    }
}

/// Exact boundary at which a helper refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalBoundary {
    /// Wire protocol or version boundary.
    Protocol,
    /// Compiled profile identity or semantics boundary.
    Profile,
    /// Requested subject or scope boundary.
    Scope,
    /// Requested observation vantage boundary.
    Vantage,
    /// Granted capability boundary.
    Capability,
    /// Monotonic deadline boundary.
    Deadline,
    /// Polling checkpoint boundary.
    Checkpoint,
    /// Backend collection boundary.
    Collection,
    /// Negotiated resource/cardinality boundary.
    Resource,
    /// Unexpected helper implementation boundary.
    Internal,
}

/// Stable refusal reason vocabulary for helper protocol v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    /// The exact protocol version is unsupported.
    UnsupportedProtocol,
    /// The requested profile identifier/version is unsupported.
    UnknownProfile,
    /// The known profile's descriptor digest differs.
    ProfileDigestMismatch,
    /// The subject or scope cannot be honored.
    UnsupportedScope,
    /// The requested vantage cannot be honored.
    UnsupportedVantage,
    /// A required capability was not granted.
    CapabilityDenied,
    /// The deadline had expired or was too short to begin safely.
    DeadlineExpired,
    /// The negotiated bounds cannot be honored.
    BoundsUnsupported,
    /// The supplied checkpoint is invalid or no longer usable.
    CheckpointInvalid,
    /// The backend could not perform collection.
    CollectionFailed,
    /// A negotiated or local resource limit prevented collection.
    ResourceExhausted,
    /// The helper encountered an internal failure before making a report.
    InternalError,
}

/// Typed explanation returned instead of a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    /// Exact instance responsible for this refusal.
    pub responsible_instance_id: InstanceId,
    /// Exact boundary that could not proceed.
    pub boundary: RefusalBoundary,
    /// Stable machine-readable refusal reason.
    pub code: RefusalCode,
    /// Bounded operator-facing explanation.
    pub message: String,
    /// Whether a new independent request might succeed without re-admission.
    pub retriable: bool,
    /// Bounded structured diagnostic detail, never authority or remediation.
    pub details: Value,
}

/// Mutually exclusive helper outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum ResponseOutcome {
    /// Successful exchange containing an immutable report of any report status.
    Report {
        /// Helper report awaiting profile admission.
        report: EvidenceReport,
    },
    /// Typed refusal containing no report.
    Refusal {
        /// Exact refusal testimony.
        refusal: Refusal,
    },
}

/// Exactly one response emitted by a helper for one request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperResponse {
    /// Must be [`HELPER_RESPONSE_SCHEMA`].
    pub schema: String,
    /// Exact copy of all request-controlled fields.
    pub echo: RequestEcho,
    /// Either a report or a refusal, never both.
    pub outcome: ResponseOutcome,
}

impl HelperResponse {
    /// Wraps a report and creates an exact request echo.
    #[must_use]
    pub fn report(request: &HelperRequest, report: EvidenceReport) -> Self {
        Self {
            schema: HELPER_RESPONSE_SCHEMA.to_owned(),
            echo: RequestEcho::from(request),
            outcome: ResponseOutcome::Report { report },
        }
    }

    /// Wraps a refusal and creates an exact request echo.
    #[must_use]
    pub fn refusal(request: &HelperRequest, refusal: Refusal) -> Self {
        Self {
            schema: HELPER_RESPONSE_SCHEMA.to_owned(),
            echo: RequestEcho::from(request),
            outcome: ResponseOutcome::Refusal { refusal },
        }
    }
}

impl Default for MonotonicDeadline {
    fn default() -> Self {
        Self {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: 1,
        }
    }
}
