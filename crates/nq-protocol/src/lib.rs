//! Stable, language-neutral contracts between NQ and witness helpers.
//!
//! The wire format is one newline-terminated UTF-8 JSON document in each
//! direction. This crate deliberately contains no profile semantics: it checks
//! the common envelope, echo, capability, and negotiated-bound laws, while a
//! compiled profile module validates coverage and observation payloads.

mod builder;
mod canonical;
mod conformance;
mod framing;
mod ids;
mod model;
mod validation;

pub use builder::{EvidenceReportBuilder, HelperRequestBuilder};
pub use canonical::{
    CanonicalizationError, DigestParseError, Sha256Digest, canonical_json_bytes, semantic_digest,
    sha256_bytes,
};
pub use conformance::{
    CONFORMANCE_DIGEST_MANIFEST_SCHEMA, CONFORMANCE_MANIFEST_SCHEMA, CONFORMANCE_RECEIPT_SCHEMA,
    ConformanceError, ConformanceErrorCode, ConformancePhase, ConformanceReceipt,
    ConformanceVersionSummary, MAX_CONFORMANCE_ERROR_BYTES, MAX_CONFORMANCE_RECEIPT_BYTES,
    verify_embedded_conformance_corpus,
};
pub use framing::{FramingError, decode_ndjson, encode_ndjson, parse_request, parse_response};
pub use ids::{
    Capability, CoverageKind, ErrorCode, ImplementationName, InstanceId, ObservationKind,
    ProfileId, ProfileVersion, RequestId, ScopeKind, SubjectId, TokenError, VantageKind,
};
pub use model::{
    BackendIdentity, BackendProvenance, Checkpoint, CollectionBounds, CoverageDeclaration,
    CoverageState, ErrorSeverity, EvidenceReport, HelperRequest, HelperResponse, MonotonicClock,
    MonotonicDeadline, Observation, ProfileBinding, Refusal, RefusalBoundary, RefusalCode,
    ReportError, ReportStatus, RequestEcho, ResponseOutcome, ScopeBinding, SubjectBinding,
    VantageBinding,
};
pub use validation::{
    ValidationError, validate_exchange, validate_report, validate_request, validate_response,
};

/// The exact helper protocol version accepted by this release.
pub const HELPER_PROTOCOL_VERSION: &str = "nq.helper.v1";

/// The request document schema identifier.
pub const HELPER_REQUEST_SCHEMA: &str = "nq.helper.request.v1";

/// The response document schema identifier.
pub const HELPER_RESPONSE_SCHEMA: &str = "nq.helper.response.v1";

/// The evidence report document schema identifier.
pub const EVIDENCE_REPORT_SCHEMA: &str = "nq.evidence_report.v1";

/// Maximum request frame accepted by the SDK, including the final newline.
pub const MAX_REQUEST_FRAME_BYTES: usize = 1_048_576;

/// Protocol-wide ceiling for a negotiated response frame.
pub const MAX_RESPONSE_FRAME_BYTES: usize = 16 * 1_048_576;

/// Protocol-wide ceiling for observations in one report.
pub const MAX_OBSERVATIONS: usize = 65_535;

/// Protocol-wide ceiling for coverage declarations in one report.
pub const MAX_COVERAGE_ENTRIES: usize = 4_096;

/// Protocol-wide ceiling for ordered report errors in one report.
pub const MAX_REPORT_ERRORS: usize = 1_024;
