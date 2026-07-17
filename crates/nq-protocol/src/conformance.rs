//! Deterministic verification of the protocol's embedded conformance corpus.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    EvidenceReport, FramingError, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse,
    MAX_RESPONSE_FRAME_BYTES, ReportStatus, ResponseOutcome, Sha256Digest, ValidationError,
    decode_ndjson, parse_response, semantic_digest, sha256_bytes, validate_exchange,
    validate_report, validate_request, validate_response,
};

/// Schema identifier for a successful embedded-corpus verification receipt.
pub const CONFORMANCE_RECEIPT_SCHEMA: &str = "nq.protocol.conformance_receipt.v1";

/// Schema identifier declared by the shipped fixture manifest.
pub const CONFORMANCE_MANIFEST_SCHEMA: &str = "nq.protocol.conformance_manifest.v1";

/// Schema identifier for the deterministic, content-addressed manifest.
pub const CONFORMANCE_DIGEST_MANIFEST_SCHEMA: &str = "nq.protocol.conformance_digest_manifest.v1";

/// Maximum serialized size of a receipt returned by this module.
pub const MAX_CONFORMANCE_RECEIPT_BYTES: usize = 4 * 1_024;

/// Maximum serialized size of an error returned by this module.
pub const MAX_CONFORMANCE_ERROR_BYTES: usize = 2 * 1_024;

const MAX_SOURCE_MANIFEST_BYTES: usize = 32 * 1_024;
const MAX_FIXTURES: usize = 64;
const MAX_FIXTURE_PATH_BYTES: usize = 192;
const MAX_ERROR_DETAIL_BYTES: usize = 512;

const SOURCE_MANIFEST: &[u8] = include_bytes!("../../../protocol/fixtures/manifest.json");

const REQUEST_FIXTURE: Fixture = Fixture {
    path: "valid/request.ndjson",
    bytes: include_bytes!("../../../protocol/fixtures/valid/request.ndjson"),
};

const VALID_FIXTURES: &[ValidFixture] = &[
    ValidFixture {
        fixture: Fixture {
            path: "valid/evidence_report.ndjson",
            bytes: include_bytes!("../../../protocol/fixtures/valid/evidence_report.ndjson"),
        },
        expected: ValidExpectation::EvidenceReport,
    },
    ValidFixture {
        fixture: Fixture {
            path: "valid/response_report.ndjson",
            bytes: include_bytes!("../../../protocol/fixtures/valid/response_report.ndjson"),
        },
        expected: ValidExpectation::CompleteReportResponse,
    },
    ValidFixture {
        fixture: Fixture {
            path: "valid/response_refusal.ndjson",
            bytes: include_bytes!("../../../protocol/fixtures/valid/response_refusal.ndjson"),
        },
        expected: ValidExpectation::RefusalResponse,
    },
    ValidFixture {
        fixture: Fixture {
            path: "valid/response_failed_report.ndjson",
            bytes: include_bytes!("../../../protocol/fixtures/valid/response_failed_report.ndjson"),
        },
        expected: ValidExpectation::FailedReportResponse,
    },
];

const INVALID_FIXTURES: &[InvalidFixture] = &[
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/request_unknown_field.ndjson",
            bytes: include_bytes!(
                "../../../protocol/fixtures/invalid/request_unknown_field.ndjson"
            ),
        },
        phase: ConformancePhase::Decode,
        reason: InvalidReason::UnknownField,
    },
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/request_duplicate_key.ndjson",
            bytes: include_bytes!(
                "../../../protocol/fixtures/invalid/request_duplicate_key.ndjson"
            ),
        },
        phase: ConformancePhase::Decode,
        reason: InvalidReason::DuplicateKey,
    },
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/request_wrong_version.ndjson",
            bytes: include_bytes!(
                "../../../protocol/fixtures/invalid/request_wrong_version.ndjson"
            ),
        },
        phase: ConformancePhase::ProtocolValidation,
        reason: InvalidReason::WrongProtocolVersion,
    },
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/response_wrong_echo.ndjson",
            bytes: include_bytes!("../../../protocol/fixtures/invalid/response_wrong_echo.ndjson"),
        },
        phase: ConformancePhase::ExchangeValidation,
        reason: InvalidReason::WrongRequestEcho,
    },
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/response_capability_escape.ndjson",
            bytes: include_bytes!(
                "../../../protocol/fixtures/invalid/response_capability_escape.ndjson"
            ),
        },
        phase: ConformancePhase::ExchangeValidation,
        reason: InvalidReason::CapabilityEscape,
    },
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/response_failed_without_error.ndjson",
            bytes: include_bytes!(
                "../../../protocol/fixtures/invalid/response_failed_without_error.ndjson"
            ),
        },
        phase: ConformancePhase::ReportValidation,
        reason: InvalidReason::FailedWithoutError,
    },
    InvalidFixture {
        fixture: Fixture {
            path: "invalid/extra_frame.ndjson",
            bytes: include_bytes!("../../../protocol/fixtures/invalid/extra_frame.ndjson"),
        },
        phase: ConformancePhase::Framing,
        reason: InvalidReason::ExtraFrame,
    },
];

/// Version and content identity of the corpus that was actually checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceVersionSummary {
    /// Exact helper protocol version exercised by the corpus.
    pub protocol_version: String,
    /// Version of the content-addressed manifest format.
    pub manifest_schema: String,
    /// Package version of the verifier implementation.
    pub verifier_version: String,
    /// SHA-256 of the canonical content-addressed fixture manifest.
    pub corpus_digest: Sha256Digest,
}

/// Bounded, deterministic receipt proving that every embedded check passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReceipt {
    /// Must be [`CONFORMANCE_RECEIPT_SCHEMA`].
    pub schema: String,
    /// Version and content identity of the verified corpus.
    pub version: ConformanceVersionSummary,
    /// Total number of embedded frames checked, including the base request.
    pub fixtures_checked: u16,
    /// Number of valid frames accepted, including the base request.
    pub valid_fixtures_accepted: u16,
    /// Number of invalid frames rejected for their declared reason.
    pub invalid_fixtures_rejected: u16,
}

/// Broad conformance boundary exercised by a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformancePhase {
    /// Fixture-manifest decoding and inventory agreement.
    Manifest,
    /// Exactly-one-frame and newline framing.
    Framing,
    /// Strict JSON/DTO decoding, including duplicate and unknown keys.
    Decode,
    /// Exact request/protocol validation.
    ProtocolValidation,
    /// Common report lifecycle validation.
    ReportValidation,
    /// Exact request/response exchange validation.
    ExchangeValidation,
    /// Expected valid outcome classification.
    OutcomeValidation,
    /// Canonical digest or receipt-size validation.
    Receipt,
}

impl ConformancePhase {
    const fn manifest_name(self) -> Option<&'static str> {
        match self {
            Self::Framing => Some("framing"),
            Self::Decode => Some("decode"),
            Self::ProtocolValidation => Some("protocol_validation"),
            Self::ReportValidation => Some("report_validation"),
            Self::ExchangeValidation => Some("exchange_validation"),
            Self::Manifest | Self::OutcomeValidation | Self::Receipt => None,
        }
    }
}

/// Stable category for a conformance verifier failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceErrorCode {
    /// The embedded manifest was malformed or disagreed with compiled entries.
    ManifestInvalid,
    /// A fixture declared valid failed validation.
    ValidFixtureRejected,
    /// A fixture declared invalid was accepted.
    InvalidFixtureAccepted,
    /// An invalid fixture failed, but not for its declared reason.
    InvalidFixtureWrongReason,
    /// The deterministic manifest could not be canonicalized or hashed.
    DigestFailed,
    /// A verifier result exceeded its fixed serialized bound.
    ResultTooLarge,
}

/// Bounded, serializable failure from embedded-corpus verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Error)]
#[error("conformance {code:?} at {phase:?}: {detail}")]
#[serde(deny_unknown_fields)]
pub struct ConformanceError {
    /// Stable machine-readable failure category.
    pub code: ConformanceErrorCode,
    /// Boundary at which verification failed.
    pub phase: ConformancePhase,
    /// Corpus-relative fixture path, when one fixture is responsible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixture: Option<String>,
    /// Bounded diagnostic text.
    pub detail: String,
}

impl ConformanceError {
    fn new(
        code: ConformanceErrorCode,
        phase: ConformancePhase,
        fixture: Option<&str>,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            code,
            phase,
            fixture: fixture.map(|path| truncate(path, MAX_FIXTURE_PATH_BYTES)),
            detail: truncate(detail.as_ref(), MAX_ERROR_DETAIL_BYTES),
        }
    }
}

/// Verifies every embedded valid and invalid fixture and returns its identity.
///
/// The returned value is deterministic: it deliberately contains no clock or
/// machine identity. The corpus digest covers the ordered fixture inventory,
/// each expectation, and the SHA-256 identity of every embedded frame.
///
/// # Errors
///
/// Returns a bounded [`ConformanceError`] if the shipped manifest disagrees
/// with the embedded inventory, a valid fixture is rejected, an invalid
/// fixture is accepted or rejected at the wrong boundary, or result
/// canonicalization exceeds a fixed bound.
pub fn verify_embedded_conformance_corpus() -> Result<ConformanceReceipt, ConformanceError> {
    verify_source_manifest()?;

    let request = verify_request_fixture(REQUEST_FIXTURE)?;
    for fixture in VALID_FIXTURES {
        verify_valid_fixture(&request, *fixture)?;
    }
    for fixture in INVALID_FIXTURES {
        verify_invalid_fixture(&request, *fixture)?;
    }

    let digest = digest_manifest()?;
    let valid_count = 1_usize + VALID_FIXTURES.len();
    let total_count = valid_count + INVALID_FIXTURES.len();
    let receipt = ConformanceReceipt {
        schema: CONFORMANCE_RECEIPT_SCHEMA.to_owned(),
        version: ConformanceVersionSummary {
            protocol_version: HELPER_PROTOCOL_VERSION.to_owned(),
            manifest_schema: CONFORMANCE_DIGEST_MANIFEST_SCHEMA.to_owned(),
            verifier_version: env!("CARGO_PKG_VERSION").to_owned(),
            corpus_digest: digest,
        },
        fixtures_checked: checked_u16(total_count)?,
        valid_fixtures_accepted: checked_u16(valid_count)?,
        invalid_fixtures_rejected: checked_u16(INVALID_FIXTURES.len())?,
    };
    ensure_serialized_bound(
        &receipt,
        MAX_CONFORMANCE_RECEIPT_BYTES,
        ConformancePhase::Receipt,
    )?;
    Ok(receipt)
}

#[derive(Clone, Copy)]
struct Fixture {
    path: &'static str,
    bytes: &'static [u8],
}

#[derive(Clone, Copy)]
struct ValidFixture {
    fixture: Fixture,
    expected: ValidExpectation,
}

#[derive(Clone, Copy)]
enum ValidExpectation {
    EvidenceReport,
    CompleteReportResponse,
    RefusalResponse,
    FailedReportResponse,
}

impl ValidExpectation {
    const fn manifest_document(self) -> &'static str {
        match self {
            Self::EvidenceReport => "evidence_report",
            Self::CompleteReportResponse | Self::RefusalResponse | Self::FailedReportResponse => {
                "response"
            }
        }
    }

    const fn manifest_outcome(self) -> Option<&'static str> {
        match self {
            Self::EvidenceReport => None,
            Self::CompleteReportResponse => Some("report"),
            Self::RefusalResponse => Some("refusal"),
            Self::FailedReportResponse => Some("failed_report"),
        }
    }

    const fn digest_expectation(self) -> &'static str {
        match self {
            Self::EvidenceReport => "accept_evidence_report",
            Self::CompleteReportResponse => "accept_complete_report_response",
            Self::RefusalResponse => "accept_refusal_response",
            Self::FailedReportResponse => "accept_failed_report_response",
        }
    }
}

#[derive(Clone, Copy)]
struct InvalidFixture {
    fixture: Fixture,
    phase: ConformancePhase,
    reason: InvalidReason,
}

#[derive(Clone, Copy)]
enum InvalidReason {
    UnknownField,
    DuplicateKey,
    WrongProtocolVersion,
    WrongRequestEcho,
    CapabilityEscape,
    FailedWithoutError,
    ExtraFrame,
}

impl InvalidReason {
    const fn digest_expectation(self) -> &'static str {
        match self {
            Self::UnknownField => "reject_unknown_field",
            Self::DuplicateKey => "reject_duplicate_key",
            Self::WrongProtocolVersion => "reject_wrong_protocol_version",
            Self::WrongRequestEcho => "reject_wrong_request_echo",
            Self::CapabilityEscape => "reject_capability_escape",
            Self::FailedWithoutError => "reject_failed_report_without_error",
            Self::ExtraFrame => "reject_extra_frame",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    schema: String,
    request: String,
    valid: Vec<SourceValidEntry>,
    invalid: Vec<SourceInvalidEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceValidEntry {
    path: String,
    document: String,
    #[serde(default)]
    outcome: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInvalidEntry {
    path: String,
    phase: String,
}

fn verify_source_manifest() -> Result<(), ConformanceError> {
    if SOURCE_MANIFEST.len() > MAX_SOURCE_MANIFEST_BYTES {
        return Err(ConformanceError::new(
            ConformanceErrorCode::ManifestInvalid,
            ConformancePhase::Manifest,
            None,
            "embedded source manifest exceeds its byte bound",
        ));
    }
    let manifest: SourceManifest = serde_json::from_slice(SOURCE_MANIFEST).map_err(|error| {
        ConformanceError::new(
            ConformanceErrorCode::ManifestInvalid,
            ConformancePhase::Manifest,
            None,
            format!("cannot decode embedded source manifest: {error}"),
        )
    })?;
    if manifest.schema != CONFORMANCE_MANIFEST_SCHEMA {
        return Err(manifest_mismatch(
            "manifest schema does not match this release",
        ));
    }
    if manifest.request != REQUEST_FIXTURE.path {
        return Err(manifest_mismatch(
            "base request path does not match inventory",
        ));
    }
    if manifest.valid.len() != VALID_FIXTURES.len()
        || manifest.invalid.len() != INVALID_FIXTURES.len()
    {
        return Err(manifest_mismatch(
            "fixture counts do not match the embedded inventory",
        ));
    }
    let total = 1 + manifest.valid.len() + manifest.invalid.len();
    if total > MAX_FIXTURES {
        return Err(manifest_mismatch("fixture count exceeds verifier bound"));
    }

    let mut paths = BTreeSet::new();
    validate_manifest_path(&manifest.request, &mut paths)?;
    for (actual, expected) in manifest.valid.iter().zip(VALID_FIXTURES) {
        validate_manifest_path(&actual.path, &mut paths)?;
        if actual.path != expected.fixture.path
            || actual.document != expected.expected.manifest_document()
            || actual.outcome.as_deref() != expected.expected.manifest_outcome()
        {
            return Err(manifest_mismatch(
                "valid fixture metadata does not match the embedded inventory",
            ));
        }
    }
    for (actual, expected) in manifest.invalid.iter().zip(INVALID_FIXTURES) {
        validate_manifest_path(&actual.path, &mut paths)?;
        if actual.path != expected.fixture.path
            || Some(actual.phase.as_str()) != expected.phase.manifest_name()
        {
            return Err(manifest_mismatch(
                "invalid fixture metadata does not match the embedded inventory",
            ));
        }
    }
    Ok(())
}

fn validate_manifest_path(
    path: &str,
    paths: &mut BTreeSet<String>,
) -> Result<(), ConformanceError> {
    let safe = !path.is_empty()
        && path.len() <= MAX_FIXTURE_PATH_BYTES
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if !safe || !paths.insert(path.to_owned()) {
        return Err(manifest_mismatch(
            "fixture paths must be unique, bounded, relative, and normalized",
        ));
    }
    Ok(())
}

fn manifest_mismatch(detail: &str) -> ConformanceError {
    ConformanceError::new(
        ConformanceErrorCode::ManifestInvalid,
        ConformancePhase::Manifest,
        None,
        detail,
    )
}

fn verify_request_fixture(fixture: Fixture) -> Result<HelperRequest, ConformanceError> {
    let request: HelperRequest = decode_ndjson(fixture.bytes, crate::MAX_REQUEST_FRAME_BYTES)
        .map_err(|error| valid_rejected(fixture.path, phase_for_framing(&error, true), &error))?;
    validate_request(&request).map_err(|error| {
        valid_rejected(fixture.path, ConformancePhase::ProtocolValidation, &error)
    })?;
    Ok(request)
}

fn verify_valid_fixture(
    request: &HelperRequest,
    fixture: ValidFixture,
) -> Result<(), ConformanceError> {
    match fixture.expected {
        ValidExpectation::EvidenceReport => {
            let report: EvidenceReport =
                decode_ndjson(fixture.fixture.bytes, MAX_RESPONSE_FRAME_BYTES).map_err(
                    |error| {
                        valid_rejected(
                            fixture.fixture.path,
                            phase_for_framing(&error, false),
                            &error,
                        )
                    },
                )?;
            validate_report(&report).map_err(|error| {
                valid_rejected(
                    fixture.fixture.path,
                    ConformancePhase::ReportValidation,
                    &error,
                )
            })?;
            if report.status != ReportStatus::Complete {
                return Err(valid_rejected_text(
                    fixture.fixture.path,
                    ConformancePhase::OutcomeValidation,
                    "standalone fixture is not a complete report",
                ));
            }
        }
        expected => {
            let response = parse_response(request, fixture.fixture.bytes).map_err(|error| {
                valid_rejected(
                    fixture.fixture.path,
                    phase_for_response_error(&error),
                    &error,
                )
            })?;
            let outcome_matches = match (expected, &response.outcome) {
                (ValidExpectation::CompleteReportResponse, ResponseOutcome::Report { report }) => {
                    report.status == ReportStatus::Complete
                }
                (ValidExpectation::FailedReportResponse, ResponseOutcome::Report { report }) => {
                    report.status == ReportStatus::Failed
                }
                (ValidExpectation::RefusalResponse, ResponseOutcome::Refusal { .. }) => true,
                _ => false,
            };
            if !outcome_matches {
                return Err(valid_rejected_text(
                    fixture.fixture.path,
                    ConformancePhase::OutcomeValidation,
                    "response outcome does not match the manifest",
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn verify_invalid_fixture(
    request: &HelperRequest,
    fixture: InvalidFixture,
) -> Result<(), ConformanceError> {
    let path = fixture.fixture.path;
    let bytes = fixture.fixture.bytes;
    match fixture.reason {
        InvalidReason::UnknownField | InvalidReason::DuplicateKey => {
            match decode_ndjson::<HelperRequest>(bytes, crate::MAX_REQUEST_FRAME_BYTES) {
                Err(FramingError::Json(error)) => {
                    let message = error.to_string();
                    let expected_fragment = match fixture.reason {
                        InvalidReason::UnknownField => "unknown field",
                        InvalidReason::DuplicateKey => "duplicate object key",
                        _ => unreachable!("matched decode reasons"),
                    };
                    if message.contains(expected_fragment) {
                        Ok(())
                    } else {
                        Err(invalid_wrong_reason(
                            path,
                            ConformancePhase::Decode,
                            format!("decode failed for a different reason: {message}"),
                        ))
                    }
                }
                Err(error) => Err(invalid_wrong_reason(
                    path,
                    phase_for_framing(&error, true),
                    error.to_string(),
                )),
                Ok(_) => Err(invalid_accepted(path, fixture.phase)),
            }
        }
        InvalidReason::WrongProtocolVersion => {
            let document: HelperRequest = decode_ndjson(bytes, crate::MAX_REQUEST_FRAME_BYTES)
                .map_err(|error| {
                    invalid_wrong_reason(path, phase_for_framing(&error, true), error.to_string())
                })?;
            match validate_request(&document) {
                Err(ValidationError::InvalidProtocolVersion { .. }) => Ok(()),
                Err(error) => Err(invalid_wrong_reason(
                    path,
                    ConformancePhase::ProtocolValidation,
                    error.to_string(),
                )),
                Ok(()) => Err(invalid_accepted(path, fixture.phase)),
            }
        }
        InvalidReason::WrongRequestEcho | InvalidReason::CapabilityEscape => {
            let response: HelperResponse = decode_ndjson(
                bytes,
                request.bounds.max_response_bytes as usize,
            )
            .map_err(|error| {
                invalid_wrong_reason(path, phase_for_framing(&error, false), error.to_string())
            })?;
            validate_response(&response).map_err(|error| {
                invalid_wrong_reason(path, ConformancePhase::ReportValidation, error.to_string())
            })?;
            match (fixture.reason, validate_exchange(request, &response)) {
                (
                    InvalidReason::WrongRequestEcho,
                    Err(ValidationError::EchoMismatch {
                        field: "echo.request_id",
                    }),
                )
                | (InvalidReason::CapabilityEscape, Err(ValidationError::CapabilityEscape(_))) => {
                    Ok(())
                }
                (_, Err(error)) => Err(invalid_wrong_reason(
                    path,
                    ConformancePhase::ExchangeValidation,
                    error.to_string(),
                )),
                (_, Ok(())) => Err(invalid_accepted(path, fixture.phase)),
            }
        }
        InvalidReason::FailedWithoutError => {
            let response: HelperResponse = decode_ndjson(
                bytes,
                request.bounds.max_response_bytes as usize,
            )
            .map_err(|error| {
                invalid_wrong_reason(path, phase_for_framing(&error, false), error.to_string())
            })?;
            let ResponseOutcome::Report { report } = &response.outcome else {
                return Err(invalid_wrong_reason(
                    path,
                    ConformancePhase::OutcomeValidation,
                    "fixture returned a refusal instead of a failed report",
                ));
            };
            match validate_report(report) {
                Err(ValidationError::InvalidField {
                    field: "report.status",
                    ..
                }) => Ok(()),
                Err(error) => Err(invalid_wrong_reason(
                    path,
                    ConformancePhase::ReportValidation,
                    error.to_string(),
                )),
                Ok(()) => Err(invalid_accepted(path, fixture.phase)),
            }
        }
        InvalidReason::ExtraFrame => {
            match decode_ndjson::<Value>(bytes, MAX_RESPONSE_FRAME_BYTES) {
                Err(FramingError::NotExactlyOneLine) => Ok(()),
                Err(error) => Err(invalid_wrong_reason(
                    path,
                    phase_for_framing(&error, false),
                    error.to_string(),
                )),
                Ok(_) => Err(invalid_accepted(path, fixture.phase)),
            }
        }
    }
}

fn valid_rejected(
    path: &str,
    phase: ConformancePhase,
    error: &impl std::fmt::Display,
) -> ConformanceError {
    valid_rejected_text(path, phase, error.to_string())
}

fn valid_rejected_text(
    path: &str,
    phase: ConformancePhase,
    detail: impl AsRef<str>,
) -> ConformanceError {
    ConformanceError::new(
        ConformanceErrorCode::ValidFixtureRejected,
        phase,
        Some(path),
        detail,
    )
}

fn invalid_accepted(path: &str, phase: ConformancePhase) -> ConformanceError {
    ConformanceError::new(
        ConformanceErrorCode::InvalidFixtureAccepted,
        phase,
        Some(path),
        "fixture declared invalid was accepted",
    )
}

fn invalid_wrong_reason(
    path: &str,
    actual_phase: ConformancePhase,
    detail: impl AsRef<str>,
) -> ConformanceError {
    ConformanceError::new(
        ConformanceErrorCode::InvalidFixtureWrongReason,
        actual_phase,
        Some(path),
        detail,
    )
}

fn phase_for_framing(error: &FramingError, request: bool) -> ConformancePhase {
    match error {
        FramingError::TooLarge { .. } | FramingError::NotExactlyOneLine => {
            ConformancePhase::Framing
        }
        FramingError::Json(_) => ConformancePhase::Decode,
        FramingError::Validation(_) if request => ConformancePhase::ProtocolValidation,
        FramingError::Validation(_) => ConformancePhase::ReportValidation,
        FramingError::Canonicalization(_) => ConformancePhase::Receipt,
    }
}

fn phase_for_response_error(error: &FramingError) -> ConformancePhase {
    match error {
        FramingError::Validation(
            ValidationError::EchoMismatch { .. } | ValidationError::CapabilityEscape(_),
        ) => ConformancePhase::ExchangeValidation,
        _ => phase_for_framing(error, false),
    }
}

#[derive(Serialize)]
struct DigestManifest {
    schema: &'static str,
    protocol_version: &'static str,
    fixtures: Vec<DigestManifestEntry>,
}

#[derive(Serialize)]
struct DigestManifestEntry {
    path: &'static str,
    expectation: &'static str,
    content_digest: Sha256Digest,
}

fn digest_manifest() -> Result<Sha256Digest, ConformanceError> {
    let mut fixtures = Vec::with_capacity(1 + VALID_FIXTURES.len() + INVALID_FIXTURES.len());
    fixtures.push(DigestManifestEntry {
        path: REQUEST_FIXTURE.path,
        expectation: "accept_request",
        content_digest: sha256_bytes(REQUEST_FIXTURE.bytes),
    });
    fixtures.extend(VALID_FIXTURES.iter().map(|fixture| DigestManifestEntry {
        path: fixture.fixture.path,
        expectation: fixture.expected.digest_expectation(),
        content_digest: sha256_bytes(fixture.fixture.bytes),
    }));
    fixtures.extend(INVALID_FIXTURES.iter().map(|fixture| DigestManifestEntry {
        path: fixture.fixture.path,
        expectation: fixture.reason.digest_expectation(),
        content_digest: sha256_bytes(fixture.fixture.bytes),
    }));
    semantic_digest(&DigestManifest {
        schema: CONFORMANCE_DIGEST_MANIFEST_SCHEMA,
        protocol_version: HELPER_PROTOCOL_VERSION,
        fixtures,
    })
    .map_err(|error| {
        ConformanceError::new(
            ConformanceErrorCode::DigestFailed,
            ConformancePhase::Receipt,
            None,
            error.to_string(),
        )
    })
}

fn checked_u16(value: usize) -> Result<u16, ConformanceError> {
    u16::try_from(value).map_err(|_| {
        ConformanceError::new(
            ConformanceErrorCode::ResultTooLarge,
            ConformancePhase::Receipt,
            None,
            "fixture count cannot be represented by the receipt",
        )
    })
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    bound: usize,
    phase: ConformancePhase,
) -> Result<(), ConformanceError> {
    let actual = serde_json::to_vec(value).map_err(|error| {
        ConformanceError::new(
            ConformanceErrorCode::DigestFailed,
            phase,
            None,
            error.to_string(),
        )
    })?;
    if actual.len() > bound {
        return Err(ConformanceError::new(
            ConformanceErrorCode::ResultTooLarge,
            phase,
            None,
            format!(
                "serialized result is {} bytes; limit is {bound}",
                actual.len()
            ),
        ));
    }
    Ok(())
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes.saturating_sub(3).min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut bounded = value[..end].to_owned();
    bounded.push_str("...");
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_corpus_is_verified_and_receipt_is_bounded() {
        let first = verify_embedded_conformance_corpus().expect("shipped corpus");
        let second = verify_embedded_conformance_corpus().expect("deterministic rerun");
        assert_eq!(first, second);
        assert_eq!(first.fixtures_checked, 12);
        assert_eq!(first.valid_fixtures_accepted, 5);
        assert_eq!(first.invalid_fixtures_rejected, 7);
        assert!(first.version.corpus_digest.as_str().starts_with("sha256:"));
        assert!(serde_json::to_vec(&first).unwrap().len() <= MAX_CONFORMANCE_RECEIPT_BYTES);
    }

    #[test]
    fn verifier_rejects_a_broken_valid_fixture() {
        let request = verify_request_fixture(REQUEST_FIXTURE).unwrap();
        let fixture = ValidFixture {
            fixture: Fixture {
                path: "valid/broken.ndjson",
                bytes: b"{}\n",
            },
            expected: ValidExpectation::EvidenceReport,
        };
        let error = verify_valid_fixture(&request, fixture).unwrap_err();
        assert_eq!(error.code, ConformanceErrorCode::ValidFixtureRejected);
        assert_eq!(error.phase, ConformancePhase::Decode);
        assert!(serde_json::to_vec(&error).unwrap().len() <= MAX_CONFORMANCE_ERROR_BYTES);
    }

    #[test]
    fn verifier_does_not_accept_a_valid_frame_as_an_invalid_fixture() {
        let request = verify_request_fixture(REQUEST_FIXTURE).unwrap();
        let fixture = InvalidFixture {
            fixture: REQUEST_FIXTURE,
            phase: ConformancePhase::ProtocolValidation,
            reason: InvalidReason::WrongProtocolVersion,
        };
        let error = verify_invalid_fixture(&request, fixture).unwrap_err();
        assert_eq!(error.code, ConformanceErrorCode::InvalidFixtureAccepted);
    }

    #[test]
    fn diagnostics_are_utf8_safe_and_bounded() {
        let input = "🦀".repeat(MAX_ERROR_DETAIL_BYTES);
        let error = ConformanceError::new(
            ConformanceErrorCode::ManifestInvalid,
            ConformancePhase::Manifest,
            Some(&input),
            &input,
        );
        assert!(error.detail.len() <= MAX_ERROR_DETAIL_BYTES);
        assert!(error.fixture.unwrap().len() <= MAX_FIXTURE_PATH_BYTES);
    }
}
