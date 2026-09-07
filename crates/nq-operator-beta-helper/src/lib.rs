//! Bounded one-shot acquisition for the operator-beta systemd and HTTP profiles.
//!
//! This crate owns testimony only. Scheduling, admission, evaluation, durable
//! custody, retry, and cross-profile composition remain with their existing
//! owners.

mod http;
mod systemd;

use std::io::{self, Read, Write};

use chrono::{Duration, Utc};
use nix::time::{ClockId, clock_gettime};
use nq_profiles::{
    EvidenceBasis, ProfileModule, ReportInput, ScopeGrant, ValidationContext, VantageGrant,
    http_endpoint, systemd_unit,
};
use nq_protocol::{
    BackendIdentity, BackendProvenance, Capability, CoverageDeclaration, CoverageKind,
    CoverageState, ErrorCode, ErrorSeverity, EvidenceReport, FramingError, HelperRequest,
    HelperResponse, ImplementationName, MAX_REQUEST_FRAME_BYTES, ObservationKind, Refusal,
    RefusalBoundary, RefusalCode, ReportError, ReportStatus, encode_ndjson, parse_request,
    validate_exchange,
};
use serde_json::{Value, json};
use thiserror::Error;

const MIN_RESPONSE_BYTES: u32 = 32_768;
const MIN_PAYLOAD_BYTES: u32 = 16_384;
const SYSTEMD_CAPABILITY: &str = "read_systemd_unit";
const HTTP_CAPABILITY: &str = "read_http_endpoint";

/// Failure before a valid bounded response can be written.
#[derive(Debug, Error)]
pub enum StdioError {
    /// Reading the one request frame failed.
    #[error("cannot read request: {0}")]
    Read(#[source] io::Error),
    /// The input exceeded the protocol request-frame ceiling.
    #[error("request frame exceeds {MAX_REQUEST_FRAME_BYTES} bytes")]
    RequestTooLarge,
    /// The input was not one strict, valid protocol request.
    #[error("invalid request: {0}")]
    InvalidRequest(#[source] FramingError),
    /// No protocol-valid response fit the request's negotiated response bound.
    #[error("cannot construct a bounded response: {0}")]
    UnrepresentableResponse(String),
    /// Writing the response frame failed.
    #[error("cannot write response: {0}")]
    Write(#[source] io::Error),
}

/// Runs one strict request/response exchange over standard input/output.
///
/// # Errors
///
/// Returns [`StdioError`] when no echoable request exists, no bounded response
/// can be represented, or standard I/O fails.
pub fn run_stdio() -> Result<(), StdioError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run(stdin.lock(), stdout.lock())
}

/// Runs one strict request/response exchange over supplied streams.
///
/// This is public only for carrier qualification. It neither schedules nor
/// persists work.
///
/// # Errors
///
/// Returns [`StdioError`] under the same conditions as [`run_stdio`].
pub fn run(mut input: impl Read, mut output: impl Write) -> Result<(), StdioError> {
    let request_bytes = read_request_frame(&mut input)?;
    let request = parse_request(&request_bytes).map_err(StdioError::InvalidRequest)?;
    let clock = LinuxBoottimeClock;
    let response = handle_request(&request, &RealSource, &clock);
    let response = ensure_bounded_response(&request, response)?;
    let frame = encode_ndjson(&response)
        .map_err(|error| StdioError::UnrepresentableResponse(format!("{error:?}")))?;
    output.write_all(&frame).map_err(StdioError::Write)?;
    output.flush().map_err(StdioError::Write)
}

fn read_request_frame(input: &mut impl Read) -> Result<Vec<u8>, StdioError> {
    let limit = u64::try_from(MAX_REQUEST_FRAME_BYTES)
        .expect("request bound fits u64")
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(MAX_REQUEST_FRAME_BYTES.min(8 * 1_024));
    input
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(StdioError::Read)?;
    if bytes.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(StdioError::RequestTooLarge);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Branch {
    Systemd,
    Http,
}

impl Branch {
    fn module(self) -> &'static dyn ProfileModule {
        match self {
            Self::Systemd => &systemd_unit::MODULE,
            Self::Http => &http_endpoint::MODULE,
        }
    }

    fn capability(self) -> &'static str {
        match self {
            Self::Systemd => SYSTEMD_CAPABILITY,
            Self::Http => HTTP_CAPABILITY,
        }
    }

    fn coverage(self) -> &'static str {
        match self {
            Self::Systemd => "systemd_unit_state",
            Self::Http => "http_endpoint_response",
        }
    }

    fn observation(self) -> &'static str {
        match self {
            Self::Systemd => "systemd_unit_snapshot",
            Self::Http => "http_response",
        }
    }
}

struct RealSource;

trait AcquisitionSource {
    fn acquire(
        &self,
        branch: Branch,
        request: &HelperRequest,
        clock: &impl DeadlineClock,
    ) -> Result<Value, CollectionFailure>;
}

impl AcquisitionSource for RealSource {
    fn acquire(
        &self,
        branch: Branch,
        request: &HelperRequest,
        clock: &impl DeadlineClock,
    ) -> Result<Value, CollectionFailure> {
        match branch {
            Branch::Systemd => systemd::acquire(request, clock),
            Branch::Http => http::acquire(request, clock),
        }
    }
}

#[derive(Debug)]
struct CollectionFailure {
    code: &'static str,
    message: String,
    retriable: bool,
}

impl CollectionFailure {
    fn new(code: &'static str, message: impl Into<String>, retriable: bool) -> Self {
        Self {
            code,
            message: bounded_message(&message.into(), 768),
            retriable,
        }
    }
}

fn handle_request(
    request: &HelperRequest,
    source: &impl AcquisitionSource,
    clock: &impl DeadlineClock,
) -> HelperResponse {
    let branch = match validate_helper_request(request, clock) {
        Ok(branch) => branch,
        Err(response) => return response,
    };
    let report = match source.acquire(branch, request, clock) {
        Ok(payload) => complete_report(request, branch, payload),
        Err(failure) => failed_report(request, branch, failure),
    };
    match report {
        Ok(report) => match validate_compiled_report(request, branch, &report) {
            Ok(()) => HelperResponse::report(request, report),
            Err(error) => internal_refusal(
                request,
                "collected testimony failed its compiled profile contract",
                json!({"validation_error": bounded_message(&error, 1024)}),
            ),
        },
        Err(error) => internal_refusal(
            request,
            "helper could not construct bounded testimony",
            json!({"error": bounded_message(&error, 1024)}),
        ),
    }
}

#[allow(clippy::too_many_lines, clippy::result_large_err)]
fn validate_helper_request(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<Branch, HelperResponse> {
    let branch = match (
        request.profile.id.as_str(),
        request.profile.version.as_str(),
    ) {
        (systemd_unit::PROFILE_ID, "1") => Branch::Systemd,
        (http_endpoint::PROFILE_ID, "1") => Branch::Http,
        _ => {
            return Err(refusal(
                request,
                RefusalBoundary::Profile,
                RefusalCode::UnknownProfile,
                "this helper implements only nq.systemd_unit/v1 and nq.http_endpoint/v1",
                false,
                json!({}),
            ));
        }
    };
    let module = branch.module();
    let digest = match module.descriptor().digest() {
        Ok(digest) => digest,
        Err(error) => {
            return Err(internal_refusal(
                request,
                "compiled profile descriptor could not be identified",
                json!({"error": bounded_message(&format!("{error:?}"), 1024)}),
            ));
        }
    };
    if request.profile.digest.as_str() != digest.as_str() {
        return Err(refusal(
            request,
            RefusalBoundary::Profile,
            RefusalCode::ProfileDigestMismatch,
            "requested profile digest differs from the compiled descriptor",
            false,
            json!({"compiled_digest": digest.as_str()}),
        ));
    }
    if request.checkpoint.is_some() {
        return Err(refusal(
            request,
            RefusalBoundary::Checkpoint,
            RefusalCode::CheckpointInvalid,
            "operator-beta observations do not accept polling checkpoints",
            false,
            json!({}),
        ));
    }
    let exact_capability = request.granted_capabilities.len() == 1
        && request.granted_capabilities[0].as_str() == branch.capability();
    if !exact_capability {
        return Err(refusal(
            request,
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
            "request must grant exactly the one capability compiled for this profile",
            false,
            json!({"required_capability": branch.capability()}),
        ));
    }
    let bounds = &request.bounds;
    if bounds.max_observations < 1
        || bounds.max_coverage_entries < 1
        || bounds.max_payload_bytes < MIN_PAYLOAD_BYTES
        || bounds.max_report_errors < 1
        || bounds.max_response_bytes < MIN_RESPONSE_BYTES
    {
        return Err(refusal(
            request,
            RefusalBoundary::Resource,
            RefusalCode::BoundsUnsupported,
            "negotiated bounds cannot represent operator-beta testimony",
            false,
            json!({
                "minimum_observations": 1,
                "minimum_coverage_entries": 1,
                "minimum_payload_bytes": MIN_PAYLOAD_BYTES,
                "minimum_report_errors": 1,
                "minimum_response_bytes": MIN_RESPONSE_BYTES,
            }),
        ));
    }
    let now = match clock.now_ns() {
        Ok(now) => now,
        Err(error) => {
            return Err(internal_refusal(
                request,
                "Linux boot-time clock could not be read",
                json!({"error": bounded_message(&error, 1024)}),
            ));
        }
    };
    if now >= request.deadline.expires_at_ns {
        return Err(refusal(
            request,
            RefusalBoundary::Deadline,
            RefusalCode::DeadlineExpired,
            "monotonic request deadline expired before collection began",
            true,
            json!({}),
        ));
    }
    let context = ValidationContext::from_request(request, Utc::now(), Duration::seconds(5));
    module.validate_binding(&context).map_err(|error| {
        refusal(
            request,
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
            "request binding is outside the compiled profile",
            false,
            json!({"profile_error": bounded_message(&format!("{error:?}"), 1024)}),
        )
    })?;
    Ok(branch)
}

fn complete_report(
    request: &HelperRequest,
    branch: Branch,
    payload: Value,
) -> Result<EvidenceReport, String> {
    let observed_at = Utc::now();
    EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        observed_at,
        ReportStatus::Complete,
        backend_provenance()?,
    )
    .coverage(CoverageDeclaration {
        kind: token(CoverageKind::new(branch.coverage()))?,
        subject: None,
        state: CoverageState::Complete,
        detail: None,
    })
    .observed_payload(
        token(ObservationKind::new(branch.observation()))?,
        request.binding.subject.clone(),
        observed_at,
        payload,
    )
    .used_capability(token(Capability::new(branch.capability()))?)
    .build()
    .map_err(|error| format!("{error:?}"))
}

fn failed_report(
    request: &HelperRequest,
    branch: Branch,
    failure: CollectionFailure,
) -> Result<EvidenceReport, String> {
    EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        Utc::now(),
        ReportStatus::Failed,
        backend_provenance()?,
    )
    .coverage(CoverageDeclaration {
        kind: token(CoverageKind::new(branch.coverage()))?,
        subject: None,
        state: CoverageState::Unavailable,
        detail: None,
    })
    .error(ReportError {
        code: token(ErrorCode::new(failure.code))?,
        severity: ErrorSeverity::Error,
        message: failure.message,
        subject: Some(request.binding.subject.clone()),
        observation_ordinal: None,
        retriable: failure.retriable,
    })
    .used_capability(token(Capability::new(branch.capability()))?)
    .build()
    .map_err(|error| format!("{error:?}"))
}

fn validate_compiled_report(
    request: &HelperRequest,
    branch: Branch,
    report: &EvidenceReport,
) -> Result<(), String> {
    let input =
        ReportInput::from_protocol_with_digest(report).map_err(|error| format!("{error:?}"))?;
    let context = ValidationContext::from_request(request, Utc::now(), Duration::seconds(5));
    branch
        .module()
        .validate(&context, &input)
        .map(|_| ())
        .map_err(|error| format!("{:?}: {}", error.code, error.message))
}

fn evidence_basis(request: &HelperRequest, access_path: &str, basis: &str) -> EvidenceBasis {
    EvidenceBasis {
        scope: ScopeGrant {
            kind: request.binding.scope.kind.to_string(),
            value: request.binding.scope.value.clone(),
        },
        vantage: VantageGrant {
            kind: request.binding.vantage.kind.to_string(),
            value: request.binding.vantage.value.clone(),
        },
        access_path: access_path.to_owned(),
        basis: basis.to_owned(),
        regime: "normal".to_owned(),
        capabilities_used: request
            .granted_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

fn ensure_bounded_response(
    request: &HelperRequest,
    response: HelperResponse,
) -> Result<HelperResponse, StdioError> {
    if validate_exchange(request, &response).is_ok() {
        return Ok(response);
    }
    let fallback = refusal(
        request,
        RefusalBoundary::Resource,
        RefusalCode::BoundsUnsupported,
        "negotiated response or payload bound cannot represent operator-beta testimony",
        false,
        json!({}),
    );
    validate_exchange(request, &fallback)
        .map(|()| fallback)
        .map_err(|error| StdioError::UnrepresentableResponse(format!("{error:?}")))
}

fn refusal(
    request: &HelperRequest,
    boundary: RefusalBoundary,
    code: RefusalCode,
    message: &str,
    retriable: bool,
    details: Value,
) -> HelperResponse {
    HelperResponse::refusal(
        request,
        Refusal {
            responsible_instance_id: request.instance_id.clone(),
            boundary,
            code,
            message: message.to_owned(),
            retriable,
            details,
        },
    )
}

fn internal_refusal(request: &HelperRequest, message: &str, details: Value) -> HelperResponse {
    refusal(
        request,
        RefusalBoundary::Internal,
        RefusalCode::InternalError,
        message,
        false,
        details,
    )
}

fn backend_provenance() -> Result<BackendProvenance, String> {
    Ok(BackendProvenance {
        implementation: BackendIdentity {
            name: token(ImplementationName::new("nq-operator-beta-helper"))?,
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            digest: None,
        },
        tools: Vec::new(),
    })
}

fn token<T>(result: Result<T, nq_protocol::TokenError>) -> Result<T, String> {
    result.map_err(|error| format!("{error:?}"))
}

fn bounded_message(message: &str, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message.to_owned();
    }
    let mut end = max_bytes;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

trait DeadlineClock {
    fn now_ns(&self) -> Result<u64, String>;
}

struct LinuxBoottimeClock;

impl DeadlineClock for LinuxBoottimeClock {
    fn now_ns(&self) -> Result<u64, String> {
        let time = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(|error| format!("{error:?}"))?;
        let seconds = u64::try_from(time.tv_sec())
            .map_err(|_| "CLOCK_BOOTTIME returned negative seconds".to_owned())?;
        let nanos = u64::try_from(time.tv_nsec())
            .map_err(|_| "CLOCK_BOOTTIME returned negative nanoseconds".to_owned())?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanos))
            .ok_or_else(|| "CLOCK_BOOTTIME overflow".to_owned())
    }
}

fn remaining(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<std::time::Duration, CollectionFailure> {
    let now = clock
        .now_ns()
        .map_err(|error| CollectionFailure::new("clock_unavailable", error, true))?;
    let nanos = request
        .deadline
        .expires_at_ns
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CollectionFailure::new(
                "deadline_expired",
                "request deadline expired during collection",
                true,
            )
        })?;
    Ok(std::time::Duration::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use nq_protocol::{
        CollectionBounds, InstanceId, MonotonicClock, MonotonicDeadline, ProfileBinding, ProfileId,
        ProfileVersion, RequestId, ResponseOutcome, ScopeBinding, ScopeKind, Sha256Digest,
        SubjectBinding, SubjectId, VantageBinding, VantageKind,
    };

    use super::*;

    const SUBJECT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const UNIT_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct FixedClock(u64);

    impl DeadlineClock for FixedClock {
        fn now_ns(&self) -> Result<u64, String> {
            Ok(self.0)
        }
    }

    struct FakeSource {
        calls: Cell<u32>,
        fail: bool,
    }

    impl AcquisitionSource for FakeSource {
        fn acquire(
            &self,
            branch: Branch,
            request: &HelperRequest,
            _clock: &impl DeadlineClock,
        ) -> Result<Value, CollectionFailure> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(CollectionFailure::new(
                    "fixture_collection_failed",
                    "deterministic collection failure",
                    true,
                ));
            }
            Ok(match branch {
                Branch::Systemd => json!({
                    "evidence_basis": evidence_basis(request, "systemd_dbus", "systemd_properties"),
                    "target_machine_identity": "machine:fixture-001",
                    "unit_name": "constellation-beta-http-fixture.service",
                    "unit_file_sha256": UNIT_DIGEST,
                    "manager_object_path": "/org/freedesktop/systemd1",
                    "unit_object_path": "/org/freedesktop/systemd1/unit/fixture",
                    "load_state": "loaded",
                    "active_state": "active",
                    "sub_state": "running",
                    "unit_file_state": "disabled",
                }),
                Branch::Http => json!({
                    "evidence_basis": evidence_basis(request, "http_tcp", "http_response"),
                    "controller_vantage_identity": "controller:fixture-001",
                    "endpoint": "http://192.0.2.10:18080/healthz",
                    "method": "GET",
                    "redirect_policy": "refuse",
                    "status": 200,
                    "body_sha256": format!("sha256:{}", "c".repeat(64)),
                    "body_bytes": 3,
                }),
            })
        }
    }

    fn exact_bounds() -> CollectionBounds {
        CollectionBounds {
            max_response_bytes: MIN_RESPONSE_BYTES,
            max_observations: 1,
            max_payload_bytes: MIN_PAYLOAD_BYTES,
            max_coverage_entries: 1,
            max_report_errors: 1,
            max_checkpoint_bytes: 1,
        }
    }

    fn request(branch: Branch) -> HelperRequest {
        let module = branch.module();
        let binding = match branch {
            Branch::Systemd => SubjectBinding {
                subject: SubjectId::new(SUBJECT).unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("systemd_unit").unwrap(),
                    value: json!({
                        "schema": "nq.operator_beta.systemd_unit_scope.v1",
                        "subject_identity": SUBJECT,
                        "target_machine_identity": "machine:fixture-001",
                        "unit_name": "constellation-beta-http-fixture.service",
                        "unit_file_sha256": UNIT_DIGEST,
                        "manager_interface": "org.freedesktop.systemd1",
                        "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
                    }),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("target_local").unwrap(),
                    value: json!({}),
                },
            },
            Branch::Http => SubjectBinding {
                subject: SubjectId::new(SUBJECT).unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("http_endpoint").unwrap(),
                    value: json!({
                        "schema": "nq.operator_beta.http_endpoint_scope.v1",
                        "subject_identity": SUBJECT,
                        "controller_vantage_identity": "controller:fixture-001",
                        "endpoint": "http://192.0.2.10:18080/healthz",
                        "method": "GET",
                        "redirect_policy": "refuse",
                        "max_response_bytes": 1024,
                    }),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("controller_http").unwrap(),
                    value: json!({
                        "controller_vantage_identity": "controller:fixture-001",
                    }),
                },
            },
        };
        HelperRequest::builder(
            RequestId::new(format!("request:{branch:?}")).unwrap(),
            InstanceId::new(format!("instance:{branch:?}")).unwrap(),
            ProfileBinding {
                id: ProfileId::new(module.descriptor().profile.id.clone()).unwrap(),
                version: ProfileVersion::new(module.descriptor().profile.version.to_string())
                    .unwrap(),
                digest: Sha256Digest::parse(module.descriptor().digest().unwrap().as_str())
                    .unwrap(),
            },
            binding,
            MonotonicDeadline {
                clock: MonotonicClock::LinuxBoottime,
                expires_at_ns: 2,
            },
        )
        .capability(Capability::new(branch.capability()).unwrap())
        .bounds(exact_bounds())
        .build()
        .unwrap()
    }

    #[test]
    fn exact_minimum_bounds_emit_compiled_reports_for_both_profiles() {
        for branch in [Branch::Systemd, Branch::Http] {
            let request = request(branch);
            let source = FakeSource {
                calls: Cell::new(0),
                fail: false,
            };
            let response = handle_request(&request, &source, &FixedClock(1));
            let ResponseOutcome::Report { report } = response.outcome else {
                panic!("expected complete report for {branch:?}");
            };
            assert_eq!(report.status, ReportStatus::Complete);
            assert_eq!(report.observations.len(), 1);
            assert_eq!(source.calls.get(), 1);
        }
    }

    #[test]
    fn collection_failure_is_explicit_unavailable_testimony() {
        let request = request(Branch::Systemd);
        let source = FakeSource {
            calls: Cell::new(0),
            fail: true,
        };
        let response = handle_request(&request, &source, &FixedClock(1));
        let ResponseOutcome::Report { report } = response.outcome else {
            panic!("expected failed report");
        };
        assert_eq!(report.status, ReportStatus::Failed);
        assert!(report.observations.is_empty());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.coverage[0].state, CoverageState::Unavailable);
    }

    #[test]
    fn each_one_below_minimum_bound_refuses_before_acquisition() {
        for field in 0..5 {
            let mut request = request(Branch::Http);
            match field {
                0 => request.bounds.max_observations = 0,
                1 => request.bounds.max_coverage_entries = 0,
                2 => request.bounds.max_payload_bytes = MIN_PAYLOAD_BYTES - 1,
                3 => request.bounds.max_report_errors = 0,
                4 => request.bounds.max_response_bytes = MIN_RESPONSE_BYTES - 1,
                _ => unreachable!(),
            }
            let source = FakeSource {
                calls: Cell::new(0),
                fail: false,
            };
            let response = handle_request(&request, &source, &FixedClock(1));
            assert!(matches!(response.outcome, ResponseOutcome::Refusal { .. }));
            assert_eq!(source.calls.get(), 0);
        }
    }

    #[test]
    fn expired_wrong_capability_and_wrong_digest_refuse_before_acquisition() {
        let mut capability = request(Branch::Systemd);
        capability.granted_capabilities = vec![Capability::new(HTTP_CAPABILITY).unwrap()];
        let source = FakeSource {
            calls: Cell::new(0),
            fail: false,
        };
        assert!(matches!(
            handle_request(&capability, &source, &FixedClock(1)).outcome,
            ResponseOutcome::Refusal { .. }
        ));
        assert_eq!(source.calls.get(), 0);

        let mut digest = request(Branch::Systemd);
        digest.profile.digest = Sha256Digest::parse(format!("sha256:{}", "d".repeat(64))).unwrap();
        let source = FakeSource {
            calls: Cell::new(0),
            fail: false,
        };
        assert!(matches!(
            handle_request(&digest, &source, &FixedClock(1)).outcome,
            ResponseOutcome::Refusal { .. }
        ));
        assert_eq!(source.calls.get(), 0);

        let expired = request(Branch::Systemd);
        let source = FakeSource {
            calls: Cell::new(0),
            fail: false,
        };
        assert!(matches!(
            handle_request(&expired, &source, &FixedClock(2)).outcome,
            ResponseOutcome::Refusal { .. }
        ));
        assert_eq!(source.calls.get(), 0);
    }

    #[test]
    fn unrepresentable_echo_has_no_protocol_response() {
        let mut request = request(Branch::Http);
        request.bounds.max_response_bytes = 256;
        let source = FakeSource {
            calls: Cell::new(0),
            fail: false,
        };
        let response = handle_request(&request, &source, &FixedClock(1));
        assert!(ensure_bounded_response(&request, response).is_err());
        assert_eq!(source.calls.get(), 0);
    }

    #[test]
    fn malformed_frame_produces_no_stdout() {
        let mut output = Vec::new();
        assert!(run(&b"{}\n{}\n"[..], &mut output).is_err());
        assert!(output.is_empty());
    }
}
