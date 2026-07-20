//! First-party, one-shot stdio watcher for the compiled `nq.host/v1` profile.
//!
//! The helper performs no scheduling, admission, evaluation, notification, or
//! remediation. It accepts one bounded protocol request, observes only the
//! exact local host binding, and emits one bounded response.

use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Write},
    num::NonZeroUsize,
};

use chrono::{Duration, Utc};
use nix::{
    time::{ClockId, clock_gettime},
    unistd::gethostname,
};
use nq_profiles::{
    EvidenceBasis, ProfileModule, ReportInput, ScopeGrant, ValidationContext, VantageGrant, host,
};
use nq_protocol::{
    BackendIdentity, BackendProvenance, Capability, CoverageDeclaration, CoverageKind,
    CoverageState, ErrorCode, ErrorSeverity, EvidenceReport, FramingError, HelperRequest,
    HelperResponse, ImplementationName, MAX_REQUEST_FRAME_BYTES, ObservationKind, Refusal,
    RefusalBoundary, RefusalCode, ReportError, ReportStatus, encode_ndjson, parse_request,
    validate_exchange,
};
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;

const PROC_UPTIME: &str = "/proc/uptime";
const PROC_LOADAVG: &str = "/proc/loadavg";
const MAX_PROC_BYTES: usize = 4_096;
const MAX_COLLECTION_ERRORS: u32 = 4;
const READ_PROCFS: &str = "read_procfs";
const READ_SYSTEM_INFO: &str = "read_system_info";
const ACCESS_PROCFS: &str = "procfs";
const ACCESS_SYSINFO: &str = "sysinfo";
const ACCESS_COMBINED: &str = "procfs_sysinfo";

/// Failure before a valid bounded response can be written.
#[derive(Debug, Error)]
pub enum StdioError {
    /// Reading the one request frame failed.
    #[error("cannot read request: {0}")]
    Read(#[source] io::Error),
    /// The input exceeded the protocol request-frame ceiling.
    #[error("request frame exceeds {MAX_REQUEST_FRAME_BYTES} bytes")]
    RequestTooLarge,
    /// The request was not one strict, valid protocol frame.
    #[error("invalid request: {0}")]
    InvalidRequest(#[source] FramingError),
    /// No protocol-valid response can fit the request's own response bound.
    #[error("cannot construct a bounded response: {0}")]
    UnrepresentableResponse(String),
    /// Writing the response frame failed.
    #[error("cannot write response: {0}")]
    Write(#[source] io::Error),
}

/// Runs one request/response exchange on standard input and standard output.
///
/// # Errors
///
/// Returns [`StdioError`] when no request can be parsed, no valid response can
/// fit negotiated bounds, or stdio fails. A parsed request otherwise receives
/// exactly one report or typed refusal.
pub fn run_stdio() -> Result<(), StdioError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run(stdin.lock(), stdout.lock())
}

/// Runs one request/response exchange over supplied streams.
///
/// This is public to support carrier conformance and embedding tests; the
/// shipped binary uses [`run_stdio`].
///
/// # Errors
///
/// Returns [`StdioError`] under the same conditions as [`run_stdio`].
pub fn run(mut input: impl Read, mut output: impl Write) -> Result<(), StdioError> {
    let request_bytes = read_request_frame(&mut input)?;
    let request = parse_request(&request_bytes).map_err(StdioError::InvalidRequest)?;
    let response = handle_request(&request, &SystemHostSource, &LinuxBoottimeClock);
    let response = ensure_bounded_response(&request, response)?;
    let frame = encode_ndjson(&response)
        .map_err(|error| StdioError::UnrepresentableResponse(error.to_string()))?;
    output.write_all(&frame).map_err(StdioError::Write)?;
    output.flush().map_err(StdioError::Write)
}

fn read_request_frame(input: &mut impl Read) -> Result<Vec<u8>, StdioError> {
    let limit = u64::try_from(MAX_REQUEST_FRAME_BYTES)
        .expect("protocol request bound fits u64")
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

fn handle_request(
    request: &HelperRequest,
    source: &impl HostSource,
    clock: &impl DeadlineClock,
) -> HelperResponse {
    if let Some(response) = validate_host_request(request, clock) {
        return response;
    }

    match collect_report(request, source, clock) {
        Ok(report) => match validate_compiled_report(request, &report) {
            Ok(()) => HelperResponse::report(request, report),
            Err(error) => internal_refusal(
                request,
                "the collected report failed the compiled nq.host/v1 contract",
                json!({"validation_error": bounded_message(&error, 1_024)}),
            ),
        },
        Err(CollectionAbort::DeadlineExpired) => refusal(
            request,
            RefusalBoundary::Deadline,
            RefusalCode::DeadlineExpired,
            "the monotonic request deadline expired during collection",
            true,
            json!({}),
        ),
        Err(CollectionAbort::Internal(error)) => internal_refusal(
            request,
            "the helper could not construct host testimony",
            json!({"error": bounded_message(&error, 1_024)}),
        ),
    }
}

fn validate_host_request(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Option<HelperResponse> {
    validate_profile_request(request)
        .or_else(|| validate_binding_request(request))
        .or_else(|| validate_capability_request(request))
        .or_else(|| validate_execution_request(request, clock))
}

fn validate_profile_request(request: &HelperRequest) -> Option<HelperResponse> {
    let descriptor = host::MODULE.descriptor();
    if request.profile.id.as_str() != host::PROFILE_ID
        || request.profile.version.as_str() != host::PROFILE_VERSION.to_string()
    {
        return Some(refusal(
            request,
            RefusalBoundary::Profile,
            RefusalCode::UnknownProfile,
            "this helper implements only nq.host/v1",
            false,
            json!({
                "requested_id": request.profile.id,
                "requested_version": request.profile.version,
                "supported_id": host::PROFILE_ID,
                "supported_version": host::PROFILE_VERSION,
            }),
        ));
    }

    let compiled_digest = match descriptor.digest() {
        Ok(digest) => digest,
        Err(error) => {
            return Some(internal_refusal(
                request,
                "the compiled profile descriptor could not be identified",
                json!({"error": bounded_message(&error.to_string(), 1_024)}),
            ));
        }
    };
    if request.profile.digest.as_str() != compiled_digest.as_str() {
        return Some(refusal(
            request,
            RefusalBoundary::Profile,
            RefusalCode::ProfileDigestMismatch,
            "the requested profile digest does not match the compiled nq.host/v1 descriptor",
            false,
            json!({
                "requested_digest": request.profile.digest,
                "compiled_digest": compiled_digest.as_str(),
            }),
        ));
    }
    None
}

fn validate_binding_request(request: &HelperRequest) -> Option<HelperResponse> {
    if let Err(message) = validate_scope(request) {
        return Some(refusal(
            request,
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
            &message,
            false,
            json!({}),
        ));
    }
    if request.binding.vantage.kind.as_str() != "local"
        || request.binding.vantage.value != json!({})
    {
        return Some(refusal(
            request,
            RefusalBoundary::Vantage,
            RefusalCode::UnsupportedVantage,
            "nq.host/v1 requires the empty local vantage",
            false,
            json!({}),
        ));
    }
    None
}

fn validate_capability_request(request: &HelperRequest) -> Option<HelperResponse> {
    if request.checkpoint.is_some() {
        return Some(refusal(
            request,
            RefusalBoundary::Checkpoint,
            RefusalCode::CheckpointInvalid,
            "nq.host/v1 does not accept polling checkpoints",
            false,
            json!({}),
        ));
    }

    let unsupported: Vec<&str> = request
        .granted_capabilities
        .iter()
        .map(Capability::as_str)
        .filter(|capability| !matches!(*capability, READ_PROCFS | READ_SYSTEM_INFO))
        .collect();
    if !unsupported.is_empty() {
        return Some(refusal(
            request,
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
            "the request grants capabilities outside this helper's nq.host/v1 implementation",
            false,
            json!({"unsupported_capabilities": unsupported}),
        ));
    }
    if request.granted_capabilities.is_empty() {
        return Some(refusal(
            request,
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
            "host collection requires read_procfs, read_system_info, or both",
            false,
            json!({"supported_capabilities": [READ_PROCFS, READ_SYSTEM_INFO]}),
        ));
    }
    None
}

fn validate_execution_request(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Option<HelperResponse> {
    if request.bounds.max_observations < 1
        || request.bounds.max_coverage_entries < 3
        || request.bounds.max_report_errors < MAX_COLLECTION_ERRORS
    {
        return Some(refusal(
            request,
            RefusalBoundary::Resource,
            RefusalCode::BoundsUnsupported,
            "the negotiated bounds cannot represent bounded nq.host/v1 testimony",
            false,
            json!({
                "minimum_observations": 1,
                "minimum_coverage_entries": 3,
                "minimum_report_errors": MAX_COLLECTION_ERRORS,
            }),
        ));
    }

    match clock.now_ns() {
        Ok(now_ns) if now_ns >= request.deadline.expires_at_ns => Some(refusal(
            request,
            RefusalBoundary::Deadline,
            RefusalCode::DeadlineExpired,
            "the monotonic request deadline expired before collection began",
            true,
            json!({}),
        )),
        Ok(_) => None,
        Err(error) => Some(internal_refusal(
            request,
            "the Linux boot-time clock could not be read",
            json!({"error": bounded_message(&error, 1_024)}),
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostScope {
    id: String,
}

fn validate_scope(request: &HelperRequest) -> Result<(), String> {
    if request.binding.scope.kind.as_str() != "host" {
        return Err("nq.host/v1 requires host scope".to_owned());
    }
    let scope: HostScope = serde_json::from_value(request.binding.scope.value.clone())
        .map_err(|_| "host scope must contain exactly one id string".to_owned())?;
    if scope.id.is_empty() || scope.id.len() > 255 {
        return Err("host scope id must contain 1 through 255 UTF-8 bytes".to_owned());
    }
    let expected = format!("host:{}", scope.id);
    if request.binding.subject.as_str() != expected {
        return Err("host scope id does not correlate with the request subject".to_owned());
    }
    Ok(())
}

fn collect_report(
    request: &HelperRequest,
    source: &impl HostSource,
    clock: &impl DeadlineClock,
) -> Result<EvidenceReport, CollectionAbort> {
    let acquisition = acquire_host(request, source, clock)?;
    ensure_before_deadline(request, clock)?;
    build_report(request, acquisition)
}

struct HostAcquisition {
    used_procfs: bool,
    used_sysinfo: bool,
    uptime_seconds: Option<u64>,
    load_1m: Option<f64>,
    hostname: Option<String>,
    cpu_count: Option<u32>,
    errors: Vec<ReportError>,
}

fn acquire_host(
    request: &HelperRequest,
    source: &impl HostSource,
    clock: &impl DeadlineClock,
) -> Result<HostAcquisition, CollectionAbort> {
    let use_procfs = granted(request, READ_PROCFS);
    let use_sysinfo = granted(request, READ_SYSTEM_INFO);
    let mut errors = Vec::with_capacity(MAX_COLLECTION_ERRORS as usize);

    let (uptime_seconds, load_1m) = if use_procfs {
        ensure_before_deadline(request, clock)?;
        (
            acquire(
                source.uptime_seconds(),
                "uptime_unavailable",
                "could not read bounded /proc/uptime",
                &mut errors,
            ),
            acquire(
                source.load_1m(),
                "loadavg_unavailable",
                "could not read bounded /proc/loadavg",
                &mut errors,
            ),
        )
    } else {
        errors.push(report_error(
            "procfs_capability_not_granted",
            "read_procfs was not granted; uptime and scheduler load were not observed",
            false,
        ));
        (None, None)
    };

    let (hostname, cpu_count) = if use_sysinfo {
        ensure_before_deadline(request, clock)?;
        (
            acquire(
                source.hostname(),
                "hostname_unavailable",
                "could not read the local kernel hostname",
                &mut errors,
            ),
            acquire(
                source.cpu_count(),
                "cpu_count_unavailable",
                "could not read available parallelism",
                &mut errors,
            ),
        )
    } else {
        errors.push(report_error(
            "system_info_capability_not_granted",
            "read_system_info was not granted; hostname and CPU count were not observed",
            false,
        ));
        (None, None)
    };

    Ok(HostAcquisition {
        used_procfs: use_procfs,
        used_sysinfo: use_sysinfo,
        uptime_seconds,
        load_1m,
        hostname,
        cpu_count,
        errors,
    })
}

fn build_report(
    request: &HelperRequest,
    acquisition: HostAcquisition,
) -> Result<EvidenceReport, CollectionAbort> {
    let observed_at = Utc::now();
    let identity_coverage = coverage_state(acquisition.hostname.is_some());
    let uptime_coverage = coverage_state(acquisition.uptime_seconds.is_some());
    let load_fields =
        usize::from(acquisition.cpu_count.is_some()) + usize::from(acquisition.load_1m.is_some());
    let load_coverage = match load_fields {
        2 => CoverageState::Complete,
        1 => CoverageState::Partial,
        _ => CoverageState::Unavailable,
    };
    let all_unavailable = identity_coverage == CoverageState::Unavailable
        && uptime_coverage == CoverageState::Unavailable
        && load_coverage == CoverageState::Unavailable;
    let all_complete = identity_coverage == CoverageState::Complete
        && uptime_coverage == CoverageState::Complete
        && load_coverage == CoverageState::Complete;
    let status = if all_complete {
        ReportStatus::Complete
    } else if all_unavailable {
        ReportStatus::Failed
    } else {
        ReportStatus::Partial
    };

    let used_capabilities = used_capabilities(acquisition.used_procfs, acquisition.used_sysinfo)?;
    let mut builder = EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        observed_at,
        status,
        backend_provenance()?,
    )
    .coverage(coverage("host_identity", identity_coverage)?)
    .coverage(coverage("uptime", uptime_coverage)?)
    .coverage(coverage("load", load_coverage)?);

    if !all_unavailable {
        let access_path = match (acquisition.used_procfs, acquisition.used_sysinfo) {
            (true, true) => ACCESS_COMBINED,
            (true, false) => ACCESS_PROCFS,
            (false, true) => ACCESS_SYSINFO,
            (false, false) => unreachable!("capability validation rejects an empty grant"),
        };
        let basis = EvidenceBasis {
            scope: ScopeGrant {
                kind: request.binding.scope.kind.to_string(),
                value: request.binding.scope.value.clone(),
            },
            vantage: VantageGrant {
                kind: request.binding.vantage.kind.to_string(),
                value: request.binding.vantage.value.clone(),
            },
            access_path: access_path.to_owned(),
            basis: "kernel_snapshot".to_owned(),
            regime: "normal".to_owned(),
            capabilities_used: used_capabilities.iter().map(ToString::to_string).collect(),
        };
        let payload = json!({
            "evidence_basis": basis,
            "hostname": acquisition.hostname,
            "uptime_seconds": acquisition.uptime_seconds,
            "cpu_count": acquisition.cpu_count,
            "load_1m": acquisition.load_1m,
        });
        builder = builder.observed_payload(
            token(ObservationKind::new("host_snapshot"))?,
            request.binding.subject.clone(),
            observed_at,
            payload,
        );
    }

    for capability in used_capabilities {
        builder = builder.used_capability(capability);
    }
    for mut error in acquisition.errors {
        if !all_unavailable {
            error.observation_ordinal = Some(0);
        }
        builder = builder.error(error);
    }
    builder
        .build()
        .map_err(|error| CollectionAbort::Internal(error.to_string()))
}

fn validate_compiled_report(
    request: &HelperRequest,
    report: &EvidenceReport,
) -> Result<(), String> {
    let input =
        ReportInput::from_protocol_with_digest(report).map_err(|error| error.to_string())?;
    let context = ValidationContext::from_request(request, Utc::now(), Duration::seconds(5));
    host::MODULE
        .validate(&context, &input)
        .map(|_| ())
        .map_err(|error| format!("{:?}: {}", error.code, error.message))
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
        "the negotiated response or payload bound is too small for nq.host/v1 testimony",
        false,
        json!({}),
    );
    validate_exchange(request, &fallback)
        .map(|()| fallback)
        .map_err(|error| StdioError::UnrepresentableResponse(error.to_string()))
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

fn granted(request: &HelperRequest, name: &str) -> bool {
    request
        .granted_capabilities
        .iter()
        .any(|capability| capability.as_str() == name)
}

fn used_capabilities(
    use_procfs: bool,
    use_sysinfo: bool,
) -> Result<Vec<Capability>, CollectionAbort> {
    let mut capabilities = Vec::with_capacity(2);
    if use_procfs {
        capabilities.push(token(Capability::new(READ_PROCFS))?);
    }
    if use_sysinfo {
        capabilities.push(token(Capability::new(READ_SYSTEM_INFO))?);
    }
    Ok(capabilities)
}

fn coverage(name: &str, state: CoverageState) -> Result<CoverageDeclaration, CollectionAbort> {
    Ok(CoverageDeclaration {
        kind: token(CoverageKind::new(name))?,
        subject: None,
        state,
        detail: None,
    })
}

fn coverage_state(present: bool) -> CoverageState {
    if present {
        CoverageState::Complete
    } else {
        CoverageState::Unavailable
    }
}

fn backend_provenance() -> Result<BackendProvenance, CollectionAbort> {
    Ok(BackendProvenance {
        implementation: BackendIdentity {
            name: token(ImplementationName::new("nq-host-helper"))?,
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            digest: None,
        },
        // This implementation invokes no backend command or shell. Binary and
        // execution-chain identity are independently pinned by admission.
        tools: Vec::new(),
    })
}

fn report_error(code: &str, message: &str, retriable: bool) -> ReportError {
    ReportError {
        code: ErrorCode::new(code).expect("static report-error code is a valid token"),
        severity: ErrorSeverity::Error,
        message: message.to_owned(),
        subject: None,
        observation_ordinal: None,
        retriable,
    }
}

fn acquire<T>(
    result: Result<T, String>,
    code: &str,
    context: &str,
    errors: &mut Vec<ReportError>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(report_error(
                code,
                &format!("{context}: {}", bounded_message(&error, 768)),
                true,
            ));
            None
        }
    }
}

fn token<T>(result: Result<T, nq_protocol::TokenError>) -> Result<T, CollectionAbort> {
    result.map_err(|error| CollectionAbort::Internal(error.to_string()))
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

#[derive(Debug)]
enum CollectionAbort {
    DeadlineExpired,
    Internal(String),
}

trait DeadlineClock {
    fn now_ns(&self) -> Result<u64, String>;
}

struct LinuxBoottimeClock;

impl DeadlineClock for LinuxBoottimeClock {
    fn now_ns(&self) -> Result<u64, String> {
        let time = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(|error| error.to_string())?;
        let seconds = u64::try_from(time.tv_sec())
            .map_err(|_| "CLOCK_BOOTTIME returned negative seconds".to_owned())?;
        let nanoseconds = u64::try_from(time.tv_nsec())
            .map_err(|_| "CLOCK_BOOTTIME returned negative nanoseconds".to_owned())?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or_else(|| "CLOCK_BOOTTIME nanoseconds overflow u64".to_owned())
    }
}

fn ensure_before_deadline(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<(), CollectionAbort> {
    let now = clock.now_ns().map_err(CollectionAbort::Internal)?;
    if now >= request.deadline.expires_at_ns {
        Err(CollectionAbort::DeadlineExpired)
    } else {
        Ok(())
    }
}

trait HostSource {
    fn uptime_seconds(&self) -> Result<u64, String>;
    fn load_1m(&self) -> Result<f64, String>;
    fn hostname(&self) -> Result<String, String>;
    fn cpu_count(&self) -> Result<u32, String>;
}

struct SystemHostSource;

impl HostSource for SystemHostSource {
    fn uptime_seconds(&self) -> Result<u64, String> {
        let text = read_bounded_utf8(PROC_UPTIME, MAX_PROC_BYTES)?;
        let token = text
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| "/proc/uptime is empty".to_owned())?;
        parse_uptime_seconds(token)
    }

    fn load_1m(&self) -> Result<f64, String> {
        let text = read_bounded_utf8(PROC_LOADAVG, MAX_PROC_BYTES)?;
        let token = text
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| "/proc/loadavg is empty".to_owned())?;
        let load = token
            .parse::<f64>()
            .map_err(|error| format!("invalid first field: {error}"))?;
        if !load.is_finite() || load.is_sign_negative() {
            return Err("first field is not finite and non-negative".to_owned());
        }
        Ok(load)
    }

    fn hostname(&self) -> Result<String, String> {
        hostname_string(gethostname().map_err(|error| error.to_string())?)
    }

    fn cpu_count(&self) -> Result<u32, String> {
        parallelism_count(std::thread::available_parallelism().map_err(|error| error.to_string())?)
    }
}

fn parse_uptime_seconds(value: &str) -> Result<u64, String> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, "0"));
    if seconds.is_empty()
        || fraction.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("first field is not a non-negative decimal duration".to_owned());
    }
    seconds
        .parse::<u64>()
        .map_err(|error| format!("invalid whole seconds: {error}"))
}

fn read_bounded_utf8(path: &str, max_bytes: usize) -> Result<String, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let limit = u64::try_from(max_bytes)
        .map_err(|error| error.to_string())?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(1_024));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > max_bytes {
        return Err(format!("file exceeds the {max_bytes}-byte local limit"));
    }
    String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8".to_owned())
}

fn hostname_string(hostname: OsString) -> Result<String, String> {
    let hostname = hostname
        .into_string()
        .map_err(|_| "kernel hostname is not valid UTF-8".to_owned())?;
    if hostname.is_empty() || hostname.len() > 255 {
        return Err("kernel hostname must contain 1 through 255 UTF-8 bytes".to_owned());
    }
    Ok(hostname)
}

fn parallelism_count(parallelism: NonZeroUsize) -> Result<u32, String> {
    u32::try_from(parallelism.get()).map_err(|_| "available parallelism exceeds u32".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_protocol::{
        CollectionBounds, InstanceId, MonotonicClock, MonotonicDeadline, ProfileBinding, ProfileId,
        ProfileVersion, RequestId, ResponseOutcome, ScopeBinding, ScopeKind, Sha256Digest,
        SubjectBinding, SubjectId, VantageBinding, VantageKind,
    };

    struct FixedClock(u64);

    impl DeadlineClock for FixedClock {
        fn now_ns(&self) -> Result<u64, String> {
            Ok(self.0)
        }
    }

    struct FakeSource {
        uptime: Result<u64, &'static str>,
        load: Result<f64, &'static str>,
        hostname: Result<&'static str, &'static str>,
        cpus: Result<u32, &'static str>,
    }

    impl FakeSource {
        fn complete() -> Self {
            Self {
                uptime: Ok(86_400),
                load: Ok(1.5),
                hostname: Ok("node-1"),
                cpus: Ok(4),
            }
        }
    }

    impl HostSource for FakeSource {
        fn uptime_seconds(&self) -> Result<u64, String> {
            self.uptime.map_err(str::to_owned)
        }

        fn load_1m(&self) -> Result<f64, String> {
            self.load.map_err(str::to_owned)
        }

        fn hostname(&self) -> Result<String, String> {
            self.hostname.map(str::to_owned).map_err(str::to_owned)
        }

        fn cpu_count(&self) -> Result<u32, String> {
            self.cpus.map_err(str::to_owned)
        }
    }

    fn request(capabilities: &[&str]) -> HelperRequest {
        let descriptor = host::MODULE.descriptor();
        HelperRequest::builder(
            RequestId::new("request:host-test").unwrap(),
            InstanceId::new("instance:host-test").unwrap(),
            ProfileBinding {
                id: ProfileId::new(host::PROFILE_ID).unwrap(),
                version: ProfileVersion::new(host::PROFILE_VERSION.to_string()).unwrap(),
                digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str()).unwrap(),
            },
            SubjectBinding {
                subject: SubjectId::new("host:node-1").unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("host").unwrap(),
                    value: json!({"id": "node-1"}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").unwrap(),
                    value: json!({}),
                },
            },
            MonotonicDeadline {
                clock: MonotonicClock::LinuxBoottime,
                expires_at_ns: 10_000,
            },
        )
        .capabilities(
            capabilities
                .iter()
                .map(|value| Capability::new(*value).unwrap())
                .collect(),
        )
        .bounds(CollectionBounds::default())
        .build()
        .unwrap()
    }

    fn report(response: HelperResponse) -> EvidenceReport {
        let ResponseOutcome::Report { report } = response.outcome else {
            panic!("expected report")
        };
        report
    }

    #[test]
    fn complete_collection_declares_composite_basis_and_both_capabilities() {
        let request = request(&[READ_PROCFS, READ_SYSTEM_INFO]);
        let response = handle_request(&request, &FakeSource::complete(), &FixedClock(1));
        validate_exchange(&request, &response).unwrap();
        let report = report(response);
        assert_eq!(report.status, ReportStatus::Complete);
        assert!(report.errors.is_empty());
        assert_eq!(
            report.used_capabilities,
            vec![
                Capability::new(READ_PROCFS).unwrap(),
                Capability::new(READ_SYSTEM_INFO).unwrap()
            ]
        );
        assert_eq!(
            report.observations[0].payload["evidence_basis"]["access_path"],
            ACCESS_COMBINED
        );
    }

    #[test]
    fn one_capability_produces_admissible_partial_coverage() {
        let request = request(&[READ_PROCFS]);
        let response = handle_request(&request, &FakeSource::complete(), &FixedClock(1));
        validate_exchange(&request, &response).unwrap();
        let report = report(response);
        assert_eq!(report.status, ReportStatus::Partial);
        assert_eq!(report.coverage[0].state, CoverageState::Unavailable);
        assert_eq!(report.coverage[1].state, CoverageState::Complete);
        assert_eq!(report.coverage[2].state, CoverageState::Partial);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(
            report.observations[0].payload["evidence_basis"]["access_path"],
            ACCESS_PROCFS
        );
    }

    #[test]
    fn total_acquisition_failure_is_retained_as_failed_testimony() {
        let source = FakeSource {
            uptime: Err("uptime denied"),
            load: Err("load denied"),
            hostname: Err("hostname denied"),
            cpus: Err("cpu denied"),
        };
        let request = request(&[READ_PROCFS, READ_SYSTEM_INFO]);
        let response = handle_request(&request, &source, &FixedClock(1));
        validate_exchange(&request, &response).unwrap();
        let report = report(response);
        assert_eq!(report.status, ReportStatus::Failed);
        assert!(report.observations.is_empty());
        assert_eq!(report.errors.len(), 4);
        assert!(
            report
                .coverage
                .iter()
                .all(|entry| entry.state == CoverageState::Unavailable)
        );
    }

    #[test]
    fn digest_scope_capability_and_deadline_fail_at_exact_boundaries() {
        let mut wrong_digest = request(&[READ_PROCFS]);
        wrong_digest.profile.digest =
            Sha256Digest::parse(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert_refusal(
            handle_request(&wrong_digest, &FakeSource::complete(), &FixedClock(1)),
            RefusalBoundary::Profile,
            RefusalCode::ProfileDigestMismatch,
        );

        let mut wrong_scope = request(&[READ_PROCFS]);
        wrong_scope.binding.scope.value = json!({"id": "somewhere-else"});
        assert_refusal(
            handle_request(&wrong_scope, &FakeSource::complete(), &FixedClock(1)),
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
        );

        assert_refusal(
            handle_request(&request(&[]), &FakeSource::complete(), &FixedClock(1)),
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
        );

        let expired = request(&[READ_PROCFS]);
        assert_refusal(
            handle_request(&expired, &FakeSource::complete(), &FixedClock(10_000)),
            RefusalBoundary::Deadline,
            RefusalCode::DeadlineExpired,
        );
    }

    #[test]
    fn malformed_or_extra_frames_never_produce_stdout_testimony() {
        let mut output = Vec::new();
        let error = run(&b"{}\n{}\n"[..], &mut output).unwrap_err();
        assert!(matches!(error, StdioError::InvalidRequest(_)));
        assert!(output.is_empty());
    }

    fn assert_refusal(
        response: HelperResponse,
        expected_boundary: RefusalBoundary,
        expected_code: RefusalCode,
    ) {
        let ResponseOutcome::Refusal { refusal } = response.outcome else {
            panic!("expected refusal")
        };
        assert_eq!(refusal.boundary, expected_boundary);
        assert_eq!(refusal.code, expected_code);
    }
}
