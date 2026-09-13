//! First-party, one-shot stdio watcher for the compiled `nq.synthetic_cache_executor_result/v1` profile.
//!
//! The helper performs no scheduling, admission, evaluation, notification, or
//! remediation. It accepts one bounded protocol request, observes only the
//! exact retained attempt binding, and emits one bounded response.

use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

use chrono::{Duration, Utc};
use nix::time::{ClockId, clock_gettime};
use nq_profiles::{
    EvidenceBasis, ProfileModule, ReportInput, ScopeGrant, ValidationContext, VantageGrant,
    synthetic_cache_executor_result,
};
use nq_protocol::{
    BackendIdentity, BackendProvenance, Capability, CoverageDeclaration, CoverageKind,
    CoverageState, EvidenceReport, FramingError, HelperRequest, HelperResponse, ImplementationName,
    MAX_REQUEST_FRAME_BYTES, ObservationKind, Refusal, RefusalBoundary, RefusalCode, ReportStatus,
    encode_ndjson, parse_request, validate_exchange,
};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const READ_RESULT: &str = "read_settled_cache_result";
const MAX_RECORD_BYTES: usize = 65_536;

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
    let response = handle_request(&request, &SystemResultSource, &LinuxBoottimeClock);
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
    source: &impl ResultSource,
    clock: &impl DeadlineClock,
) -> HelperResponse {
    if let Some(response) = validate_result_request(request, clock) {
        return response;
    }

    match collect_report(request, source, clock) {
        Ok(report) => match validate_compiled_report(request, &report) {
            Ok(()) => HelperResponse::report(request, report),
            Err(error) => internal_refusal(
                request,
                "the collected report failed the compiled nq.synthetic_cache_executor_result/v1 contract",
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
            "the helper could not construct retained-attempt testimony",
            json!({"error": bounded_message(&error, 1_024)}),
        ),
    }
}

fn validate_result_request(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Option<HelperResponse> {
    validate_profile_request(request)
        .or_else(|| validate_binding_request(request))
        .or_else(|| validate_capability_request(request))
        .or_else(|| validate_execution_request(request, clock))
}

fn validate_profile_request(request: &HelperRequest) -> Option<HelperResponse> {
    let descriptor = synthetic_cache_executor_result::MODULE.descriptor();
    if request.profile.id.as_str() != synthetic_cache_executor_result::PROFILE_ID
        || request.profile.version.as_str()
            != synthetic_cache_executor_result::PROFILE_VERSION.to_string()
    {
        return Some(refusal(
            request,
            RefusalBoundary::Profile,
            RefusalCode::UnknownProfile,
            "this helper implements only nq.synthetic_cache_executor_result/v1",
            false,
            json!({
                "requested_id": request.profile.id,
                "requested_version": request.profile.version,
                "supported_id": synthetic_cache_executor_result::PROFILE_ID,
                "supported_version": synthetic_cache_executor_result::PROFILE_VERSION,
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
            "the requested profile digest does not match the compiled nq.synthetic_cache_executor_result/v1 descriptor",
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
    if request.binding.vantage.kind.as_str() != "retained_docket_state"
        || request.binding.vantage.value != json!({})
    {
        return Some(refusal(
            request,
            RefusalBoundary::Vantage,
            RefusalCode::UnsupportedVantage,
            "the retained-result profile requires the empty retained_docket_state vantage",
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
            "nq.synthetic_cache_executor_result/v1 does not accept polling checkpoints",
            false,
            json!({}),
        ));
    }

    let unsupported: Vec<&str> = request
        .granted_capabilities
        .iter()
        .map(Capability::as_str)
        .filter(|capability| *capability != READ_RESULT)
        .collect();
    if !unsupported.is_empty() {
        return Some(refusal(
            request,
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
            "the request grants capabilities outside this helper's nq.synthetic_cache_executor_result/v1 implementation",
            false,
            json!({"unsupported_capabilities": unsupported}),
        ));
    }
    if request.granted_capabilities.len() != 1 {
        return Some(refusal(
            request,
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
            "retained-result collection requires exactly read_settled_cache_result",
            false,
            json!({"supported_capabilities": [READ_RESULT]}),
        ));
    }
    None
}

fn validate_execution_request(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Option<HelperResponse> {
    if request.bounds.max_observations < 1 || request.bounds.max_coverage_entries < 1 {
        return Some(refusal(
            request,
            RefusalBoundary::Resource,
            RefusalCode::BoundsUnsupported,
            "the negotiated bounds cannot represent bounded nq.synthetic_cache_executor_result/v1 testimony",
            false,
            json!({
                "minimum_observations": 1,
                "minimum_coverage_entries": 1,
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
struct ResultScope {
    attempt: String,
    marker: String,
    subject: String,
    scope: String,
    work: String,
    work_schema: String,
    executor_plan: String,
    executor_program_digest: String,
    docket_database: String,
    executor_record: String,
}

fn validate_scope(request: &HelperRequest) -> Result<(), String> {
    if request.binding.scope.kind.as_str() != "synthetic_cache_executor_attempt" {
        return Err(
            "retained-result profile requires synthetic_cache_executor_attempt scope".to_owned(),
        );
    }
    let scope: ResultScope = serde_json::from_value(request.binding.scope.value.clone())
        .map_err(|_| "retained-result scope has invalid fields".to_owned())?;
    if request.binding.subject.as_str() != scope.subject
        || !Path::new(&scope.docket_database).is_absolute()
        || !Path::new(&scope.executor_record).is_absolute()
    {
        return Err("retained-result paths or subject do not match the exact scope".to_owned());
    }
    Ok(())
}

fn collect_report(
    request: &HelperRequest,
    source: &impl ResultSource,
    clock: &impl DeadlineClock,
) -> Result<EvidenceReport, CollectionAbort> {
    let acquisition = acquire_result(request, source, clock)?;
    ensure_before_deadline(request, clock)?;
    build_report(request, acquisition)
}

#[derive(Debug)]
struct ResultAcquisition {
    observed_at: chrono::DateTime<Utc>,
    payload: Value,
}

fn acquire_result(
    request: &HelperRequest,
    source: &impl ResultSource,
    clock: &impl DeadlineClock,
) -> Result<ResultAcquisition, CollectionAbort> {
    ensure_before_deadline(request, clock)?;
    source.read(request).map_err(CollectionAbort::Internal)
}

fn build_report(
    request: &HelperRequest,
    acquisition: ResultAcquisition,
) -> Result<EvidenceReport, CollectionAbort> {
    let used = token(Capability::new(READ_RESULT))?;
    let basis = EvidenceBasis {
        scope: ScopeGrant {
            kind: request.binding.scope.kind.to_string(),
            value: request.binding.scope.value.clone(),
        },
        vantage: VantageGrant {
            kind: request.binding.vantage.kind.to_string(),
            value: request.binding.vantage.value.clone(),
        },
        access_path: "docket_sqlite_and_executor_record".into(),
        basis: "docket_settlement_and_executor_receipt".into(),
        regime: "past_attempt".into(),
        capabilities_used: std::collections::BTreeSet::from([READ_RESULT.into()]),
    };
    let mut payload = acquisition.payload;
    payload
        .as_object_mut()
        .ok_or_else(|| CollectionAbort::Internal("payload is not an object".into()))?
        .insert(
            "evidence_basis".into(),
            serde_json::to_value(basis).map_err(|e| CollectionAbort::Internal(e.to_string()))?,
        );
    EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        acquisition.observed_at,
        ReportStatus::Complete,
        backend_provenance()?,
    )
    .coverage(coverage("synthetic_cache_result", CoverageState::Complete)?)
    .observed_payload(
        token(ObservationKind::new("settled_executor_result"))?,
        request.binding.subject.clone(),
        acquisition.observed_at,
        payload,
    )
    .used_capability(used)
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
    synthetic_cache_executor_result::MODULE
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
        "the negotiated response or payload bound is too small for nq.synthetic_cache_executor_result/v1 testimony",
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

fn coverage(name: &str, state: CoverageState) -> Result<CoverageDeclaration, CollectionAbort> {
    Ok(CoverageDeclaration {
        kind: token(CoverageKind::new(name))?,
        subject: None,
        state,
        detail: None,
    })
}

fn backend_provenance() -> Result<BackendProvenance, CollectionAbort> {
    Ok(BackendProvenance {
        implementation: BackendIdentity {
            name: token(ImplementationName::new("nq-synthetic-cache-result-helper"))?,
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            digest: None,
        },
        // This implementation invokes no backend command or shell. Binary and
        // execution-chain identity are independently pinned by admission.
        tools: Vec::new(),
    })
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

trait ResultSource {
    fn read(&self, request: &HelperRequest) -> Result<ResultAcquisition, String>;
}
struct SystemResultSource;

#[derive(Deserialize)]
struct DocketRow {
    attempt: String,
    executor_marker: String,
    subject: String,
    scope: String,
    work: String,
    work_schema: String,
    executor_plan: String,
    executor_program_digest: String,
    settlement: String,
    receipt: String,
    outcome: String,
}

impl ResultSource for SystemResultSource {
    fn read(&self, request: &HelperRequest) -> Result<ResultAcquisition, String> {
        let scope: ResultScope = serde_json::from_value(request.binding.scope.value.clone())
            .map_err(|e| e.to_string())?;
        read_result_scope(&scope)
    }
}

fn read_result_scope(scope: &ResultScope) -> Result<ResultAcquisition, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&scope.executor_record)
        .map_err(|e| format!("executor record unavailable: {e}"))?;
    if !file
        .metadata()
        .map_err(|e| format!("executor record metadata unavailable: {e}"))?
        .file_type()
        .is_file()
    {
        return Err("executor record is not a regular file".into());
    }
    let mut bytes = Vec::with_capacity(MAX_RECORD_BYTES.min(8192));
    file.take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("executor record unavailable: {e}"))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("executor record exceeds 65536 bytes".into());
    }
    let record: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("executor record invalid: {e}"))?;
    if serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes {
        return Err("executor record is not exact canonical JSON".into());
    }
    if record.get("evidence_schema").and_then(Value::as_str)
        != Some("maude.local-compose.executor-evidence/v1")
        || record.get("outcome").and_then(Value::as_str) != Some("success")
    {
        return Err("executor record schema or outcome differs".into());
    }
    let dispatch = record
        .get("dispatch")
        .and_then(Value::as_object)
        .ok_or("dispatch absent")?;
    let outcome = record
        .get("docket_outcome")
        .and_then(Value::as_object)
        .ok_or("docket outcome absent")?;
    let conn =
        Connection::open_with_flags(&scope.docket_database, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("Docket database unavailable: {e}"))?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN;")
        .map_err(|e| e.to_string())?;
    let row=conn.query_row("SELECT attempt,executor_marker,subject,scope,work,work_schema,executor_plan,executor_program_digest,settlement,receipt,outcome FROM governed_loop_attempt WHERE attempt=?1",[&scope.attempt],|r|Ok(DocketRow{attempt:r.get(0)?,executor_marker:r.get(1)?,subject:r.get(2)?,scope:r.get(3)?,work:r.get(4)?,work_schema:r.get(5)?,executor_plan:r.get(6)?,executor_program_digest:r.get(7)?,settlement:r.get(8)?,receipt:r.get(9)?,outcome:r.get(10)?})).map_err(|e|format!("settled Docket attempt unavailable: {e}"))?;
    fn field<'a>(o: &'a serde_json::Map<String, Value>, n: &str) -> Result<&'a str, String> {
        o.get(n)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{n} absent"))
    }
    if row.attempt != scope.attempt
        || row.executor_marker != scope.marker
        || row.subject != scope.subject
        || row.scope != scope.scope
        || row.work != scope.work
        || row.work_schema != scope.work_schema
        || row.executor_plan != scope.executor_plan
        || row.executor_program_digest != scope.executor_program_digest
        || row.outcome != "success"
        || field(dispatch, "attempt")? != row.attempt
        || field(dispatch, "marker")? != row.executor_marker
        || field(dispatch, "subject")? != row.subject
        || field(dispatch, "scope")? != row.scope
        || field(dispatch, "work")? != row.work
        || field(dispatch, "work_schema")? != row.work_schema
        || field(outcome, "attempt")? != row.attempt
        || field(outcome, "marker")? != row.executor_marker
        || field(outcome, "receipt")? != row.receipt
        || field(outcome, "outcome")? != "success"
    {
        return Err("Docket row and executor result binding differ".into());
    }
    let mut preimage = record.as_object().ok_or("record object absent")?.clone();
    preimage.remove("docket_outcome");
    let canonical = serde_json::to_vec(&Value::Object(preimage)).map_err(|e| e.to_string())?;
    if domain_digest("maude.local-compose.executor-evidence/v1", &canonical) != row.receipt {
        return Err("executor receipt mismatch".into());
    }
    let evidence = record
        .get("evidence")
        .and_then(Value::as_object)
        .ok_or("evidence absent")?;
    let sequence = evidence
        .get("cache_sequence")
        .and_then(Value::as_array)
        .ok_or("cache sequence absent")?
        .iter()
        .map(cache_row)
        .collect::<Result<Vec<_>, _>>()?;
    let failures = evidence
        .get("failure_requests")
        .and_then(Value::as_array)
        .ok_or("failure requests absent")?
        .iter()
        .map(|v| {
            v.get("cache_node")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or("failure cache node absent".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let restored = evidence
        .get("restored_nodes")
        .and_then(Value::as_array)
        .ok_or("restored nodes absent")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or("restored node invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let health = evidence
        .get("health")
        .and_then(|v| v.get("status"))
        .and_then(Value::as_u64)
        .ok_or("health absent")?;
    let millis = record
        .get("observed_at_unix_ms")
        .and_then(Value::as_i64)
        .ok_or("observation time absent")?;
    let observed_at =
        chrono::DateTime::from_timestamp_millis(millis).ok_or("observation time invalid")?;
    Ok(ResultAcquisition {
        observed_at,
        payload: json!({"attempt":row.attempt,"marker":row.executor_marker,"subject":row.subject,"scope":row.scope,"work":row.work,"work_schema":row.work_schema,"executor_plan":row.executor_plan,"executor_program_digest":row.executor_program_digest,"settlement":row.settlement,"receipt":row.receipt,"outcome":row.outcome,"health_status":health,"cache_sequence":sequence,"failure_cache_nodes":failures,"restored_nodes":restored}),
    })
}

fn cache_row(v: &Value) -> Result<Value, String> {
    Ok(
        json!({"cache":v.get("cache").and_then(Value::as_str).ok_or("cache absent")?,"cache_node":v.get("cache_node").and_then(Value::as_str).ok_or("cache node absent")?,"origin_count":v.get("origin_count").and_then(Value::as_str).ok_or("origin count absent")?,"status":v.get("status").and_then(Value::as_u64).ok_or("status absent")?}),
    )
}
fn domain_digest(domain: &str, payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"ag-ng\0digest\0v1\0");
    h.update((domain.len() as u128).to_be_bytes());
    h.update(domain.as_bytes());
    h.update((payload.len() as u128).to_be_bytes());
    h.update(payload);
    format!("sha256:{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const D: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn fixture() -> (TempDir, ResultScope, Value) {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("docket.sqlite3");
        let record_path = dir.path().join("result.json");
        let mut record = json!({
            "dispatch":{"attempt":D,"marker":D,"subject":D,"scope":D,"work":D,"work_schema":"maude.local-compose-workflow/v1"},
            "evidence":{
                "health":{"status":200},
                "cache_sequence":[
                    {"cache":"MISS","cache_node":"cache-a","origin_count":"1","status":200},
                    {"cache":"MISS","cache_node":"cache-b","origin_count":"2","status":200},
                    {"cache":"HIT","cache_node":"cache-a","origin_count":"1","status":200},
                    {"cache":"HIT","cache_node":"cache-b","origin_count":"2","status":200}
                ],
                "failure_requests":[{"cache_node":"cache-b"},{"cache_node":"cache-b"},{"cache_node":"cache-b"},{"cache_node":"cache-b"}],
                "restored_nodes":["cache-a","cache-b"]
            },
            "evidence_schema":"maude.local-compose.executor-evidence/v1",
            "observed_at_unix_ms":1789128000000_i64,
            "outcome":"success"
        });
        let preimage = serde_json::to_vec(&record).expect("canonical fixture");
        let receipt = domain_digest("maude.local-compose.executor-evidence/v1", &preimage);
        record.as_object_mut().expect("object").insert(
            "docket_outcome".into(),
            json!({"attempt":D,"marker":D,"outcome":"success","receipt":receipt}),
        );
        std::fs::write(&record_path, serde_json::to_vec(&record).expect("record")).expect("write");
        let connection = Connection::open(&database).expect("database");
        connection.execute_batch("CREATE TABLE governed_loop_attempt(attempt TEXT PRIMARY KEY, executor_marker TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, work TEXT NOT NULL, work_schema TEXT NOT NULL, executor_plan TEXT NOT NULL, executor_program_digest TEXT NOT NULL, settlement TEXT NOT NULL, receipt TEXT NOT NULL, outcome TEXT NOT NULL);").expect("schema");
        connection
            .execute(
                "INSERT INTO governed_loop_attempt VALUES (?1,?2,?3,?4,?5,'maude.local-compose-workflow/v1',?6,?7,?8,?9,'success')",
                rusqlite::params![D, D, D, D, D, D, D, D, receipt],
            )
            .expect("row");
        drop(connection);
        let scope = ResultScope {
            attempt: D.into(),
            marker: D.into(),
            subject: D.into(),
            scope: D.into(),
            work: D.into(),
            work_schema: "maude.local-compose-workflow/v1".into(),
            executor_plan: D.into(),
            executor_program_digest: D.into(),
            docket_database: database.to_string_lossy().into_owned(),
            executor_record: record_path.to_string_lossy().into_owned(),
        };
        (dir, scope, record)
    }

    #[test]
    fn reads_exact_settled_result_and_preserves_original_time() {
        let (_dir, scope, _) = fixture();
        let result = read_result_scope(&scope).expect("matching records");
        assert_eq!(result.observed_at.timestamp_millis(), 1_789_128_000_000);
        assert_eq!(result.payload["cache_sequence"][2]["cache"], "HIT");
    }

    #[test]
    fn refuses_wrong_subject_binding() {
        let (_dir, mut scope, _) = fixture();
        scope.subject = format!("sha256:{}", "e".repeat(64));
        assert!(
            read_result_scope(&scope)
                .unwrap_err()
                .contains("binding differ")
        );
    }

    #[test]
    fn refuses_receipt_mismatch() {
        let (_dir, scope, mut record) = fixture();
        record["evidence"]["health"]["status"] = json!(503);
        std::fs::write(&scope.executor_record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            read_result_scope(&scope)
                .unwrap_err()
                .contains("receipt mismatch")
        );
    }

    #[test]
    fn refuses_missing_record_schema() {
        let (_dir, scope, mut record) = fixture();
        record.as_object_mut().unwrap().remove("evidence_schema");
        std::fs::write(&scope.executor_record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            read_result_scope(&scope)
                .unwrap_err()
                .contains("schema or outcome")
        );
    }

    #[test]
    fn refuses_mismatched_nested_attempt() {
        let (_dir, scope, mut record) = fixture();
        record["docket_outcome"]["attempt"] = json!(format!("sha256:{}", "a".repeat(64)));
        std::fs::write(&scope.executor_record, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            read_result_scope(&scope)
                .unwrap_err()
                .contains("binding differ")
        );
    }

    #[test]
    fn refuses_missing_attempt() {
        let (_dir, mut scope, _) = fixture();
        scope.attempt = format!("sha256:{}", "f".repeat(64));
        assert!(
            read_result_scope(&scope)
                .unwrap_err()
                .contains("unavailable")
        );
    }
}
