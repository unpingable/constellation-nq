use std::collections::BTreeSet;

use serde_json::Value;
use thiserror::Error;

use crate::{
    Capability, CollectionBounds, CoverageState, EVIDENCE_REPORT_SCHEMA, EvidenceReport,
    HELPER_PROTOCOL_VERSION, HELPER_RESPONSE_SCHEMA, HelperRequest, HelperResponse,
    MAX_COVERAGE_ENTRIES, MAX_OBSERVATIONS, MAX_REPORT_ERRORS, MAX_RESPONSE_FRAME_BYTES,
    ResponseOutcome, canonical_json_bytes,
};

const MAX_BINDING_BYTES: usize = 64 * 1_024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1_024;
const MAX_MESSAGE_BYTES: usize = 4 * 1_024;
const MAX_BACKEND_IDENTITIES: usize = 64;
const MAX_BACKEND_VERSION_BYTES: usize = 512;
const MAX_HARD_PAYLOAD_BYTES: usize = 1_048_576;

/// Common-envelope validation failure.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// A document advertised the wrong schema identifier.
    #[error("{document} schema must be {expected:?}, got {actual:?}")]
    InvalidSchema {
        /// Document being validated.
        document: &'static str,
        /// Required exact schema identifier.
        expected: &'static str,
        /// Received schema identifier.
        actual: String,
    },
    /// A request advertised an unsupported exact protocol version.
    #[error("protocol version must be {expected:?}, got {actual:?}")]
    InvalidProtocolVersion {
        /// Required exact protocol identifier.
        expected: &'static str,
        /// Received protocol identifier.
        actual: String,
    },
    /// A field failed a common structural law.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },
    /// A bounded field exceeded its limit.
    #[error("{field} has size/count {actual}; limit is {limit}")]
    BoundExceeded {
        /// Stable field path.
        field: &'static str,
        /// Permitted maximum.
        limit: usize,
        /// Actual size or count.
        actual: usize,
    },
    /// A set-like ordered list contained a duplicate.
    #[error("duplicate {field} value {value:?}")]
    Duplicate {
        /// Stable field path.
        field: &'static str,
        /// Duplicate's stable text representation.
        value: String,
    },
    /// A response failed to echo a request-controlled field exactly.
    #[error("response echo differs from request at {field}")]
    EchoMismatch {
        /// Stable mismatched field path.
        field: &'static str,
    },
    /// A report claimed use of a capability outside its grant.
    #[error("report used ungranted capability {0}")]
    CapabilityEscape(Capability),
    /// Canonical serialization needed for a bound check failed.
    #[error("cannot measure {field}: {source}")]
    Canonicalization {
        /// Stable field path.
        field: &'static str,
        /// Serialization failure.
        #[source]
        source: crate::CanonicalizationError,
    },
}

/// Checks a request's common envelope, deadline, capability set, and bounds.
///
/// # Errors
///
/// Returns [`ValidationError`] for any invalid common field or hard bound.
pub fn validate_request(request: &HelperRequest) -> Result<(), ValidationError> {
    exact_schema("request", &request.schema, crate::HELPER_REQUEST_SCHEMA)?;
    if request.protocol_version != HELPER_PROTOCOL_VERSION {
        return Err(ValidationError::InvalidProtocolVersion {
            expected: HELPER_PROTOCOL_VERSION,
            actual: request.protocol_version.clone(),
        });
    }
    if request.deadline.expires_at_ns == 0 {
        return Err(invalid(
            "deadline.expires_at_ns",
            "zero is not an absolute monotonic deadline",
        ));
    }
    validate_bounds(&request.bounds)?;
    validate_unique_capabilities(&request.granted_capabilities, "granted_capabilities")?;
    bounded_json(
        "binding.scope.value",
        &request.binding.scope.value,
        MAX_BINDING_BYTES,
    )?;
    bounded_json(
        "binding.vantage.value",
        &request.binding.vantage.value,
        MAX_BINDING_BYTES,
    )?;
    if let Some(checkpoint) = &request.checkpoint {
        bounded_json(
            "checkpoint.value",
            &checkpoint.value,
            request.bounds.max_checkpoint_bytes as usize,
        )?;
    }
    if let Some(selection) = &request.passive_host_load_sample {
        if selection.schema != crate::PASSIVE_HOST_LOAD_SELECTION_SCHEMA_V1 {
            return Err(invalid(
                "passive_host_load_sample.schema",
                "unsupported passive host-load selection schema",
            ));
        }
        if selection.max_age_ms == 0 || selection.max_age_ms > 300_000 {
            return Err(invalid(
                "passive_host_load_sample.max_age_ms",
                "must be between 1 and the nq.host/v1 300000ms reliance horizon",
            ));
        }
        for (field, value) in [
            (
                "passive_host_load_sample.observer_profile",
                selection.observer_profile.as_str(),
            ),
            (
                "passive_host_load_sample.producer_issuer",
                selection.producer_issuer.as_str(),
            ),
            (
                "passive_host_load_sample.producer_key_id",
                selection.producer_key_id.as_str(),
            ),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(invalid(field, "must contain 1 through 256 UTF-8 bytes"));
            }
        }
    }
    Ok(())
}

fn validate_bounds(bounds: &CollectionBounds) -> Result<(), ValidationError> {
    if bounds.max_response_bytes < 256 {
        return Err(invalid(
            "bounds.max_response_bytes",
            "must be at least 256 bytes",
        ));
    }
    upper_bound(
        "bounds.max_response_bytes",
        bounds.max_response_bytes as usize,
        MAX_RESPONSE_FRAME_BYTES,
    )?;
    upper_bound(
        "bounds.max_observations",
        bounds.max_observations as usize,
        MAX_OBSERVATIONS,
    )?;
    upper_bound(
        "bounds.max_payload_bytes",
        bounds.max_payload_bytes as usize,
        MAX_HARD_PAYLOAD_BYTES,
    )?;
    upper_bound(
        "bounds.max_coverage_entries",
        bounds.max_coverage_entries as usize,
        MAX_COVERAGE_ENTRIES,
    )?;
    upper_bound(
        "bounds.max_report_errors",
        bounds.max_report_errors as usize,
        MAX_REPORT_ERRORS,
    )?;
    upper_bound(
        "bounds.max_checkpoint_bytes",
        bounds.max_checkpoint_bytes as usize,
        MAX_HARD_PAYLOAD_BYTES,
    )?;
    Ok(())
}

/// Checks a report's profile-independent structural and lifecycle laws.
///
/// Profile vocabulary, coverage completeness, field consistency, and subject
/// correlation remain the compiled profile module's responsibility.
///
/// # Errors
///
/// Returns [`ValidationError`] for invalid report structure, status
/// inconsistency, duplicate set entries, or a protocol-wide hard bound.
#[allow(clippy::too_many_lines)]
pub fn validate_report(report: &EvidenceReport) -> Result<(), ValidationError> {
    exact_schema("evidence report", &report.schema, EVIDENCE_REPORT_SCHEMA)?;
    bounded_json(
        "report.binding.scope.value",
        &report.binding.scope.value,
        MAX_BINDING_BYTES,
    )?;
    bounded_json(
        "report.binding.vantage.value",
        &report.binding.vantage.value,
        MAX_BINDING_BYTES,
    )?;
    upper_bound(
        "report.coverage",
        report.coverage.len(),
        MAX_COVERAGE_ENTRIES,
    )?;
    upper_bound(
        "report.observations",
        report.observations.len(),
        MAX_OBSERVATIONS,
    )?;
    upper_bound("report.errors", report.errors.len(), MAX_REPORT_ERRORS)?;
    upper_bound(
        "report.backend.tools",
        report.backend.tools.len(),
        MAX_BACKEND_IDENTITIES,
    )?;

    let mut coverage = BTreeSet::new();
    for declaration in &report.coverage {
        let key = (declaration.kind.clone(), declaration.subject.clone());
        if !coverage.insert(key) {
            return Err(ValidationError::Duplicate {
                field: "report.coverage(kind,subject)",
                value: format!(
                    "{}:{}",
                    declaration.kind,
                    declaration
                        .subject
                        .as_ref()
                        .map_or("<root>", crate::SubjectId::as_str)
                ),
            });
        }
        if let Some(detail) = &declaration.detail {
            bounded_json("report.coverage[].detail", detail, MAX_DIAGNOSTIC_BYTES)?;
        }
    }

    for (index, observation) in report.observations.iter().enumerate() {
        if observation.ordinal as usize != index {
            return Err(invalid(
                "report.observations[].ordinal",
                format!(
                    "ordinal {} appears at position {index}; ordinals must be contiguous from zero",
                    observation.ordinal
                ),
            ));
        }
        bounded_json(
            "report.observations[].payload",
            &observation.payload,
            MAX_HARD_PAYLOAD_BYTES,
        )?;
    }

    for error in &report.errors {
        bounded_nonempty_text("report.errors[].message", &error.message, MAX_MESSAGE_BYTES)?;
        if let Some(ordinal) = error.observation_ordinal
            && ordinal as usize >= report.observations.len()
        {
            return Err(invalid(
                "report.errors[].observation_ordinal",
                format!("ordinal {ordinal} does not identify an observation"),
            ));
        }
    }

    validate_unique_capabilities(&report.used_capabilities, "report.used_capabilities")?;
    validate_backend(
        &report.backend.implementation,
        "report.backend.implementation",
    )?;
    for tool in &report.backend.tools {
        validate_backend(tool, "report.backend.tools[]")?;
    }
    if let Some(checkpoint) = &report.next_checkpoint {
        bounded_json(
            "report.next_checkpoint.value",
            &checkpoint.value,
            MAX_HARD_PAYLOAD_BYTES,
        )?;
    }

    match report.status {
        crate::ReportStatus::Complete => {
            if report
                .coverage
                .iter()
                .any(|entry| entry.state != CoverageState::Complete)
            {
                return Err(invalid(
                    "report.status",
                    "complete report contains partial or unavailable coverage",
                ));
            }
            if report
                .errors
                .iter()
                .any(|error| error.severity == crate::ErrorSeverity::Error)
            {
                return Err(invalid(
                    "report.status",
                    "complete report contains an error-severity report error",
                ));
            }
        }
        crate::ReportStatus::Failed => {
            if !report
                .errors
                .iter()
                .any(|error| error.severity == crate::ErrorSeverity::Error)
            {
                return Err(invalid(
                    "report.status",
                    "failed report must retain at least one error-severity report error",
                ));
            }
        }
        crate::ReportStatus::Partial => {}
    }
    Ok(())
}

fn validate_backend(
    identity: &crate::BackendIdentity,
    field: &'static str,
) -> Result<(), ValidationError> {
    if let Some(version) = &identity.version {
        bounded_nonempty_text(field, version, MAX_BACKEND_VERSION_BYTES)?;
    }
    Ok(())
}

/// Checks a response without assuming a particular originating request.
///
/// # Errors
///
/// Returns [`ValidationError`] for any invalid common response, report, or
/// refusal field.
pub fn validate_response(response: &HelperResponse) -> Result<(), ValidationError> {
    exact_schema("response", &response.schema, HELPER_RESPONSE_SCHEMA)?;
    if response.echo.protocol_version != HELPER_PROTOCOL_VERSION {
        return Err(ValidationError::InvalidProtocolVersion {
            expected: HELPER_PROTOCOL_VERSION,
            actual: response.echo.protocol_version.clone(),
        });
    }
    if response.echo.deadline.expires_at_ns == 0 {
        return Err(invalid(
            "echo.deadline.expires_at_ns",
            "zero is not an absolute monotonic deadline",
        ));
    }
    validate_bounds(&response.echo.bounds)?;
    validate_unique_capabilities(
        &response.echo.granted_capabilities,
        "echo.granted_capabilities",
    )?;
    bounded_json(
        "echo.binding.scope.value",
        &response.echo.binding.scope.value,
        MAX_BINDING_BYTES,
    )?;
    bounded_json(
        "echo.binding.vantage.value",
        &response.echo.binding.vantage.value,
        MAX_BINDING_BYTES,
    )?;
    if let Some(checkpoint) = &response.echo.checkpoint {
        bounded_json(
            "echo.checkpoint.value",
            &checkpoint.value,
            response.echo.bounds.max_checkpoint_bytes as usize,
        )?;
    }
    match &response.outcome {
        ResponseOutcome::Report { report } => validate_report(report)?,
        ResponseOutcome::Refusal { refusal } => {
            bounded_nonempty_text("refusal.message", &refusal.message, MAX_MESSAGE_BYTES)?;
            bounded_json("refusal.details", &refusal.details, MAX_DIAGNOSTIC_BYTES)?;
            validate_refusal_pair(refusal)?;
        }
    }
    Ok(())
}

fn validate_refusal_pair(refusal: &crate::Refusal) -> Result<(), ValidationError> {
    use crate::{RefusalBoundary as Boundary, RefusalCode as Code};

    let expected = match refusal.code {
        Code::UnsupportedProtocol => Boundary::Protocol,
        Code::UnknownProfile | Code::ProfileDigestMismatch => Boundary::Profile,
        Code::UnsupportedScope => Boundary::Scope,
        Code::UnsupportedVantage => Boundary::Vantage,
        Code::CapabilityDenied => Boundary::Capability,
        Code::DeadlineExpired => Boundary::Deadline,
        Code::BoundsUnsupported | Code::ResourceExhausted => Boundary::Resource,
        Code::CheckpointInvalid => Boundary::Checkpoint,
        Code::CollectionFailed => Boundary::Collection,
        Code::InternalError => Boundary::Internal,
    };
    if refusal.boundary != expected {
        return Err(invalid(
            "refusal.boundary",
            format!(
                "boundary {:?} is inconsistent with refusal code {:?}; expected {:?}",
                refusal.boundary, refusal.code, expected
            ),
        ));
    }
    Ok(())
}

/// Checks exact echo, identity, capability-subset, and negotiated-bound laws.
///
/// # Errors
///
/// Returns [`ValidationError`] if either document is invalid or the response
/// escapes any identity, capability, cardinality, payload, or byte bound fixed
/// by `request`.
pub fn validate_exchange(
    request: &HelperRequest,
    response: &HelperResponse,
) -> Result<(), ValidationError> {
    validate_request(request)?;
    validate_response(response)?;

    let expected = crate::RequestEcho::from(request);
    if response.echo.protocol_version != expected.protocol_version {
        return Err(echo("echo.protocol_version"));
    }
    if response.echo.request_id != expected.request_id {
        return Err(echo("echo.request_id"));
    }
    if response.echo.instance_id != expected.instance_id {
        return Err(echo("echo.instance_id"));
    }
    if response.echo.profile != expected.profile {
        return Err(echo("echo.profile"));
    }
    if response.echo.binding != expected.binding {
        return Err(echo("echo.binding"));
    }
    if response.echo.granted_capabilities != expected.granted_capabilities {
        return Err(echo("echo.granted_capabilities"));
    }
    if response.echo.checkpoint != expected.checkpoint {
        return Err(echo("echo.checkpoint"));
    }
    if response.echo.passive_host_load_sample != expected.passive_host_load_sample {
        return Err(echo("echo.passive_host_load_sample"));
    }
    if response.echo.deadline != expected.deadline {
        return Err(echo("echo.deadline"));
    }
    if response.echo.bounds != expected.bounds {
        return Err(echo("echo.bounds"));
    }

    let response_size = canonical_json_bytes(response)
        .map_err(|source| ValidationError::Canonicalization {
            field: "response",
            source,
        })?
        .len()
        + 1;
    upper_bound(
        "response frame",
        response_size,
        request.bounds.max_response_bytes as usize,
    )?;

    match &response.outcome {
        ResponseOutcome::Report { report } => {
            if report.profile != request.profile {
                return Err(echo("outcome.report.profile"));
            }
            if report.binding != request.binding {
                return Err(echo("outcome.report.binding"));
            }
            upper_bound(
                "report.observations",
                report.observations.len(),
                request.bounds.max_observations as usize,
            )?;
            upper_bound(
                "report.coverage",
                report.coverage.len(),
                request.bounds.max_coverage_entries as usize,
            )?;
            upper_bound(
                "report.errors",
                report.errors.len(),
                request.bounds.max_report_errors as usize,
            )?;
            for observation in &report.observations {
                bounded_json(
                    "report.observations[].payload",
                    &observation.payload,
                    request.bounds.max_payload_bytes as usize,
                )?;
            }
            if let Some(checkpoint) = &report.next_checkpoint {
                bounded_json(
                    "report.next_checkpoint.value",
                    &checkpoint.value,
                    request.bounds.max_checkpoint_bytes as usize,
                )?;
            }
            let granted: BTreeSet<_> = request.granted_capabilities.iter().collect();
            for capability in &report.used_capabilities {
                if !granted.contains(capability) {
                    return Err(ValidationError::CapabilityEscape(capability.clone()));
                }
            }
        }
        ResponseOutcome::Refusal { refusal } => {
            if refusal.responsible_instance_id != request.instance_id {
                return Err(echo("outcome.refusal.responsible_instance_id"));
            }
        }
    }
    Ok(())
}

fn exact_schema(
    document: &'static str,
    actual: &str,
    expected: &'static str,
) -> Result<(), ValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ValidationError::InvalidSchema {
            document,
            expected,
            actual: actual.to_owned(),
        })
    }
}

fn validate_unique_capabilities(
    capabilities: &[Capability],
    field: &'static str,
) -> Result<(), ValidationError> {
    let mut seen = BTreeSet::new();
    for capability in capabilities {
        if !seen.insert(capability) {
            return Err(ValidationError::Duplicate {
                field,
                value: capability.to_string(),
            });
        }
    }
    Ok(())
}

fn bounded_nonempty_text(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    upper_bound(field, value.len(), limit)
}

fn bounded_json(field: &'static str, value: &Value, limit: usize) -> Result<(), ValidationError> {
    let actual = canonical_json_bytes(value)
        .map_err(|source| ValidationError::Canonicalization { field, source })?
        .len();
    upper_bound(field, actual, limit)
}

fn upper_bound(field: &'static str, actual: usize, limit: usize) -> Result<(), ValidationError> {
    if actual > limit {
        Err(ValidationError::BoundExceeded {
            field,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ValidationError {
    ValidationError::InvalidField {
        field,
        reason: reason.into(),
    }
}

fn echo(field: &'static str) -> ValidationError {
    ValidationError::EchoMismatch { field }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use serde_json::json;

    use super::*;
    use crate::{
        BackendIdentity, BackendProvenance, CoverageDeclaration, CoverageKind, ErrorCode,
        EvidenceReport, ImplementationName, Observation, ObservationKind, ProfileBinding,
        ProfileId, ProfileVersion, ReportError, ReportStatus, ScopeBinding, ScopeKind,
        Sha256Digest, SubjectBinding, SubjectId, VantageBinding, VantageKind,
    };

    fn report() -> EvidenceReport {
        let profile = ProfileBinding {
            id: ProfileId::new("nq.conformance").unwrap(),
            version: ProfileVersion::new("1").unwrap(),
            digest: Sha256Digest::parse(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };
        let binding = SubjectBinding {
            subject: SubjectId::new("conformance:test").unwrap(),
            scope: ScopeBinding {
                kind: ScopeKind::new("fixture").unwrap(),
                value: json!({"id": "test"}),
            },
            vantage: VantageBinding {
                kind: VantageKind::new("local").unwrap(),
                value: json!({}),
            },
        };
        let observed_at = chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        EvidenceReport {
            schema: EVIDENCE_REPORT_SCHEMA.to_owned(),
            profile,
            binding: binding.clone(),
            observed_at,
            status: ReportStatus::Complete,
            coverage: vec![CoverageDeclaration {
                kind: CoverageKind::new("echo").unwrap(),
                subject: None,
                state: CoverageState::Complete,
                detail: None,
            }],
            observations: vec![Observation {
                ordinal: 0,
                kind: ObservationKind::new("echo").unwrap(),
                subject: binding.subject,
                observed_at,
                payload: json!({"ok": true}),
            }],
            errors: vec![],
            used_capabilities: vec![],
            backend: BackendProvenance {
                implementation: BackendIdentity {
                    name: ImplementationName::new("test").unwrap(),
                    version: Some("1".to_owned()),
                    digest: None,
                },
                tools: vec![],
            },
            next_checkpoint: None,
        }
    }

    #[test]
    fn rejects_non_contiguous_ordinals() {
        let mut report = report();
        report.observations[0].ordinal = 7;
        assert!(matches!(
            validate_report(&report),
            Err(ValidationError::InvalidField {
                field: "report.observations[].ordinal",
                ..
            })
        ));
    }

    #[test]
    fn failed_report_is_retained_only_with_structured_error() {
        let mut report = report();
        report.status = ReportStatus::Failed;
        assert!(validate_report(&report).is_err());
        report.errors.push(ReportError {
            code: ErrorCode::new("backend_failed").unwrap(),
            severity: crate::ErrorSeverity::Error,
            message: "backend failed".to_owned(),
            subject: None,
            observation_ordinal: None,
            retriable: true,
        });
        assert!(validate_report(&report).is_ok());
    }
}
