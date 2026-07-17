//! Hostile profile-validation and detector-lifecycle corpus.

use std::collections::BTreeSet;

use chrono::{Duration, TimeZone as _, Utc};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorState, EvidenceWatermark, ProfileModule,
    ProfileRefusalCode, ReportInput, ScopeGrant, SemanticCoverageState, SemanticReportStatus,
    ValidatedReport, ValidationContext, VantageGrant, all_profiles, conformance, host,
    resolve_profile,
};
use serde_json::{Value, json};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0)
        .single()
        .expect("fixed date is valid")
}

fn conformance_context() -> ValidationContext {
    ValidationContext {
        instance_id: "instance:conformance".to_owned(),
        request_subject: "conformance:fixture-1".to_owned(),
        scope: ScopeGrant {
            kind: "fixture".to_owned(),
            value: json!({"id": "fixture-1", "nonce": "nq-nonce-1"}),
        },
        vantage: VantageGrant {
            kind: "local".to_owned(),
            value: json!({}),
        },
        granted_capabilities: BTreeSet::new(),
        received_at: now(),
        max_observations: 1,
        max_future_skew: Duration::seconds(5),
    }
}

fn conformance_payload() -> Value {
    json!({
        "evidence_basis": {
            "scope": {"kind": "fixture", "value": {"id": "fixture-1", "nonce": "nq-nonce-1"}},
            "vantage": {"kind": "local", "value": {}},
            "access_path": "process",
            "basis": "request_echo",
            "regime": "conformance",
            "capabilities_used": []
        },
        "nonce": "nq-nonce-1"
    })
}

fn conformance_report() -> ReportInput {
    let descriptor = conformance::MODULE.descriptor();
    ReportInput {
        report_digest: format!("sha256:{}", "1".repeat(64)),
        profile: descriptor.profile.clone(),
        profile_digest: descriptor
            .digest()
            .expect("compiled descriptor canonicalizes")
            .as_str()
            .to_owned(),
        status: SemanticReportStatus::Complete,
        observed_at: now(),
        coverage: vec![nq_profiles::CoverageInput {
            name: "echo".to_owned(),
            subject: None,
            state: SemanticCoverageState::Complete,
            detail: None,
        }],
        observations: vec![nq_profiles::ObservationInput {
            kind: "echo".to_owned(),
            subject: "conformance:fixture-1".to_owned(),
            ordinal: 0,
            observed_at: now(),
            payload: conformance_payload(),
        }],
        error_count: 0,
        failure_error_count: 0,
        used_capabilities: BTreeSet::new(),
    }
}

fn host_context(received_at: chrono::DateTime<Utc>) -> ValidationContext {
    ValidationContext {
        instance_id: "instance:host".to_owned(),
        request_subject: "host:node-1".to_owned(),
        scope: ScopeGrant {
            kind: "host".to_owned(),
            value: json!({"id": "node-1"}),
        },
        vantage: VantageGrant {
            kind: "local".to_owned(),
            value: json!({}),
        },
        granted_capabilities: BTreeSet::from(["read_procfs".to_owned()]),
        received_at,
        max_observations: 1,
        max_future_skew: Duration::seconds(5),
    }
}

fn host_payload(load_1m: Option<f64>) -> Value {
    json!({
        "evidence_basis": {
            "scope": {"kind": "host", "value": {"id": "node-1"}},
            "vantage": {"kind": "local", "value": {}},
            "access_path": "procfs",
            "basis": "kernel_snapshot",
            "regime": "normal",
            "capabilities_used": ["read_procfs"]
        },
        "hostname": "node-1",
        "uptime_seconds": 86400,
        "cpu_count": 2,
        "load_1m": load_1m
    })
}

fn host_report(at: chrono::DateTime<Utc>, load_1m: f64) -> ReportInput {
    let descriptor = host::MODULE.descriptor();
    ReportInput {
        report_digest: format!("sha256:{}", "2".repeat(64)),
        profile: descriptor.profile.clone(),
        profile_digest: descriptor
            .digest()
            .expect("compiled descriptor canonicalizes")
            .as_str()
            .to_owned(),
        status: SemanticReportStatus::Complete,
        observed_at: at,
        coverage: ["host_identity", "uptime", "load"]
            .into_iter()
            .map(|name| nq_profiles::CoverageInput {
                name: name.to_owned(),
                subject: None,
                state: SemanticCoverageState::Complete,
                detail: None,
            })
            .collect(),
        observations: vec![nq_profiles::ObservationInput {
            kind: "host_snapshot".to_owned(),
            subject: "host:node-1".to_owned(),
            ordinal: 0,
            observed_at: at,
            payload: host_payload(Some(load_1m)),
        }],
        error_count: 0,
        failure_error_count: 0,
        used_capabilities: BTreeSet::from(["read_procfs".to_owned()]),
    }
}

fn failed_host_report(at: chrono::DateTime<Utc>) -> ReportInput {
    let mut report = host_report(at, 0.0);
    report.report_digest = format!("sha256:{}", "3".repeat(64));
    report.status = SemanticReportStatus::Failed;
    for coverage in &mut report.coverage {
        coverage.state = SemanticCoverageState::Unavailable;
    }
    report.observations.clear();
    report.error_count = 1;
    report.failure_error_count = 1;
    report.used_capabilities.clear();
    report
}

fn detector_report(
    report_id: &str,
    report_sequence: u64,
    report: ValidatedReport,
) -> DetectorReport {
    DetectorReport {
        report_id: report_id.to_owned(),
        report_sequence,
        report,
    }
}

#[test]
fn registry_is_explicit_and_exact() {
    assert_eq!(all_profiles().len(), 2);
    assert!(resolve_profile("nq.conformance", 1).is_some());
    assert!(resolve_profile("nq.host", 1).is_some());
    assert!(resolve_profile("nq.host", 2).is_none());
    assert_ne!(
        conformance::MODULE.descriptor().digest().unwrap(),
        host::MODULE.descriptor().digest().unwrap()
    );
    assert!(
        host::MODULE.detectors()[0]
            .descriptor()
            .digest()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn admits_complete_conformance_and_typed_projection() {
    let admitted = conformance::MODULE
        .validate(&conformance_context(), &conformance_report())
        .expect("valid echo is admitted");
    let projection = conformance::MODULE
        .project(&admitted)
        .expect("admitted payload projects");
    let echo = projection[0]
        .as_any()
        .downcast_ref::<conformance::EchoProjection>()
        .expect("projection retains concrete profile type");
    assert_eq!(echo.nonce, "nq-nonce-1");
}

#[test]
fn rejects_unknown_observation_kind() {
    let mut report = conformance_report();
    report.observations[0].kind = "helper_claim".to_owned();
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &report)
        .expect_err("unknown kind must remain rejected custody");
    assert_eq!(refusal.code, ProfileRefusalCode::UnknownObservationKind);
    assert_eq!(refusal.instance_id, "instance:conformance");
}

#[test]
fn rejects_duplicate_and_missing_coverage() {
    let mut duplicate = conformance_report();
    duplicate.coverage.push(duplicate.coverage[0].clone());
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &duplicate)
        .expect_err("duplicate coverage must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::DuplicateCoverage);

    let mut missing = conformance_report();
    missing.coverage.clear();
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &missing)
        .expect_err("missing coverage must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::MissingCoverage);
}

#[test]
fn rejects_subject_scope_and_capability_escape() {
    let mut subject_escape = conformance_report();
    subject_escape.observations[0].subject = "conformance:other".to_owned();
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &subject_escape)
        .expect_err("subject expansion must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::SubjectEscape);

    let mut scope_escape = conformance_report();
    scope_escape.observations[0].payload["evidence_basis"]["scope"]["value"]["id"] = json!("other");
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &scope_escape)
        .expect_err("scope expansion must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::ScopeEscape);

    let mut vantage_escape = conformance_report();
    vantage_escape.observations[0].payload["evidence_basis"]["vantage"]["kind"] = json!("remote");
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &vantage_escape)
        .expect_err("vantage replacement must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::VantageEscape);

    let mut capability_escape = conformance_report();
    capability_escape.used_capabilities = BTreeSet::from(["root".to_owned()]);
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &capability_escape)
        .expect_err("capability expansion must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::CapabilityEscape);
}

#[test]
fn rejects_profile_digest_drift_and_cardinality_escape() {
    let mut digest_drift = conformance_report();
    digest_drift.profile_digest = format!("sha256:{}", "f".repeat(64));
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &digest_drift)
        .expect_err("shape conformance does not qualify a different descriptor");
    assert_eq!(refusal.code, ProfileRefusalCode::UnknownProfile);

    let mut too_many = conformance_report();
    let mut second = too_many.observations[0].clone();
    second.ordinal = 1;
    too_many.observations.push(second);
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &too_many)
        .expect_err("request and profile cardinality may not expand");
    assert_eq!(refusal.code, ProfileRefusalCode::ObservationLimitExceeded);
}

#[test]
fn rejects_helper_owned_authority_and_nonce_overclaim() {
    let mut authority = conformance_report();
    authority.observations[0].payload["severity"] = json!("critical");
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &authority)
        .expect_err("helpers cannot emit severity");
    assert_eq!(refusal.code, ProfileRefusalCode::ForbiddenHelperAssertion);

    let mut false_echo = conformance_report();
    false_echo.observations[0].payload["nonce"] = json!("not-the-request");
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &false_echo)
        .expect_err("shape conformance cannot synthesize an echo");
    assert_eq!(refusal.code, ProfileRefusalCode::InconsistentReport);
}

#[test]
fn partial_and_failed_reports_are_valid_testimony_but_cannot_overclaim() {
    let mut partial = conformance_report();
    partial.status = SemanticReportStatus::Partial;
    partial.coverage[0].state = SemanticCoverageState::Partial;
    partial.error_count = 1;
    conformance::MODULE
        .validate(&conformance_context(), &partial)
        .expect("bounded partial testimony is retained");

    let mut failed = conformance_report();
    failed.status = SemanticReportStatus::Failed;
    failed.coverage[0].state = SemanticCoverageState::Unavailable;
    failed.observations.clear();
    failed.error_count = 1;
    failed.failure_error_count = 1;
    conformance::MODULE
        .validate(&conformance_context(), &failed)
        .expect("valid failed testimony is retained");

    let mut overclaim = conformance_report();
    overclaim.observations.clear();
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &overclaim)
        .expect_err("complete coverage without the echo must fail");
    assert_eq!(refusal.code, ProfileRefusalCode::InconsistentReport);

    let mut status_overclaim = conformance_report();
    status_overclaim.coverage[0].state = SemanticCoverageState::Partial;
    let refusal = conformance::MODULE
        .validate(&conformance_context(), &status_overclaim)
        .expect_err("complete status cannot overclaim partial coverage");
    assert_eq!(refusal.code, ProfileRefusalCode::ReportStatusOverclaim);
}

#[test]
fn host_profile_enforces_field_coverage_consistency() {
    let context = host_context(now());
    let mut report = host_report(now(), 1.0);
    report.observations[0].payload["load_1m"] = Value::Null;
    let refusal = host::MODULE
        .validate(&context, &report)
        .expect_err("complete load coverage cannot omit load");
    assert_eq!(refusal.code, ProfileRefusalCode::InconsistentReport);

    let mut partial = host_report(now(), 1.0);
    partial.status = SemanticReportStatus::Partial;
    partial.error_count = 1;
    partial.coverage[1].state = SemanticCoverageState::Unavailable;
    partial.coverage[2].state = SemanticCoverageState::Partial;
    partial.observations[0].payload["uptime_seconds"] = Value::Null;
    partial.observations[0].payload["load_1m"] = Value::Null;
    host::MODULE
        .validate(&context, &partial)
        .expect("partial host testimony with consistent fields is retained");

    host::MODULE
        .validate(&context, &failed_host_report(now()))
        .expect("failed host testimony remains valid testimony");
}

#[test]
fn detector_requires_newest_current_complete_coverage_to_resolve() {
    let current_context = host_context(now());
    let current = detector_report(
        "report:current",
        10,
        host::MODULE
            .validate(&current_context, &host_report(now(), 1.0))
            .expect("complete host report"),
    );
    let detector = host::MODULE.detectors()[0];
    let empty_input = DetectorInput {
        instance_id: "instance:host",
        evaluated_at: now(),
        watermark: EvidenceWatermark(9),
        reports: &[],
    };
    assert_eq!(
        detector.evaluate(&empty_input).state,
        DetectorState::CannotEvaluate
    );
    let input = DetectorInput {
        instance_id: "instance:host",
        evaluated_at: now() + Duration::seconds(30),
        watermark: EvidenceWatermark(10),
        reports: std::slice::from_ref(&current),
    };
    let result = detector.evaluate(&input);
    assert_eq!(result.state, DetectorState::ExplicitlyAbsent);
    assert_eq!(result.evidence[0].report_id, "report:current");
    assert_eq!(result.evidence[0].report_sequence, 10);

    let pressured = detector_report(
        "report:pressured",
        11,
        host::MODULE
            .validate(&current_context, &host_report(now(), 6.0))
            .expect("complete pressured host report"),
    );
    let input = DetectorInput {
        reports: std::slice::from_ref(&pressured),
        ..input
    };
    assert_eq!(detector.evaluate(&input).state, DetectorState::Present);

    let stale_input = DetectorInput {
        evaluated_at: now() + Duration::seconds(301),
        reports: std::slice::from_ref(&current),
        ..input
    };
    assert_eq!(
        detector.evaluate(&stale_input).state,
        DetectorState::CannotEvaluate
    );

    let failed_context = host_context(now() + Duration::seconds(60));
    let newer_failed = detector_report(
        "report:failed",
        12,
        host::MODULE
            .validate(
                &failed_context,
                &failed_host_report(now() + Duration::seconds(60)),
            )
            .expect("failed report is admitted testimony"),
    );
    let mut unrelated_failure = newer_failed.clone();
    unrelated_failure.report.instance_id = "instance:other".to_owned();
    let unrelated_reports = [current.clone(), unrelated_failure];
    let unrelated_input = DetectorInput {
        evaluated_at: now() + Duration::seconds(70),
        reports: &unrelated_reports,
        ..input
    };
    assert_eq!(
        detector.evaluate(&unrelated_input).state,
        DetectorState::ExplicitlyAbsent,
        "a different instance cannot shadow this instance's evidence"
    );
    let reports = [current.clone(), newer_failed];
    let newer_failure_input = DetectorInput {
        evaluated_at: now() + Duration::seconds(70),
        reports: &reports,
        ..input
    };
    let result = detector.evaluate(&newer_failure_input);
    assert_eq!(result.state, DetectorState::CannotEvaluate);
    assert!(result.refusal.is_some());
}

#[test]
fn detector_recency_uses_only_durable_report_sequence() {
    let detector = host::MODULE.detectors()[0];

    let complete = detector_report(
        "report:complete-clock-ahead",
        40,
        host::MODULE
            .validate(
                &host_context(now() + Duration::seconds(100)),
                &host_report(now(), 1.0),
            )
            .expect("complete report with a later receive clock"),
    );
    let failed = detector_report(
        "report:failed-clock-behind",
        41,
        host::MODULE
            .validate(
                &host_context(now() - Duration::seconds(10)),
                &failed_host_report(now() - Duration::seconds(10)),
            )
            .expect("later durable report with an earlier wall clock"),
    );
    let reversed = [failed, complete];
    let result = detector.evaluate(&DetectorInput {
        instance_id: "instance:host",
        evaluated_at: now() + Duration::seconds(30),
        watermark: EvidenceWatermark(41),
        reports: &reversed,
    });
    assert_eq!(
        result.state,
        DetectorState::CannotEvaluate,
        "a later failed report must win even when both timestamps move backward"
    );

    let mut complete_input = host_report(now(), 1.0);
    complete_input.report_digest = format!("sha256:{}", "f".repeat(64));
    let complete = detector_report(
        "report:complete-equal-clock",
        50,
        host::MODULE
            .validate(&host_context(now()), &complete_input)
            .expect("complete equal-clock report"),
    );
    let mut failed_input = failed_host_report(now());
    failed_input.report_digest = format!("sha256:{}", "0".repeat(64));
    let failed = detector_report(
        "report:failed-equal-clock",
        51,
        host::MODULE
            .validate(&host_context(now()), &failed_input)
            .expect("failed equal-clock report"),
    );
    let equal_clocks = [complete, failed];
    let result = detector.evaluate(&DetectorInput {
        instance_id: "instance:host",
        evaluated_at: now() + Duration::seconds(30),
        watermark: EvidenceWatermark(51),
        reports: &equal_clocks,
    });
    assert_eq!(
        result.state,
        DetectorState::CannotEvaluate,
        "digest lexical order must not break equal timestamp ties"
    );
}

#[test]
fn protocol_report_normalization_is_centralized() {
    use nq_protocol::{
        BackendIdentity, BackendProvenance, CoverageDeclaration, CoverageKind, CoverageState,
        EvidenceReport, HelperRequest, ImplementationName, InstanceId, MonotonicDeadline,
        Observation, ObservationKind, ProfileBinding, ProfileId, ProfileVersion, ReportStatus,
        RequestId, ScopeBinding, ScopeKind, Sha256Digest, SubjectBinding, SubjectId,
        VantageBinding, VantageKind,
    };

    let descriptor = conformance::MODULE.descriptor();
    let profile = ProfileBinding {
        id: ProfileId::new("nq.conformance").unwrap(),
        version: ProfileVersion::new("1").unwrap(),
        digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str()).unwrap(),
    };
    let binding = SubjectBinding {
        subject: SubjectId::new("conformance:fixture-1").unwrap(),
        scope: ScopeBinding {
            kind: ScopeKind::new("fixture").unwrap(),
            value: json!({"id": "fixture-1", "nonce": "nq-nonce-1"}),
        },
        vantage: VantageBinding {
            kind: VantageKind::new("local").unwrap(),
            value: json!({}),
        },
    };
    let request = HelperRequest::builder(
        RequestId::new("request:profile-normalization").unwrap(),
        InstanceId::new("instance:conformance").unwrap(),
        profile.clone(),
        binding.clone(),
        MonotonicDeadline::default(),
    )
    .build()
    .expect("request is protocol valid");
    let report = EvidenceReport {
        schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
        profile,
        binding: binding.clone(),
        observed_at: now(),
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
            subject: binding.subject.clone(),
            observed_at: now(),
            payload: conformance_payload(),
        }],
        errors: Vec::new(),
        used_capabilities: Vec::new(),
        backend: BackendProvenance {
            implementation: BackendIdentity {
                name: ImplementationName::new("python-specimen").unwrap(),
                version: Some("1".to_owned()),
                digest: None,
            },
            tools: Vec::new(),
        },
        next_checkpoint: None,
    };

    let normalized = ReportInput::from_protocol_with_digest(&report).expect("normalizes");
    assert_eq!(normalized.profile.id, "nq.conformance");
    assert_eq!(normalized.coverage[0].name, "echo");
    assert_eq!(normalized.observations[0].subject, "conformance:fixture-1");
    let context = ValidationContext::from_request(&request, now(), Duration::seconds(5));
    assert_eq!(context.scope.value["nonce"], "nq-nonce-1");
    conformance::MODULE
        .validate(&context, &normalized)
        .expect("normalized protocol report is admitted");
}
