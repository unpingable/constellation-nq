//! Operator-beta qualification for generic systemd and HTTP profiles.

use std::collections::BTreeSet;

use chrono::{Duration, TimeZone as _, Utc};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorState, EvidenceWatermark, ProfileModule, ReportInput,
    ScopeGrant, SemanticCoverageState, SemanticReportStatus, ThresholdPolicyInput,
    ValidationContext, VantageGrant, all_profiles, http_endpoint, systemd_unit,
};
use nq_protocol::Sha256Digest;
use serde_json::{Value, json};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 0)
        .single()
        .expect("fixed qualification time")
}

fn subject() -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn digest_value(value: &Value) -> Sha256Digest {
    nq_protocol::semantic_digest(value).expect("canonical policy value")
}

fn scope_identity(module: &'static dyn ProfileModule, subject: &str, scope: &ScopeGrant) -> Value {
    let descriptor = module.descriptor();
    let profile = json!({
        "id": descriptor.profile.id,
        "version": descriptor.profile.version.to_string(),
        "digest": descriptor.digest().expect("profile digest").as_str(),
    });
    let digest = nq_protocol::semantic_digest(&json!({
        "schema": "nq.diagnostic_scope.v1",
        "subject": subject,
        "scope": scope,
        "profile": profile,
    }))
    .expect("diagnostic scope identity");
    json!({
        "id": format!("nq.scope.{}", scope.kind),
        "version": descriptor.profile.version.to_string(),
        "digest": digest,
    })
}

fn report(
    module: &'static dyn ProfileModule,
    observed_at: chrono::DateTime<Utc>,
    coverage: &str,
    kind: &str,
    subject: &str,
    payload: Value,
    capabilities: BTreeSet<String>,
) -> ReportInput {
    let descriptor = module.descriptor();
    ReportInput {
        report_digest: format!("sha256:{}", "b".repeat(64)),
        profile: descriptor.profile.clone(),
        profile_digest: descriptor
            .digest()
            .expect("profile digest")
            .as_str()
            .to_owned(),
        status: SemanticReportStatus::Complete,
        observed_at,
        coverage: vec![nq_profiles::CoverageInput {
            name: coverage.to_owned(),
            subject: None,
            state: SemanticCoverageState::Complete,
            detail: None,
        }],
        observations: vec![nq_profiles::ObservationInput {
            kind: kind.to_owned(),
            subject: subject.to_owned(),
            ordinal: 0,
            observed_at,
            payload,
        }],
        error_count: 0,
        failure_error_count: 0,
        used_capabilities: capabilities,
    }
}

fn systemd_context() -> ValidationContext {
    let subject = subject();
    ValidationContext {
        instance_id: "operator-beta-systemd".to_owned(),
        request_subject: subject.clone(),
        scope: ScopeGrant {
            kind: "systemd_unit".to_owned(),
            value: json!({
                "schema": "nq.operator_beta.systemd_unit_scope.v1",
                "subject_identity": subject,
                "target_machine_identity": "machine:fixture-001",
                "unit_name": "constellation-beta-http-fixture.service",
                "unit_file_sha256": format!("sha256:{}", "c".repeat(64)),
                "manager_interface": "org.freedesktop.systemd1",
                "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
            }),
        },
        vantage: VantageGrant {
            kind: "target_local".to_owned(),
            value: json!({}),
        },
        granted_capabilities: BTreeSet::from(["read_systemd_unit".to_owned()]),
        received_at: now(),
        max_observations: 1,
        max_future_skew: Duration::seconds(5),
    }
}

fn systemd_payload(context: &ValidationContext) -> Value {
    json!({
        "evidence_basis": {
            "scope": context.scope,
            "vantage": context.vantage,
            "access_path": "systemd_dbus",
            "basis": "systemd_properties",
            "regime": "normal",
            "capabilities_used": ["read_systemd_unit"],
        },
        "target_machine_identity": "machine:fixture-001",
        "unit_name": "constellation-beta-http-fixture.service",
        "unit_file_sha256": format!("sha256:{}", "c".repeat(64)),
        "manager_object_path": "/org/freedesktop/systemd1",
        "unit_object_path": "/org/freedesktop/systemd1/unit/constellation_2dbeta_2dhttp_2dfixture_2eservice",
        "load_state": "loaded",
        "active_state": "active",
        "sub_state": "running",
        "unit_file_state": "disabled",
    })
}

fn systemd_policy(context: &ValidationContext) -> ThresholdPolicyInput {
    let value = json!({
        "schema": systemd_unit::THRESHOLD_POLICY_SCHEMA,
        "fixture_run_id": "fixture-001",
        "subject_identity": context.request_subject,
        "request_scope": scope_identity(&systemd_unit::MODULE, &context.request_subject, &context.scope),
        "expected_load_state": "loaded",
        "expected_active_state": "active",
        "expected_sub_state": "running",
        "expected_unit_file_state": "disabled",
    });
    ThresholdPolicyInput {
        id: systemd_unit::THRESHOLD_POLICY_ID.to_owned(),
        version: "fixture-001".to_owned(),
        digest: digest_value(&value),
        value,
    }
}

fn http_context() -> ValidationContext {
    let subject = subject();
    ValidationContext {
        instance_id: "operator-beta-http".to_owned(),
        request_subject: subject.clone(),
        scope: ScopeGrant {
            kind: "http_endpoint".to_owned(),
            value: json!({
                "schema": "nq.operator_beta.http_endpoint_scope.v1",
                "subject_identity": subject,
                "controller_vantage_identity": "controller:fixture-001",
                "endpoint": "http://192.0.2.10:18080/healthz",
                "method": "GET",
                "redirect_policy": "refuse",
                "max_response_bytes": 1024,
            }),
        },
        vantage: VantageGrant {
            kind: "controller_http".to_owned(),
            value: json!({"controller_vantage_identity": "controller:fixture-001"}),
        },
        granted_capabilities: BTreeSet::from(["read_http_endpoint".to_owned()]),
        received_at: now(),
        max_observations: 1,
        max_future_skew: Duration::seconds(5),
    }
}

fn http_payload(context: &ValidationContext) -> Value {
    json!({
        "evidence_basis": {
            "scope": context.scope,
            "vantage": context.vantage,
            "access_path": "http_tcp",
            "basis": "http_response",
            "regime": "normal",
            "capabilities_used": ["read_http_endpoint"],
        },
        "controller_vantage_identity": "controller:fixture-001",
        "endpoint": "http://192.0.2.10:18080/healthz",
        "method": "GET",
        "redirect_policy": "refuse",
        "status": 200,
        "body_sha256": format!("sha256:{}", "d".repeat(64)),
        "body_bytes": 3,
    })
}

fn http_policy(context: &ValidationContext) -> ThresholdPolicyInput {
    let value = json!({
        "schema": http_endpoint::THRESHOLD_POLICY_SCHEMA,
        "fixture_run_id": "fixture-001",
        "subject_identity": context.request_subject,
        "request_scope": scope_identity(&http_endpoint::MODULE, &context.request_subject, &context.scope),
        "expected_status": 200,
        "expected_body_sha256": format!("sha256:{}", "d".repeat(64)),
    });
    ThresholdPolicyInput {
        id: http_endpoint::THRESHOLD_POLICY_ID.to_owned(),
        version: "fixture-001".to_owned(),
        digest: digest_value(&value),
        value,
    }
}

#[test]
fn registry_contains_the_two_generic_operator_beta_profiles() {
    let keys: Vec<_> = all_profiles()
        .iter()
        .map(|module| {
            let key = &module.descriptor().profile;
            (key.id.as_str(), key.version)
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            ("nq.conformance", 1),
            ("nq.host", 1),
            ("nq.systemd_unit", 1),
            ("nq.http_endpoint", 1),
        ]
    );
}

#[test]
fn systemd_policy_is_external_bound_and_time_limited() {
    let context = systemd_context();
    let validated = systemd_unit::MODULE
        .validate(
            &context,
            &report(
                &systemd_unit::MODULE,
                now(),
                "systemd_unit_state",
                "systemd_unit_snapshot",
                &context.request_subject,
                systemd_payload(&context),
                BTreeSet::from(["read_systemd_unit".to_owned()]),
            ),
        )
        .expect("exact systemd testimony");
    let occurrence = DetectorReport {
        report_id: "report:systemd".to_owned(),
        report_sequence: 1,
        report: validated,
    };
    let policy = systemd_policy(&context);
    let detector = systemd_unit::MODULE.detectors()[0];
    let input = DetectorInput {
        instance_id: &context.instance_id,
        evaluated_at: now() + Duration::seconds(60),
        watermark: EvidenceWatermark(1),
        threshold_policy: Some(&policy),
        reports: std::slice::from_ref(&occurrence),
    };
    assert_eq!(
        detector.evaluate(&input).state,
        DetectorState::ExplicitlyAbsent
    );

    let stale = DetectorInput {
        evaluated_at: now() + Duration::seconds(61),
        ..input.clone()
    };
    assert_eq!(
        detector.evaluate(&stale).state,
        DetectorState::CannotEvaluate
    );

    let mut mismatch = policy.clone();
    mismatch.value["expected_active_state"] = json!("inactive");
    mismatch.digest = digest_value(&mismatch.value);
    let mismatch_input = DetectorInput {
        threshold_policy: Some(&mismatch),
        ..input.clone()
    };
    assert_eq!(
        detector.evaluate(&mismatch_input).state,
        DetectorState::Present
    );

    let mut wrong_subject = policy.clone();
    wrong_subject.value["subject_identity"] = json!(format!("sha256:{}", "e".repeat(64)));
    wrong_subject.digest = digest_value(&wrong_subject.value);
    let wrong_subject_input = DetectorInput {
        threshold_policy: Some(&wrong_subject),
        ..input.clone()
    };
    assert_eq!(
        detector.evaluate(&wrong_subject_input).state,
        DetectorState::CannotEvaluate
    );

    let missing_policy = DetectorInput {
        threshold_policy: None,
        ..input
    };
    assert_eq!(
        detector.evaluate(&missing_policy).state,
        DetectorState::CannotEvaluate
    );
}

#[test]
fn http_policy_is_external_bound_and_substitution_safe() {
    let context = http_context();
    let validated = http_endpoint::MODULE
        .validate(
            &context,
            &report(
                &http_endpoint::MODULE,
                now(),
                "http_endpoint_response",
                "http_response",
                &context.request_subject,
                http_payload(&context),
                BTreeSet::from(["read_http_endpoint".to_owned()]),
            ),
        )
        .expect("exact HTTP testimony");
    let occurrence = DetectorReport {
        report_id: "report:http".to_owned(),
        report_sequence: 1,
        report: validated,
    };
    let policy = http_policy(&context);
    let detector = http_endpoint::MODULE.detectors()[0];
    let input = DetectorInput {
        instance_id: &context.instance_id,
        evaluated_at: now() + Duration::seconds(30),
        watermark: EvidenceWatermark(1),
        threshold_policy: Some(&policy),
        reports: std::slice::from_ref(&occurrence),
    };
    assert_eq!(
        detector.evaluate(&input).state,
        DetectorState::ExplicitlyAbsent
    );

    let mut mismatch = policy.clone();
    mismatch.value["expected_body_sha256"] = json!(format!("sha256:{}", "f".repeat(64)));
    mismatch.digest = digest_value(&mismatch.value);
    let mismatch_input = DetectorInput {
        threshold_policy: Some(&mismatch),
        ..input.clone()
    };
    assert_eq!(
        detector.evaluate(&mismatch_input).state,
        DetectorState::Present
    );

    let mut changed_without_reseal = policy.clone();
    changed_without_reseal.value["expected_status"] = json!(503);
    let changed_input = DetectorInput {
        threshold_policy: Some(&changed_without_reseal),
        ..input.clone()
    };
    assert_eq!(
        detector.evaluate(&changed_input).state,
        DetectorState::CannotEvaluate
    );

    let mut wrong_scope = context.clone();
    wrong_scope.scope.value["endpoint"] = json!("http://192.0.2.11:18080/healthz");
    assert!(
        http_endpoint::MODULE
            .validate(
                &wrong_scope,
                &report(
                    &http_endpoint::MODULE,
                    now(),
                    "http_endpoint_response",
                    "http_response",
                    &context.request_subject,
                    http_payload(&context),
                    BTreeSet::from(["read_http_endpoint".to_owned()]),
                ),
            )
            .is_err(),
        "subject-equal but scope-substituted evidence must refuse"
    );
}
