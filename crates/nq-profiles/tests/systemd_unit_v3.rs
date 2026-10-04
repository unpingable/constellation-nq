//! `nq.systemd_unit/v3` admission and judgment: only loaded + active is the
//! expected state, every other admitted state is present, an unanswerable
//! query is `cannot_evaluate` carrying the systemd owner's code, and the
//! subject, scope and payload are exact.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, TimeZone, Utc};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorResult, DetectorState, EvidenceWatermark, ProfileModule,
    ReportInput, ScopeGrant, ValidatedReport, ValidationContext, VantageGrant, resolve_profile,
    systemd_unit_v3,
};
use serde_json::{Value, json};

const MACHINE: &str = "1a5b08928e884e73bf4f60a3c73ef497";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 24, 12, 0, 0)
        .single()
        .expect("fixed time")
}

fn module() -> &'static dyn ProfileModule {
    resolve_profile(
        systemd_unit_v3::PROFILE_ID,
        systemd_unit_v3::PROFILE_VERSION,
    )
    .expect("v3 is compiled")
}

fn scope_value(machine: &str, unit: &str) -> Value {
    json!({"schema": systemd_unit_v3::SCOPE_SCHEMA, "machine_id": machine, "unit_name": unit})
}

fn context(subject: &str, scope: Value) -> ValidationContext {
    ValidationContext {
        instance_id: "unit-test".to_owned(),
        request_subject: subject.to_owned(),
        scope: ScopeGrant {
            kind: systemd_unit_v3::SCOPE_KIND.to_owned(),
            value: scope,
        },
        vantage: VantageGrant {
            kind: "local".to_owned(),
            value: json!({}),
        },
        granted_capabilities: BTreeSet::from(["read_systemd_unit".to_owned()]),
        received_at: now(),
        max_observations: 1,
        max_future_skew: Duration::seconds(5),
    }
}

fn cron() -> ValidationContext {
    context(
        &systemd_unit_v3::subject_for(MACHINE, "cron.service"),
        scope_value(MACHINE, "cron.service"),
    )
}

fn protocol_profile() -> Value {
    let descriptor = module().descriptor();
    json!({
        "id": descriptor.profile.id,
        "version": descriptor.profile.version.to_string(),
        "digest": descriptor.digest().expect("digest").as_str()
    })
}

fn binding(context: &ValidationContext) -> Value {
    json!({
        "subject": context.request_subject,
        "scope": {"kind": context.scope.kind, "value": context.scope.value},
        "vantage": {"kind": "local", "value": {}}
    })
}

fn backend() -> Value {
    json!({"implementation": {"name": "nq-host-resource-helper", "version": "0.1.0"}, "tools": []})
}

fn complete(context: &ValidationContext, payload_overrides: &[(&str, Value)]) -> ReportInput {
    let observed_at = now() - Duration::seconds(1);
    let mut payload = json!({
        "evidence_basis": {
            "scope": {"kind": context.scope.kind, "value": context.scope.value},
            "vantage": {"kind": "local", "value": {}},
            "access_path": "systemd_dbus",
            "basis": "manager_snapshot",
            "regime": "normal",
            "capabilities_used": ["read_systemd_unit"]
        },
        "machine_id": context.scope.value["machine_id"],
        "unit_name": context.scope.value["unit_name"],
        "load_state": "loaded",
        "active_state": "active",
        "sub_state": "running",
        "boot_id":"7e3e2a67-f95e-437a-b6c6-d2bf99d44e0c"
    });
    for (key, value) in payload_overrides {
        payload[*key] = value.clone();
    }
    let report: nq_protocol::EvidenceReport = serde_json::from_value(json!({
        "schema": "nq.evidence_report.v1",
        "profile": protocol_profile(),
        "binding": binding(context),
        "observed_at": observed_at,
        "status": "complete",
        "coverage": [{"kind": "systemd_unit_state", "state": "complete"}],
        "observations": [{
            "ordinal": 0,
            "kind": "systemd_unit_state_snapshot",
            "subject": context.request_subject,
            "observed_at": observed_at,
            "payload": payload
        }],
        "errors": [],
        "used_capabilities": ["read_systemd_unit"],
        "backend": backend()
    }))
    .expect("report shape");
    ReportInput::from_protocol_with_digest(&report).expect("normalizes")
}

fn admit(context: &ValidationContext, input: &ReportInput) -> ValidatedReport {
    module()
        .validate(context, input)
        .unwrap_or_else(|refusal| panic!("admitted: {refusal:?}"))
}

fn judge(context: &ValidationContext, report: ValidatedReport, age: i64) -> DetectorResult {
    let occurrence = DetectorReport {
        report_id: "report:unit".to_owned(),
        report_sequence: 1,
        report,
    };
    module().detectors()[0].evaluate(&DetectorInput {
        instance_id: &context.instance_id,
        evaluated_at: now() - Duration::seconds(1) + Duration::seconds(age),
        watermark: EvidenceWatermark(1),
        threshold_policy: None,
        reports: std::slice::from_ref(&occurrence),
    })
}

#[test]
fn revisions_and_subject_identity_are_distinct_from_boot_identity() {
    assert!(resolve_profile("nq.systemd_unit", 1).is_some());
    assert!(resolve_profile("nq.systemd_unit", 2).is_some());
    assert_eq!(module().descriptor().profile.version, 3);
    let context = cron();
    let original = admit(&context, &complete(&context, &[]));
    let successor = admit(
        &context,
        &complete(
            &context,
            &[("boot_id", json!("313a2679-0aa3-4a1b-9122-0caa5756e006"))],
        ),
    );
    assert_eq!(
        original.observations[0].subject,
        successor.observations[0].subject
    );
    assert_ne!(original.report_digest, successor.report_digest);
    assert_ne!(
        module().project(&original).unwrap()[0].canonical_json(),
        module().project(&successor).unwrap()[0].canonical_json()
    );
}
#[test]
fn missing_malformed_and_extra_boot_fields_refuse() {
    let context = cron();
    for value in [
        Value::Null,
        json!(""),
        json!("7E3E2A67-F95E-437A-B6C6-D2BF99D44E0C"),
        json!("00000000-0000-0000-0000-000000000000"),
        json!("7e3e2a67-f95e-437a-b6c6-d2bf99d44e0c\n"),
    ] {
        assert!(
            module()
                .validate(&context, &complete(&context, &[("boot_id", value)]))
                .is_err()
        );
    }
    let mut input = complete(&context, &[]);
    input.observations[0]
        .payload
        .as_object_mut()
        .unwrap()
        .remove("boot_id");
    assert!(module().validate(&context, &input).is_err());
    assert!(
        module()
            .validate(
                &context,
                &complete(&context, &[("boot_identity", json!("invented"))])
            )
            .is_err()
    );
}
#[test]
fn stable_scope_never_accepts_a_pinned_boot_or_wrong_subject() {
    let mut context = cron();
    context.scope.value["boot_id"] = json!("7e3e2a67-f95e-437a-b6c6-d2bf99d44e0c");
    assert!(module().validate_binding(&context).is_err());
    let mut wrong = cron();
    wrong.request_subject = "systemd-unit:ffffffffffffffffffffffffffffffff/cron.service".into();
    assert!(module().validate_binding(&wrong).is_err());
}
#[test]
fn judgment_keeps_native_polarity_and_freshness() {
    let context = cron();
    for (state, wanted) in [
        ("active", DetectorState::ExplicitlyAbsent),
        ("inactive", DetectorState::Present),
        ("failed", DetectorState::Present),
    ] {
        let admitted = admit(
            &context,
            &complete(&context, &[("active_state", json!(state))]),
        );
        assert_eq!(judge(&context, admitted.clone(), 60).state, wanted);
        assert_eq!(
            judge(&context, admitted.clone(), 61).state,
            DetectorState::CannotEvaluate
        );
        assert_eq!(
            judge(&context, admitted, -1).state,
            DetectorState::CannotEvaluate
        );
    }
}
#[test]
fn wrong_machine_state_capability_and_provenance_refuse() {
    let context = cron();
    for (field, value) in [
        ("machine_id", json!("ffffffffffffffffffffffffffffffff")),
        ("active_state", json!("invented")),
        ("unit_name", json!("other.service")),
    ] {
        assert!(
            module()
                .validate(&context, &complete(&context, &[(field, value)]))
                .is_err()
        );
    }
    let mut input = complete(&context, &[]);
    input.observations[0].payload["evidence_basis"]["scope"]["value"]["unit_name"] =
        json!("other.service");
    assert!(module().validate(&context, &input).is_err());
}

#[test]
fn shared_export_vector_is_native_boot_bound_testimony() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json"
    ))
    .unwrap();
    let descriptor = module().descriptor();
    assert_eq!(
        serde_json::to_value(descriptor).unwrap(),
        vectors["profile_descriptor"]
    );
    assert_eq!(
        descriptor.digest().unwrap().as_str(),
        vectors["profile_digest"].as_str().unwrap()
    );
    let report: nq_protocol::EvidenceReport =
        serde_json::from_value(vectors["report"].clone()).unwrap();
    nq_protocol::validate_report(&report).unwrap();
    let input = ReportInput::from_protocol_with_digest(&report).unwrap();
    let mut ctx = context(
        report.binding.subject.as_str(),
        report.binding.scope.value.clone(),
    );
    ctx.instance_id = vectors["export"]["instance_id"].as_str().unwrap().into();
    ctx.received_at = report.observed_at + Duration::seconds(1);
    let admitted = admit(&ctx, &input);
    assert_eq!(
        admitted.report_digest,
        vectors["export"]["evidence"]["report_digest"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        admitted.observations[0].payload,
        vectors["export"]["observation"]["payload"]
    );
    assert_eq!(
        module().project(&admitted).unwrap()[0].canonical_json()["payload"],
        admitted.observations[0].payload
    );
}

#[test]
fn boot_acquisition_failure_is_typed_indeterminate_not_previous_success() {
    let ctx = cron();
    for code in [
        "boot_identity_unavailable",
        "boot_identity_malformed",
        "boot_identity_changed",
    ] {
        let report: nq_protocol::EvidenceReport = serde_json::from_value(json!({
            "schema":"nq.evidence_report.v1", "profile":protocol_profile(), "binding":binding(&ctx),
            "observed_at":now()-Duration::seconds(1), "status":"failed",
            "coverage":[{"kind":"systemd_unit_state","state":"unavailable"}], "observations":[],
            "errors":[{"code":code,"severity":"error","message":"bounded acquisition fixture","retriable":true,"subject":ctx.request_subject}],
            "used_capabilities":["read_systemd_unit"], "backend":backend()
        })).unwrap();
        let input = ReportInput::from_protocol_with_digest(&report).unwrap();
        let result = judge(&ctx, admit(&ctx, &input), 1);
        assert_eq!(result.state, DetectorState::CannotEvaluate);
        assert_eq!(
            result
                .refusal
                .unwrap()
                .details
                .get("failure_code")
                .map(String::as_str),
            Some(code)
        );
    }
}
