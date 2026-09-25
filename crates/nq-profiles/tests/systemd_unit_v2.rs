//! `nq.systemd_unit/v2` admission and judgment: only loaded + active is the
//! expected state, every other admitted state is present, an unanswerable
//! query is `cannot_evaluate` carrying the systemd owner's code, and the
//! subject, scope and payload are exact.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, TimeZone, Utc};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorResult, DetectorState, EvidenceWatermark, ProfileModule,
    ProfileRefusalCode, ReportInput, ScopeGrant, ValidatedReport, ValidationContext, VantageGrant,
    resolve_profile, systemd_unit, systemd_unit_v2, systemd_unit_v2::SystemdUnitFailureCode,
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
        systemd_unit_v2::PROFILE_ID,
        systemd_unit_v2::PROFILE_VERSION,
    )
    .expect("v2 is compiled")
}

fn scope_value(machine: &str, unit: &str) -> Value {
    json!({"schema": systemd_unit_v2::SCOPE_SCHEMA, "machine_id": machine, "unit_name": unit})
}

fn context(subject: &str, scope: Value) -> ValidationContext {
    ValidationContext {
        instance_id: "unit-test".to_owned(),
        request_subject: subject.to_owned(),
        scope: ScopeGrant {
            kind: systemd_unit_v2::SCOPE_KIND.to_owned(),
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
        &systemd_unit_v2::subject_for(MACHINE, "cron.service"),
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
        "sub_state": "running"
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

fn failed(context: &ValidationContext, code: &str, retriable: bool) -> ReportInput {
    let report: nq_protocol::EvidenceReport = serde_json::from_value(json!({
        "schema": "nq.evidence_report.v1",
        "profile": protocol_profile(),
        "binding": binding(context),
        "observed_at": now() - Duration::seconds(1),
        "status": "failed",
        "coverage": [{"kind": "systemd_unit_state", "state": "unavailable"}],
        "observations": [],
        "errors": [{
            "code": code,
            "severity": "error",
            "message": "the system manager's machine identity differs from the exact request scope",
            "retriable": retriable,
            "subject": context.request_subject
        }],
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

fn reason(result: &DetectorResult) -> Option<&str> {
    result
        .refusal
        .as_ref()
        .and_then(|refusal| refusal.details.get("reason"))
        .map(String::as_str)
}

#[test]
fn v2_is_a_separate_revision_and_v1_is_untouched() {
    assert!(resolve_profile(systemd_unit::PROFILE_ID, 1).is_some());
    let v2 = module().descriptor();
    assert_eq!(v2.profile.version, 2);
    assert_ne!(
        v2.digest().expect("digest"),
        resolve_profile(systemd_unit::PROFILE_ID, 1)
            .expect("v1")
            .descriptor()
            .digest()
            .expect("digest")
    );
    assert_eq!(v2.freshness.reliance_seconds, 60);
    let detector = module().detectors()[0].descriptor();
    assert_eq!(detector.id, "nq.systemd_unit.required_active");
    assert_eq!(detector.condition, "systemd_unit_not_active");
    assert_eq!(module().failure_codes(), SystemdUnitFailureCode::tokens());
    assert!(
        resolve_profile(systemd_unit::PROFILE_ID, 1)
            .expect("v1")
            .failure_codes()
            .is_empty()
    );
}

#[test]
fn only_loaded_and_active_is_explicitly_absent() {
    let context = cron();
    let active = judge(&context, admit(&context, &complete(&context, &[])), 0);
    assert_eq!(active.state, DetectorState::ExplicitlyAbsent);
    assert_eq!(active.condition, "systemd_unit_not_active");
    assert!(
        active
            .limitations
            .iter()
            .any(|text| text.contains("not a service operational"))
    );
    for (load, active_state, sub) in [
        ("loaded", "inactive", "dead"),
        ("loaded", "failed", "failed"),
        ("loaded", "activating", "auto-restart"),
        ("loaded", "deactivating", "stop-sigterm"),
        ("loaded", "reloading", "reload"),
        ("loaded", "maintenance", "cleaning"),
        ("not-found", "inactive", "dead"),
        ("masked", "inactive", "dead"),
        ("error", "active", "running"),
    ] {
        let input = complete(
            &context,
            &[
                ("load_state", json!(load)),
                ("active_state", json!(active_state)),
                ("sub_state", json!(sub)),
            ],
        );
        let result = judge(&context, admit(&context, &input), 0);
        assert_eq!(
            result.state,
            DetectorState::Present,
            "{load}/{active_state}/{sub}"
        );
        assert!(result.refusal.is_none());
    }
}

#[test]
fn stale_support_is_cannot_evaluate_never_absence() {
    let context = cron();
    let at_edge = judge(&context, admit(&context, &complete(&context, &[])), 60);
    assert_eq!(at_edge.state, DetectorState::ExplicitlyAbsent);
    let stale = judge(&context, admit(&context, &complete(&context, &[])), 61);
    assert_eq!(stale.state, DetectorState::CannotEvaluate);
    assert_eq!(reason(&stale), Some("invalid_freshness"));
    let future = judge(&context, admit(&context, &complete(&context, &[])), -1);
    assert_eq!(future.state, DetectorState::CannotEvaluate);
}

#[test]
fn the_systemd_owner_code_travels_and_foreign_codes_do_not() {
    let context = cron();
    for code in SystemdUnitFailureCode::ALL {
        for retriable in [true, false] {
            let result = judge(
                &context,
                admit(&context, &failed(&context, code.as_str(), retriable)),
                0,
            );
            assert_eq!(result.state, DetectorState::CannotEvaluate);
            let refusal = result.refusal.expect("typed refusal");
            assert_eq!(refusal.profile, module().descriptor().profile);
            assert_eq!(
                refusal.details.get("reason").map(String::as_str),
                Some("incomplete_systemd_unit_coverage")
            );
            assert_eq!(
                refusal.details.get("failure_code").map(String::as_str),
                Some(code.as_str())
            );
            assert_eq!(
                refusal.details.get("failure_retriable").map(String::as_str),
                Some(if retriable { "true" } else { "false" })
            );
            assert!(!refusal.message.contains("machine identity differs"));
        }
    }
    for foreign in [
        "psi_not_provided",
        "not_a_mountpoint",
        "systemd_unit_cardinality",
        "backend_failed",
    ] {
        let result = judge(
            &context,
            admit(&context, &failed(&context, foreign, true)),
            0,
        );
        assert_eq!(result.state, DetectorState::CannotEvaluate);
        let refusal = result.refusal.expect("typed refusal");
        assert!(!refusal.details.contains_key("failure_code"), "{foreign}");
        assert!(!refusal.details.contains_key("failure_retriable"));
    }
}

#[test]
fn subject_scope_and_payload_substitution_are_refused() {
    // Subject names another unit or machine than the scope.
    for subject in [
        systemd_unit_v2::subject_for(MACHINE, "rsyslog.service"),
        systemd_unit_v2::subject_for("ffffffffffffffffffffffffffffffff", "cron.service"),
        format!("host:{MACHINE}"),
    ] {
        let context = context(&subject, scope_value(MACHINE, "cron.service"));
        let refusal = module()
            .validate_binding(&context)
            .expect_err("substituted subject");
        assert_eq!(refusal.code, ProfileRefusalCode::ScopeEscape, "{subject}");
    }
    // Aliases are canonical-name questions: the grammar admits the name, the
    // helper refuses it live; templates, instances and sockets are outside v2.
    for unit in ["getty@tty1.service", "ssh.socket", "foo@.service"] {
        let context = context(
            &systemd_unit_v2::subject_for(MACHINE, unit),
            scope_value(MACHINE, unit),
        );
        assert!(module().validate_binding(&context).is_err(), "{unit}");
    }
    // The v1 fixture scope is not a v2 scope.
    let v1_shaped = context(
        &systemd_unit_v2::subject_for(MACHINE, "cron.service"),
        json!({
            "schema": "nq.operator_beta.systemd_unit_scope.v1",
            "machine_id": MACHINE,
            "unit_name": "cron.service"
        }),
    );
    assert!(module().validate_binding(&v1_shaped).is_err());
    // A payload naming another unit, another machine, or an unrecognized
    // state is refused at admission.
    let context = cron();
    for overrides in [
        vec![("unit_name", json!("rsyslog.service"))],
        vec![("machine_id", json!("ffffffffffffffffffffffffffffffff"))],
        vec![("active_state", json!("refreshing"))],
        vec![("load_state", json!("Loaded"))],
        vec![("sub_state", json!(""))],
        vec![("unit_file_state", json!("enabled"))],
    ] {
        let label = format!("{overrides:?}");
        let refusal = module()
            .validate(&context, &complete(&context, &overrides))
            .expect_err(&label);
        assert_eq!(refusal.code, ProfileRefusalCode::InvalidPayload, "{label}");
    }
}
