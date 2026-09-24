//! Owner-defined typed failure codes survive admission and reach the
//! detector refusal, bound to the owning profile, with `retriable` carried
//! exactly as the helper emitted it; nothing else about admission or the
//! `cannot_evaluate` state changes, and one owner's code never becomes
//! another's.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Duration, TimeZone, Utc};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorState, EvidenceWatermark, ProfileModule, ProfileRefusal,
    ReportInput, ScopeGrant, ValidatedReport, ValidationContext, VantageGrant, all_profiles,
    host_filesystem::FilesystemFailureCode, host_memory::MemoryFailureCode,
};
use serde_json::{Value, json};

const MACHINE: &str = "0123456789abcdef0123456789abcdef";
const UUID: &str = "00000000-0000-4000-8000-0000000000f5";

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 24, 12, 0, 0)
        .single()
        .expect("fixed time")
}

fn module(id: &str) -> &'static dyn ProfileModule {
    *all_profiles()
        .iter()
        .find(|module| module.descriptor().profile.id == id)
        .unwrap_or_else(|| panic!("profile {id} is compiled"))
}

struct Owner {
    module: &'static dyn ProfileModule,
    context: ValidationContext,
    coverage_kind: &'static str,
    capabilities: Vec<&'static str>,
}

fn memory_owner() -> Owner {
    let subject = format!("host:{MACHINE}");
    Owner {
        module: module("nq.host_memory"),
        context: ValidationContext {
            instance_id: "mem-test".to_owned(),
            request_subject: subject,
            scope: ScopeGrant {
                kind: "host_memory".to_owned(),
                value: json!({"schema": "nq.host_memory_scope.v1", "machine_id": MACHINE}),
            },
            vantage: VantageGrant {
                kind: "local".to_owned(),
                value: json!({}),
            },
            granted_capabilities: BTreeSet::from([
                "read_machine_identity".to_owned(),
                "read_procfs".to_owned(),
            ]),
            received_at: now(),
            max_observations: 1,
            max_future_skew: Duration::seconds(5),
        },
        coverage_kind: "memory_pressure_stall",
        capabilities: vec!["read_machine_identity", "read_procfs"],
    }
}

fn filesystem_owner() -> Owner {
    let subject = format!("host-filesystem:{MACHINE}/{UUID}");
    Owner {
        module: module("nq.host_filesystem_capacity"),
        context: ValidationContext {
            instance_id: "fs-test".to_owned(),
            request_subject: subject,
            scope: ScopeGrant {
                kind: "host_filesystem".to_owned(),
                value: json!({
                    "schema": "nq.host_filesystem_scope.v1",
                    "machine_id": MACHINE,
                    "filesystem_uuid": UUID,
                    "filesystem_type": "ext4",
                    "mountpoint": "/data"
                }),
            },
            vantage: VantageGrant {
                kind: "local".to_owned(),
                value: json!({}),
            },
            granted_capabilities: BTreeSet::from([
                "read_machine_identity".to_owned(),
                "read_mount_table".to_owned(),
                "read_filesystem_statistics".to_owned(),
            ]),
            received_at: now(),
            max_observations: 1,
            max_future_skew: Duration::seconds(5),
        },
        coverage_kind: "filesystem_statistics",
        capabilities: vec![
            "read_machine_identity",
            "read_mount_table",
            "read_filesystem_statistics",
        ],
    }
}

/// A failed helper report in the exact shape the real helper emits, with the
/// given structured errors (`code`, `severity`, `retriable`). The message is
/// deliberately the kind of prose that must never travel.
fn failed_report(owner: &Owner, errors: &[(&str, &str, bool)]) -> nq_protocol::EvidenceReport {
    let descriptor = owner.module.descriptor();
    let errors = errors
        .iter()
        .map(|(code, severity, retriable)| {
            json!({
                "code": code,
                "severity": severity,
                "message": "live /etc/machine-id differs from the exact request scope",
                "retriable": retriable,
                "subject": owner.context.request_subject
            })
        })
        .collect::<Vec<_>>();
    serde_json::from_value(json!({
        "schema": "nq.evidence_report.v1",
        "profile": {
            "id": descriptor.profile.id,
            "version": descriptor.profile.version.to_string(),
            "digest": descriptor.digest().expect("digest").as_str()
        },
        "binding": {
            "subject": owner.context.request_subject,
            "scope": {"kind": owner.context.scope.kind, "value": owner.context.scope.value},
            "vantage": {"kind": "local", "value": {}}
        },
        "observed_at": now() - Duration::seconds(1),
        "status": "failed",
        "coverage": [{"kind": owner.coverage_kind, "state": "unavailable"}],
        "observations": [],
        "errors": errors,
        "used_capabilities": owner.capabilities,
        "backend": {"implementation": {"name": "nq-host-resource-helper", "version": "0.1.0"}, "tools": []}
    }))
    .expect("report shape")
}

fn admit(owner: &Owner, report: &nq_protocol::EvidenceReport) -> ValidatedReport {
    let input = ReportInput::from_protocol_with_digest(report).expect("normalizes");
    // The normalized input never serializes the retained errors: historical
    // normalized-artifact identities are computed from this form.
    let normalized = serde_json::to_value(&input).expect("json");
    assert!(normalized.get("errors").is_none());
    owner
        .module
        .validate(&owner.context, &input)
        .unwrap_or_else(|refusal| panic!("failed testimony is admitted: {refusal:?}"))
}

fn refusal(owner: &Owner, validated: ValidatedReport) -> ProfileRefusal {
    let occurrence = DetectorReport {
        report_id: "report:test".to_owned(),
        report_sequence: 1,
        report: validated,
    };
    let detector = owner.module.detectors()[0];
    let result = detector.evaluate(&DetectorInput {
        instance_id: &owner.context.instance_id,
        evaluated_at: now() + Duration::seconds(10),
        watermark: EvidenceWatermark(1),
        threshold_policy: None,
        reports: std::slice::from_ref(&occurrence),
    });
    assert_eq!(result.state, DetectorState::CannotEvaluate);
    result
        .refusal
        .expect("a cannot_evaluate carries its typed refusal")
}

fn details(refusal: &ProfileRefusal) -> &BTreeMap<String, String> {
    &refusal.details
}

#[test]
fn the_same_code_text_under_two_owners_stays_bound_to_each_owner() {
    let memory = memory_owner();
    let filesystem = filesystem_owner();
    let code = MemoryFailureCode::MachineIdentityMismatch.as_str();
    assert_eq!(
        code,
        FilesystemFailureCode::MachineIdentityMismatch.as_str()
    );

    let memory_refusal = refusal(
        &memory,
        admit(&memory, &failed_report(&memory, &[(code, "error", false)])),
    );
    let filesystem_refusal = refusal(
        &filesystem,
        admit(
            &filesystem,
            &failed_report(&filesystem, &[(code, "error", false)]),
        ),
    );
    for (owner, refusal, reason) in [
        (&memory, &memory_refusal, "incomplete_memory_coverage"),
        (
            &filesystem,
            &filesystem_refusal,
            "incomplete_filesystem_coverage",
        ),
    ] {
        let details = details(refusal);
        assert_eq!(details.get("reason").map(String::as_str), Some(reason));
        assert_eq!(details.get("failure_code").map(String::as_str), Some(code));
        assert_eq!(
            details.get("failure_retriable").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            details.get("failure_error_count").map(String::as_str),
            Some("1")
        );
        assert_eq!(refusal.profile, owner.module.descriptor().profile);
        // The helper's prose never travels: neither the message nor any path.
        assert!(!refusal.message.contains("/etc/machine-id"));
        assert!(details.values().all(|value| !value.contains('/')));
        assert!(
            details
                .values()
                .all(|value| !value.contains(char::is_whitespace))
        );
    }
    assert_ne!(memory_refusal.profile, filesystem_refusal.profile);
}

#[test]
fn a_foreign_or_unlisted_code_is_not_carried_and_changes_nothing_else() {
    let filesystem = filesystem_owner();
    let memory = memory_owner();
    let filesystem_listed = FilesystemFailureCode::StatfsFailed.as_str();
    let memory_listed = MemoryFailureCode::PsiReadFailed.as_str();
    for (owner, listed_code, foreign) in [
        (
            &filesystem,
            filesystem_listed,
            MemoryFailureCode::PsiNotProvided.as_str(),
        ),
        (&filesystem, filesystem_listed, "backend_failed"),
        (
            &filesystem,
            filesystem_listed,
            "unlisted_code_from_elsewhere",
        ),
        (
            &memory,
            memory_listed,
            FilesystemFailureCode::NotAMountpoint.as_str(),
        ),
        (&memory, memory_listed, "backend_failed"),
    ] {
        let carried = admit(
            owner,
            &failed_report(owner, &[(listed_code, "error", true)]),
        );
        let uncarried = admit(owner, &failed_report(owner, &[(foreign, "error", true)]));
        // Admission is identical apart from the retained error identity.
        let mut carried_view = carried.clone();
        carried_view.report_errors.clear();
        let mut uncarried_view = uncarried.clone();
        uncarried_view.report_errors.clear();
        carried_view.report_digest.clear();
        uncarried_view.report_digest.clear();
        assert_eq!(carried_view, uncarried_view, "{foreign}");
        assert_eq!(uncarried.report_errors.len(), 1);
        assert_eq!(uncarried.report_errors[0].code, foreign);

        let refusal = refusal(owner, uncarried);
        let details = details(&refusal);
        assert!(
            details.get("failure_code").is_none(),
            "{foreign} was carried"
        );
        assert!(details.get("failure_retriable").is_none(), "{foreign}");
        assert_eq!(
            details.get("failure_error_count").map(String::as_str),
            Some("1")
        );
    }
}

#[test]
fn retriable_is_carried_exactly_as_emitted_and_never_inferred() {
    let memory = memory_owner();
    let filesystem = filesystem_owner();
    for (owner, code) in [
        (&memory, MemoryFailureCode::PsiReadFailed.as_str()),
        (
            &filesystem,
            FilesystemFailureCode::MountIdentityUnavailable.as_str(),
        ),
    ] {
        for retriable in [true, false] {
            let refusal = refusal(
                owner,
                admit(owner, &failed_report(owner, &[(code, "error", retriable)])),
            );
            assert_eq!(
                details(&refusal)
                    .get("failure_retriable")
                    .map(String::as_str),
                Some(if retriable { "true" } else { "false" }),
                "{code} {retriable}"
            );
            assert_eq!(
                details(&refusal).get("failure_code").map(String::as_str),
                Some(code)
            );
        }
    }
}

#[test]
fn several_collection_errors_carry_no_code_and_a_warning_does_not_count() {
    let memory = memory_owner();
    let two = refusal(
        &memory,
        admit(
            &memory,
            &failed_report(
                &memory,
                &[
                    (MemoryFailureCode::PsiReadFailed.as_str(), "error", true),
                    (MemoryFailureCode::PsiMalformed.as_str(), "error", false),
                ],
            ),
        ),
    );
    assert!(details(&two).get("failure_code").is_none());
    assert!(details(&two).get("failure_retriable").is_none());
    assert_eq!(
        details(&two).get("failure_error_count").map(String::as_str),
        Some("2")
    );
    let with_warning = refusal(
        &memory,
        admit(
            &memory,
            &failed_report(
                &memory,
                &[
                    (
                        MemoryFailureCode::BootClockUnavailable.as_str(),
                        "warning",
                        true,
                    ),
                    (MemoryFailureCode::PsiNotProvided.as_str(), "error", false),
                ],
            ),
        ),
    );
    assert_eq!(
        details(&with_warning)
            .get("failure_code")
            .map(String::as_str),
        Some("psi_not_provided")
    );
    assert_eq!(
        details(&with_warning)
            .get("failure_retriable")
            .map(String::as_str),
        Some("false")
    );
}

#[test]
fn the_detail_key_set_is_closed_and_every_value_is_a_token() {
    let filesystem = filesystem_owner();
    let memory = memory_owner();
    let filesystem_refusal = refusal(
        &filesystem,
        admit(
            &filesystem,
            &failed_report(
                &filesystem,
                &[(
                    FilesystemFailureCode::FilesystemIdentityMismatch.as_str(),
                    "error",
                    false,
                )],
            ),
        ),
    );
    assert_eq!(
        details(&filesystem_refusal)
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "failure_code",
            "failure_error_count",
            "failure_retriable",
            "reason",
            "report_status"
        ]
    );
    let memory_refusal = refusal(
        &memory,
        admit(
            &memory,
            &failed_report(
                &memory,
                &[(MemoryFailureCode::PsiMalformed.as_str(), "error", false)],
            ),
        ),
    );
    assert_eq!(
        details(&memory_refusal)
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "failure_code",
            "failure_error_count",
            "failure_retriable",
            "reason"
        ]
    );
    for refusal in [&filesystem_refusal, &memory_refusal] {
        for value in details(refusal).values() {
            assert!(!value.is_empty());
            assert!(!value.contains(char::is_whitespace));
            assert!(!value.contains('/'));
        }
    }
}

#[test]
fn stored_report_bytes_stay_stable_and_old_rows_round_trip() {
    let memory = memory_owner();
    let failed = admit(
        &memory,
        &failed_report(
            &memory,
            &[(MemoryFailureCode::PsiNotProvided.as_str(), "error", false)],
        ),
    );
    let with_errors = serde_json::to_value(&failed).expect("json");
    assert_eq!(
        with_errors["report_errors"],
        json!([{"code": "psi_not_provided", "severity": "error", "retriable": false}])
    );
    // A report with no retained errors serializes without the key, so every
    // previously stored complete report keeps its exact bytes, and a stored
    // row without the key (every row before this change) decodes to an
    // empty list.
    let mut complete_shaped = failed.clone();
    complete_shaped.report_errors.clear();
    let without = serde_json::to_value(&complete_shaped).expect("json");
    assert!(without.get("report_errors").is_none());
    let mut old_row = with_errors.clone();
    old_row
        .as_object_mut()
        .expect("object")
        .remove("report_errors");
    let decoded: ValidatedReport = serde_json::from_value(old_row).expect("old row decodes");
    assert!(decoded.report_errors.is_empty());
    assert_eq!(decoded, complete_shaped);
    // Round trip of the new bytes is exact.
    let again: ValidatedReport = serde_json::from_value(with_errors.clone()).expect("decodes");
    assert_eq!(serde_json::to_value(&again).expect("json"), with_errors);
    // An unknown key inside the retained error is refused: the carrier is
    // closed and cannot grow a message or a path.
    let mut widened = with_errors;
    widened["report_errors"][0]["message"] = Value::String("prose".to_owned());
    assert!(serde_json::from_value::<ValidatedReport>(widened).is_err());
}
