//! Additive native-profile, native-clock, and per-launch deadline carriers.

use nq_host_role_contract::{
    ContractError, RuntimeRecord, RuntimeSchema, ValidatedRuntimeRecord,
    verified_native_correspondence_manifest,
};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use serde_json::{Value, json};

fn digest(label: &str) -> String {
    sha256_bytes(label.as_bytes()).to_string()
}

fn identity(kind: &str, id: &str, version: &str, descriptor_label: &str) -> Value {
    json!({
        "kind": kind,
        "id": id,
        "version": version,
        "descriptor_digest": digest(descriptor_label)
    })
}

fn reference(schema: &str, record_label: &str, bytes_label: &str) -> Value {
    json!({
        "schema": schema,
        "record_id": digest(record_label),
        "bytes_digest": digest(bytes_label)
    })
}

fn namespace() -> Value {
    json!({
        "namespace_id": "nq.production",
        "namespace_version": "1",
        "catalog_generation": "7",
        "catalog_id": digest("production-catalog-7")
    })
}

fn seal(mut value: Value, identity_field: &str) -> Value {
    let object = value.as_object_mut().expect("record object");
    object.remove(identity_field);
    let identity = semantic_digest(&Value::Object(object.clone())).expect("self identity");
    object.insert(
        identity_field.to_owned(),
        Value::String(identity.to_string()),
    );
    value
}

fn profile_qualification() -> Value {
    seal(
        json!({
            "schema": "nq.native_profile_qualification.v1",
            "qualification_id": digest("placeholder"),
            "namespace": namespace(),
            "cohort": identity(
                "static_cohort",
                "generic-host/profiles",
                "1",
                "production-cohort-descriptor"
            ),
            "cohort_generation": "1",
            "cohort_semantics_digest": digest("production-cohort-semantics"),
            "production_profile": identity(
                "diagnostic_profile",
                "generic-host/conformance",
                "1",
                "production-profile-descriptor"
            ),
            "production_question": identity(
                "diagnostic_question",
                "generic-host/conformance/question",
                "1",
                "production-question-descriptor"
            ),
            "production_build": identity(
                "build",
                "nq/runtime",
                "1",
                "production-build-descriptor"
            ),
            "native_profile": {
                "descriptor_schema": "nq.profile_descriptor.v1",
                "profile_id": "nq.conformance",
                "profile_version": 1,
                "descriptor_digest": digest("native-profile-descriptor"),
                "semantic_identity_schema": "nq.profile_semantic_id.v1",
                "semantic_identity_digest": digest("native-profile-semantics"),
                "evaluator_source_digest": digest("native-evaluator-source"),
                "helper_protocol_version": "nq.helper.v1",
                "detector_closure": {
                    "schema": "nq.detector_closure.v1",
                    "identity_digest": digest("empty-detector-closure"),
                    "detector_count": 0
                }
            },
            "native_evaluator": {
                "artifact_digest": digest("native-evaluator-artifact"),
                "artifact_identity_method": "linux-proc-self-exe-fd-sha256-v1",
                "target_triple": "x86_64-unknown-linux-gnu"
            },
            "qualification_evidence": [
                reference("nq.external_record.v1", "profile-qualification-run", "profile-evidence")
            ],
            "nonclaims": [
                "relates production and native identities but does not equate them",
                "does not establish invocation, reliance, authorization, or action"
            ]
        }),
        "qualification_id",
    )
}

fn clock_qualification() -> Value {
    seal(
        json!({
            "schema": "nq.native_clock_qualification.v1",
            "qualification_id": digest("placeholder"),
            "namespace": namespace(),
            "cohort": identity(
                "static_cohort",
                "generic-host/profiles",
                "1",
                "production-cohort-descriptor"
            ),
            "cohort_generation": "1",
            "cohort_semantics_digest": digest("production-cohort-semantics"),
            "production_clock": identity(
                "clock",
                "generic-host/bounded-clock",
                "1",
                "production-clock-descriptor"
            ),
            "production_build": identity(
                "build",
                "nq/runtime",
                "1",
                "production-build-descriptor"
            ),
            "platform": identity(
                "platform",
                "ubuntu/24.04/amd64",
                "1",
                "production-platform-descriptor"
            ),
            "absolute_time": {
                "semantic_identity_digest": digest("clock-realtime-semantics"),
                "observation_method": "clock_gettime-clock-realtime-v1",
                "clock_id": "CLOCK_REALTIME",
                "epoch": "unix",
                "unit": "nanosecond",
                "accuracy_qualification": {
                    "status": "unqualified"
                }
            },
            "boottime": {
                "semantic_identity_digest": digest("clock-boottime-semantics"),
                "observation_method": "clock_gettime-clock-boottime-v1",
                "clock_id": "CLOCK_BOOTTIME",
                "boot_epoch_binding_method": "linux-boot-id-v1",
                "unit": "nanosecond",
                "suspend_semantics": "includes_suspended_time"
            },
            "wall_to_monotonic_bridge": {
                "semantic_identity_digest": digest("realtime-boottime-bridge"),
                "method": "realtime-boottime-bracket-v1"
            },
            "runner_watchdog": {
                "method": "std-instant-v1",
                "relation_to_governed_deadline": "auxiliary_non_equivalent"
            },
            "qualification_evidence": [
                reference("nq.external_record.v1", "clock-qualification-run", "clock-evidence")
            ],
            "nonclaims": [
                "UTC accuracy remains unqualified",
                "does not establish cross-host clock coherence",
                "runner watchdog is not the governed deadline"
            ]
        }),
        "qualification_id",
    )
}

fn deadline_evaluation(
    realtime_before: &str,
    realtime_after: &str,
    launched_at: &str,
    attempt_deadline: &str,
    boottime_at_ns: u64,
    boottime_expiry_ns: u64,
    violations: &[&str],
) -> Value {
    let clock =
        ValidatedRuntimeRecord::validate_value(clock_qualification()).expect("clock qualification");
    seal(
        json!({
            "schema": "nq.deadline_evaluation.v1",
            "evaluation_id": digest("placeholder"),
            "namespace": namespace(),
            "outer_request": reference(
                "nq.diagnostic_invocation_request.v1",
                "outer-request",
                "outer-request-bytes"
            ),
            "activation": reference(
                "nq.runtime_activation.v1",
                "activation",
                "activation-bytes"
            ),
            "clock_qualification": clock.exact_reference(),
            "clock": identity(
                "clock",
                "generic-host/bounded-clock",
                "1",
                "production-clock-descriptor"
            ),
            "request_bounds": {
                "not_before": "2026-07-29T22:00:00Z",
                "deadline": "2026-07-29T22:00:10Z",
                "maximum_execution_ms": 1000
            },
            "bracket_policy": {
                "policy": identity(
                    "policy",
                    "nq/deadline-bracket",
                    "1",
                    "deadline-bracket-policy"
                ),
                "maximum_width_ns": 100_000
            },
            "sample": {
                "realtime_before": realtime_before,
                "boottime_at_ns": boottime_at_ns.to_string(),
                "realtime_after": realtime_after,
                "bracket_width_ns": 1000,
                "boot_epoch": digest("boot-epoch")
            },
            "derived": {
                "launched_at": launched_at,
                "attempt_deadline": attempt_deadline,
                "boottime_expiry_ns": boottime_expiry_ns.to_string()
            },
            "decision": {
                "state": if violations.is_empty() { "accepted" } else { "refused" },
                "violations": violations
            },
            "nonclaims": [
                "does not reference or authorize an execution launch",
                "does not establish source-evidence freshness or Nightshift currentness",
                "does not grant reliance, authorization, or action"
            ]
        }),
        "evaluation_id",
    )
}

fn accepted_deadline_evaluation() -> Value {
    deadline_evaluation(
        "2026-07-29T22:00:01.000000000Z",
        "2026-07-29T22:00:01.000001000Z",
        "2026-07-29T22:00:01.000001000Z",
        "2026-07-29T22:00:02.000001000Z",
        10_000_000_000_000_000,
        10_000_001_000_000_000,
        &[],
    )
}

#[test]
fn additive_manifest_is_content_addressed_without_rewriting_frozen_3a_provenance() {
    let manifest =
        verified_native_correspondence_manifest().expect("exact additive schema manifest");
    assert_eq!(manifest.assets.len(), 3);
    assert_eq!(
        manifest
            .assets
            .iter()
            .map(|asset| asset.schema.as_str())
            .collect::<Vec<_>>(),
        RuntimeSchema::ALL
            .iter()
            .filter(|schema| schema.is_native_correspondence())
            .map(|schema| schema.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn all_three_correspondence_carriers_validate_and_remain_typed() {
    let profile =
        ValidatedRuntimeRecord::validate_value(profile_qualification()).expect("profile carrier");
    let clock =
        ValidatedRuntimeRecord::validate_value(clock_qualification()).expect("clock carrier");
    let deadline = ValidatedRuntimeRecord::validate_value(accepted_deadline_evaluation())
        .expect("deadline carrier");

    assert!(matches!(
        profile.record(),
        RuntimeRecord::NativeProfileQualification(_)
    ));
    assert!(matches!(
        clock.record(),
        RuntimeRecord::NativeClockQualification(_)
    ));
    assert!(matches!(
        deadline.record(),
        RuntimeRecord::DeadlineEvaluation(_)
    ));
    for carrier in [&profile, &clock, &deadline] {
        let replay = ValidatedRuntimeRecord::decode_canonical(carrier.canonical_bytes())
            .expect("canonical replay");
        assert_eq!(replay.record_id(), carrier.record_id());
        assert_eq!(replay.bytes_digest(), carrier.bytes_digest());
    }
}

#[test]
fn profile_qualification_has_no_trusted_boolean_and_refuses_identity_collapse() {
    let mut boolean = profile_qualification();
    boolean["qualified"] = json!(true);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(boolean),
        Err(ContractError::RecordShape { .. })
    ));

    let mut alias = profile_qualification();
    alias["production_profile"]["descriptor_digest"] =
        alias["native_profile"]["descriptor_digest"].clone();
    alias = seal(alias, "qualification_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(alias),
        Err(ContractError::CorrespondenceIdentityCollapse)
    ));

    let mut build_alias = profile_qualification();
    build_alias["production_build"]["descriptor_digest"] =
        build_alias["native_evaluator"]["artifact_digest"].clone();
    build_alias = seal(build_alias, "qualification_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(build_alias),
        Err(ContractError::CorrespondenceIdentityCollapse)
    ));

    let mut missing_question = profile_qualification();
    missing_question
        .as_object_mut()
        .expect("qualification object")
        .remove("production_question");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(missing_question),
        Err(ContractError::RecordShape { .. })
    ));

    let mut multiple_questions = profile_qualification();
    multiple_questions["production_question"] = json!([
        identity(
            "diagnostic_question",
            "generic-host/conformance/question",
            "1",
            "production-question-descriptor"
        ),
        identity(
            "diagnostic_question",
            "generic-host/other-question",
            "1",
            "other-question-descriptor"
        )
    ]);
    multiple_questions = seal(multiple_questions, "qualification_id");
    let multiple_result = ValidatedRuntimeRecord::validate_value(multiple_questions);
    assert!(
        matches!(
            &multiple_result,
            Err(ContractError::SchemaValidation { .. } | ContractError::Json(_))
        ),
        "{multiple_result:?}"
    );

    let mut wrong_question_kind = profile_qualification();
    wrong_question_kind["production_question"]["kind"] = json!("diagnostic_profile");
    wrong_question_kind = seal(wrong_question_kind, "qualification_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(wrong_question_kind),
        Err(ContractError::IdentityKindMismatch { .. } | ContractError::SchemaValidation { .. })
    ));
}

#[test]
fn clock_qualification_cannot_invent_accuracy_or_alias_native_semantics() {
    let mut bounded = clock_qualification();
    bounded["absolute_time"]["accuracy_qualification"]["uncertainty_ns"] = json!(1000);
    bounded = seal(bounded, "qualification_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(bounded),
        Err(ContractError::SchemaValidation { .. })
    ));

    let mut claimed = clock_qualification();
    claimed["absolute_time"]["accuracy_qualification"]["status"] = json!("qualified");
    claimed = seal(claimed, "qualification_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(claimed),
        Err(ContractError::InvalidNativeClockQualification | ContractError::SchemaValidation { .. })
    ));

    let mut alias = clock_qualification();
    alias["absolute_time"]["semantic_identity_digest"] =
        alias["production_clock"]["descriptor_digest"].clone();
    alias = seal(alias, "qualification_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(alias),
        Err(ContractError::CorrespondenceIdentityCollapse)
    ));
}

#[test]
fn deadline_verdict_and_derived_values_are_recomputed_not_supplied() {
    let mut laundered = accepted_deadline_evaluation();
    laundered["decision"]["state"] = json!("refused");
    laundered["decision"]["violations"] = json!(["bracket_too_wide"]);
    laundered = seal(laundered, "evaluation_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(laundered),
        Err(ContractError::DeadlineEvaluationMismatch)
    ));

    let mut rebound = accepted_deadline_evaluation();
    rebound["derived"]["boottime_expiry_ns"] = json!("10000001000000001");
    rebound = seal(rebound, "evaluation_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(rebound),
        Err(ContractError::DeadlineEvaluationMismatch)
    ));

    let refused = deadline_evaluation(
        "2026-07-29T22:00:11.000000000Z",
        "2026-07-29T22:00:11.000001000Z",
        "2026-07-29T22:00:11.000001000Z",
        "2026-07-29T22:00:12.000001000Z",
        10_000_000_000_000_000,
        10_000_001_000_000_000,
        &[
            "request_deadline_exhausted",
            "execution_budget_exceeds_request_deadline",
        ],
    );
    ValidatedRuntimeRecord::validate_value(refused).expect("typed deadline refusal");
}

#[test]
fn boottime_nanoseconds_are_canonical_decimal_strings_beyond_i_json_range() {
    let value = accepted_deadline_evaluation();
    let boottime = value["sample"]["boottime_at_ns"]
        .as_str()
        .expect("decimal string")
        .parse::<u64>()
        .expect("u64 boottime");
    assert!(boottime > 9_007_199_254_740_991);
    ValidatedRuntimeRecord::validate_value(value).expect("uptime beyond 104 days");

    let mut leading_zero = accepted_deadline_evaluation();
    leading_zero["sample"]["boottime_at_ns"] = json!("010000000000000000");
    leading_zero = seal(leading_zero, "evaluation_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(leading_zero),
        Err(ContractError::SchemaValidation { .. } | ContractError::DeadlineEvaluationMismatch)
    ));

    let mut overflow = accepted_deadline_evaluation();
    overflow["sample"]["boottime_at_ns"] = json!("18446744073709551616");
    overflow = seal(overflow, "evaluation_id");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(overflow),
        Err(ContractError::DeadlineEvaluationMismatch)
    ));
}

#[test]
fn deadline_carrier_cannot_reference_launch_or_accept_an_unknown_schema() {
    let mut cycle = accepted_deadline_evaluation();
    cycle["execution_launch"] = reference(
        "nq.execution_launch.v1",
        "future-launch",
        "future-launch-bytes",
    );
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(cycle),
        Err(ContractError::RecordShape { .. })
    ));

    let mut unknown = accepted_deadline_evaluation();
    unknown["schema"] = json!("nq.deadline_evaluation.v2");
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(unknown),
        Err(ContractError::UnknownRuntimeSchema(schema))
            if schema == "nq.deadline_evaluation.v2"
    ));
}

#[test]
fn exact_record_id_is_distinct_from_exact_byte_digest() {
    for value in [
        profile_qualification(),
        clock_qualification(),
        accepted_deadline_evaluation(),
    ] {
        let carrier = ValidatedRuntimeRecord::validate_value(value).expect("valid carrier");
        assert_ne!(
            carrier.record_id(),
            &Sha256Digest::parse(carrier.bytes_digest().as_str()).expect("byte digest")
        );
    }
}
