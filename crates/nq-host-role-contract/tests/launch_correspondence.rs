//! Exact cohort/profile/question/clock/deadline joins for one bounded launch.

use nq_host_role_contract::{
    ContractError, IdentityRef, RecordRef, RuntimeRecordSet, ValidatedRuntimeRecord,
    verified_corrected_specimen,
};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use serde_json::{Map, Value, json};

type Mutation = fn(&mut Value);

fn unchanged(_: &mut Value) {}

#[derive(Clone, Copy, Default)]
enum CohortDigestMode {
    #[default]
    Current,
    BeforeMutation,
}

#[derive(Clone, Copy, Default)]
enum QualifierSet {
    #[default]
    Exact,
    DuplicateProfile,
    DuplicateClock,
    UnreferencedProfile(&'static str),
    UnreferencedClock(&'static str),
}

#[derive(Clone, Copy, Default)]
enum QualificationList {
    #[default]
    Exact,
    AddOpaque,
}

#[derive(Clone, Copy)]
struct Scenario {
    mutate_cohort: Mutation,
    mutate_profile: Mutation,
    mutate_clock: Mutation,
    mutate_deadline: Mutation,
    cohort_digest: CohortDigestMode,
    qualifier_set: QualifierSet,
    qualification_list: QualificationList,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            mutate_cohort: unchanged,
            mutate_profile: unchanged,
            mutate_clock: unchanged,
            mutate_deadline: unchanged,
            cohort_digest: CohortDigestMode::Current,
            qualifier_set: QualifierSet::Exact,
            qualification_list: QualificationList::Exact,
        }
    }
}

struct Fixture {
    records: RuntimeRecordSet,
    launch: RecordRef,
    profile_qualification: RecordRef,
    clock_qualification: RecordRef,
    deadline_evaluation: RecordRef,
    question: IdentityRef,
}

struct QualificationContext<'a> {
    namespace: &'a Value,
    cohort: &'a Value,
    generation: &'a Value,
    semantics: &'a Sha256Digest,
    profile: &'a Value,
    question: &'a Value,
    build: &'a Value,
    clock: &'a Value,
    platform: &'a Value,
}

#[allow(clippy::too_many_lines)] // One fixture builder keeps every exact-reference update visible.
fn fixture(scenario: Scenario) -> Fixture {
    let source: Value =
        serde_json::from_slice(verified_corrected_specimen().expect("corrected specimen"))
            .expect("specimen JSON");
    let records = source["records"].as_object().expect("record map");
    let mut cohort = records["cohort_manifest"].clone();
    let original_semantics = cohort_semantics_digest(&cohort);
    (scenario.mutate_cohort)(&mut cohort);
    let semantics = match scenario.cohort_digest {
        CohortDigestMode::Current => cohort_semantics_digest(&cohort),
        CohortDigestMode::BeforeMutation => original_semantics,
    };
    let cohort_identity = cohort["cohort"].clone();
    let cohort_generation = cohort["generation"].clone();
    let namespace = cohort["namespace"].clone();
    let production_profile = cohort["members"]["profiles"][0].clone();
    let question = cohort["members"]["questions"][0].clone();
    let production_build = cohort["compatible_builds"][0].clone();
    let subject_platform = records["subject_platform_relation"]["right"].clone();
    let production_clock = records["request"]["time_bounds"]["clock"].clone();
    let context = QualificationContext {
        namespace: &namespace,
        cohort: &cohort_identity,
        generation: &cohort_generation,
        semantics: &semantics,
        profile: &production_profile,
        question: &question,
        build: &production_build,
        clock: &production_clock,
        platform: &subject_platform,
    };

    let mut profile = profile_qualification(&context, "primary");
    (scenario.mutate_profile)(&mut profile);
    profile = seal(profile, "qualification_id");
    let profile_record =
        ValidatedRuntimeRecord::validate_value(profile.clone()).expect("profile qualifier");

    let mut clock = clock_qualification(&context, "primary");
    (scenario.mutate_clock)(&mut clock);
    clock = seal(clock, "qualification_id");
    let clock_record =
        ValidatedRuntimeRecord::validate_value(clock.clone()).expect("clock qualifier");

    let mut qualification_references = vec![
        Value::from(profile_record.exact_reference()),
        Value::from(clock_record.exact_reference()),
    ];
    let mut extra_records = Vec::new();
    match scenario.qualifier_set {
        QualifierSet::Exact => {}
        QualifierSet::DuplicateProfile => {
            let duplicate = ValidatedRuntimeRecord::validate_value(profile_qualification(
                &context,
                "duplicate",
            ))
            .expect("duplicate qualifier");
            qualification_references.push(Value::from(duplicate.exact_reference()));
            extra_records.push(duplicate);
        }
        QualifierSet::DuplicateClock => {
            let duplicate =
                ValidatedRuntimeRecord::validate_value(clock_qualification(&context, "duplicate"))
                    .expect("duplicate clock qualifier");
            qualification_references.push(Value::from(duplicate.exact_reference()));
            extra_records.push(duplicate);
        }
        QualifierSet::UnreferencedProfile(generation) => {
            let generation = json!(generation);
            let unreferenced_context = QualificationContext {
                generation: &generation,
                ..context
            };
            let unreferenced = ValidatedRuntimeRecord::validate_value(profile_qualification(
                &unreferenced_context,
                "unreferenced",
            ))
            .expect("unreferenced qualifier");
            extra_records.push(unreferenced);
        }
        QualifierSet::UnreferencedClock(generation) => {
            let generation = json!(generation);
            let unreferenced_context = QualificationContext {
                generation: &generation,
                ..context
            };
            let unreferenced = ValidatedRuntimeRecord::validate_value(clock_qualification(
                &unreferenced_context,
                "unreferenced",
            ))
            .expect("unreferenced clock qualifier");
            extra_records.push(unreferenced);
        }
    }
    if matches!(scenario.qualification_list, QualificationList::AddOpaque) {
        qualification_references
            .push(records["cohort_manifest"]["qualification_records"][0].clone());
    }
    cohort["qualification_records"] = Value::Array(qualification_references);
    let cohort_record =
        ValidatedRuntimeRecord::validate_value(cohort).expect("cohort with exact qualifiers");

    let mut activation = records["activation"].clone();
    activation["cohort_manifest"] = Value::from(cohort_record.exact_reference());
    let activation_record = ValidatedRuntimeRecord::validate_value(activation).expect("activation");

    let mut request = records["request"].clone();
    request["expected_binding"]["cohort_manifest"] = Value::from(cohort_record.exact_reference());
    request["expected_binding"]["activation"] = Value::from(activation_record.exact_reference());
    reseal_request(&mut request);
    let request_record = ValidatedRuntimeRecord::validate_value(request.clone()).expect("request");

    let mut deadline = deadline_evaluation(
        &namespace,
        &request_record.exact_reference(),
        &activation_record.exact_reference(),
        &clock_record.exact_reference(),
        &production_clock,
        &request["time_bounds"],
    );
    (scenario.mutate_deadline)(&mut deadline);
    deadline = seal(deadline, "evaluation_id");
    let deadline_record =
        ValidatedRuntimeRecord::validate_value(deadline).expect("deadline evaluation");

    let mut launch = records["execution_launch"].clone();
    launch["outer_request"] = Value::from(request_record.exact_reference());
    launch["activation_snapshot"] = Value::from(activation_record.exact_reference());
    launch["prelaunch_checks"]["deadline"] = Value::from(deadline_record.exact_reference());
    let launch_record = ValidatedRuntimeRecord::validate_value(launch).expect("launch");

    let relation_record =
        ValidatedRuntimeRecord::validate_value(records["subject_platform_relation"].clone())
            .expect("subject-platform relation");
    let mut set = RuntimeRecordSet::new();
    for record in [
        profile_record.clone(),
        clock_record.clone(),
        cohort_record,
        relation_record,
        activation_record,
        request_record,
        deadline_record.clone(),
        launch_record.clone(),
    ]
    .into_iter()
    .chain(extra_records)
    {
        set.insert(record).expect("unique record");
    }

    Fixture {
        records: set,
        launch: launch_record.exact_reference(),
        profile_qualification: profile_record.exact_reference(),
        clock_qualification: clock_record.exact_reference(),
        deadline_evaluation: deadline_record.exact_reference(),
        question: serde_json::from_value(question).expect("question identity"),
    }
}

#[test]
fn positive_selection_exposes_only_exact_reopenable_correspondence() {
    let fixture = fixture(Scenario::default());
    let selection = fixture
        .records
        .select_launch_correspondence(&fixture.launch)
        .expect("unique exact correspondence");

    assert_eq!(selection.launch(), &fixture.launch);
    assert_eq!(
        selection.native_profile_qualification(),
        &fixture.profile_qualification
    );
    assert_eq!(
        selection.native_clock_qualification(),
        &fixture.clock_qualification
    );
    assert_eq!(
        selection.deadline_evaluation(),
        &fixture.deadline_evaluation
    );
    assert_eq!(selection.production_question(), &fixture.question);
    for reference in [
        selection.launch(),
        selection.outer_request(),
        selection.activation(),
        selection.cohort_manifest(),
        selection.native_profile_qualification(),
        selection.native_clock_qualification(),
        selection.deadline_evaluation(),
    ] {
        assert_eq!(
            fixture
                .records
                .get(&reference.record_id)
                .expect("selected record")
                .exact_reference(),
            *reference
        );
    }
}

#[test]
fn qualification_list_is_excluded_but_every_cohort_semantic_field_is_load_bearing() {
    fn mutate_effective_interval(cohort: &mut Value) {
        cohort["effective_interval"]["effective_until"] = json!("2026-07-29T00:00:00Z");
    }

    let plain = fixture(Scenario::default());
    let augmented = fixture(Scenario {
        qualification_list: QualificationList::AddOpaque,
        ..Scenario::default()
    });
    let plain = plain
        .records
        .select_launch_correspondence(&plain.launch)
        .expect("plain selection");
    let augmented = augmented
        .records
        .select_launch_correspondence(&augmented.launch)
        .expect("additional opaque qualification");
    assert_ne!(plain.cohort_manifest(), augmented.cohort_manifest());
    assert_eq!(
        plain.cohort_semantics_digest(),
        augmented.cohort_semantics_digest()
    );

    let stale = fixture(Scenario {
        mutate_cohort: mutate_effective_interval,
        cohort_digest: CohortDigestMode::BeforeMutation,
        ..Scenario::default()
    });
    assert!(matches!(
        stale.records.select_launch_correspondence(&stale.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence profile qualifier cohort"
        ))
    ));
}

#[test]
fn cohort_identity_generation_and_digest_substitution_refuse() {
    fn substitute_identity(profile: &mut Value) {
        profile["cohort"]["id"] = json!("generic-host/other-profiles");
    }
    fn substitute_generation(profile: &mut Value) {
        profile["cohort_generation"] = json!("2");
    }
    fn substitute_digest(profile: &mut Value) {
        profile["cohort_semantics_digest"] = json!(digest("substituted-cohort-semantics"));
    }
    fn substitute_clock_identity(clock: &mut Value) {
        clock["cohort"]["id"] = json!("generic-host/other-profiles");
    }
    fn substitute_clock_generation(clock: &mut Value) {
        clock["cohort_generation"] = json!("2");
    }
    fn substitute_clock_digest(clock: &mut Value) {
        clock["cohort_semantics_digest"] = json!(digest("substituted-clock-cohort-semantics"));
    }

    for mutation in [
        substitute_identity as Mutation,
        substitute_generation,
        substitute_digest,
    ] {
        let fixture = fixture(Scenario {
            mutate_profile: mutation,
            ..Scenario::default()
        });
        assert!(matches!(
            fixture
                .records
                .select_launch_correspondence(&fixture.launch),
            Err(ContractError::InvocationJoin(
                "launch correspondence profile qualifier cohort"
            ))
        ));
    }

    for mutation in [
        substitute_clock_identity as Mutation,
        substitute_clock_generation,
        substitute_clock_digest,
    ] {
        let fixture = fixture(Scenario {
            mutate_clock: mutation,
            ..Scenario::default()
        });
        assert!(matches!(
            fixture
                .records
                .select_launch_correspondence(&fixture.launch),
            Err(ContractError::InvocationJoin(
                "launch correspondence clock qualifier cohort"
            ))
        ));
    }
}

#[test]
fn profile_question_is_exact_and_never_inferred_from_profile_text() {
    fn substitute_question(profile: &mut Value) {
        profile["production_question"]["id"] = json!("host-resource/lookalike-question");
    }
    let fixture = fixture(Scenario {
        mutate_profile: substitute_question,
        ..Scenario::default()
    });
    assert!(matches!(
        fixture
            .records
            .select_launch_correspondence(&fixture.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence profile or question outside cohort"
        ))
    ));
}

#[test]
fn duplicate_and_unreferenced_same_generation_qualifiers_refuse() {
    let duplicate = fixture(Scenario {
        qualifier_set: QualifierSet::DuplicateProfile,
        ..Scenario::default()
    });
    assert!(matches!(
        duplicate
            .records
            .select_launch_correspondence(&duplicate.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence requires exactly one applicable profile qualifier"
        ))
    ));

    let unreferenced = fixture(Scenario {
        qualifier_set: QualifierSet::UnreferencedProfile("1"),
        ..Scenario::default()
    });
    assert!(matches!(
        unreferenced
            .records
            .select_launch_correspondence(&unreferenced.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence qualifier claims cohort without exact cohort reference"
        ))
    ));

    let later_generation = fixture(Scenario {
        qualifier_set: QualifierSet::UnreferencedProfile("2"),
        ..Scenario::default()
    });
    later_generation
        .records
        .select_launch_correspondence(&later_generation.launch)
        .expect("later generation cannot reinterpret historical launch");

    let duplicate_clock = fixture(Scenario {
        qualifier_set: QualifierSet::DuplicateClock,
        ..Scenario::default()
    });
    assert!(matches!(
        duplicate_clock
            .records
            .select_launch_correspondence(&duplicate_clock.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence requires exactly one applicable clock qualifier"
        ))
    ));

    let unreferenced_clock = fixture(Scenario {
        qualifier_set: QualifierSet::UnreferencedClock("1"),
        ..Scenario::default()
    });
    assert!(matches!(
        unreferenced_clock
            .records
            .select_launch_correspondence(&unreferenced_clock.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence qualifier claims cohort without exact cohort reference"
        ))
    ));
}

#[test]
fn clock_must_match_exact_request_clock_and_subject_platform_relation() {
    fn substitute_clock(clock: &mut Value) {
        clock["production_clock"]["id"] = json!("lab/lookalike-clock");
    }
    fn substitute_platform(clock: &mut Value) {
        clock["platform"]["id"] = json!("ubuntu/24.04/lookalike");
    }
    for mutation in [substitute_clock as Mutation, substitute_platform] {
        let fixture = fixture(Scenario {
            mutate_clock: mutation,
            ..Scenario::default()
        });
        assert!(matches!(
            fixture
                .records
                .select_launch_correspondence(&fixture.launch),
            Err(ContractError::InvocationJoin(
                "launch correspondence requires exactly one applicable clock qualifier"
            ))
        ));
    }
}

#[test]
fn both_qualifiers_require_an_exact_compatible_production_build() {
    fn substitute_build(qualification: &mut Value) {
        qualification["production_build"]["id"] = json!("nq-diagnostic/lookalike");
    }
    let profile = fixture(Scenario {
        mutate_profile: substitute_build,
        ..Scenario::default()
    });
    assert!(matches!(
        profile
            .records
            .select_launch_correspondence(&profile.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence profile qualifier build"
        ))
    ));
    let clock = fixture(Scenario {
        mutate_clock: substitute_build,
        ..Scenario::default()
    });
    assert!(matches!(
        clock.records.select_launch_correspondence(&clock.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence clock qualifier build"
        ))
    ));
}

#[test]
fn deadline_must_reproduce_request_and_launch_instead_of_merely_be_accepted() {
    fn widen_request_bounds(deadline: &mut Value) {
        deadline["request_bounds"]["not_before"] = json!("2026-07-28T22:01:00Z");
    }
    fn shift_launch(deadline: &mut Value) {
        deadline["sample"]["realtime_before"] = json!("2026-07-28T22:02:02.999999000Z");
        deadline["sample"]["realtime_after"] = json!("2026-07-28T22:02:03Z");
        deadline["derived"]["launched_at"] = json!("2026-07-28T22:02:03Z");
        deadline["derived"]["attempt_deadline"] = json!("2026-07-28T22:02:33Z");
    }
    for mutation in [widen_request_bounds as Mutation, shift_launch] {
        let fixture = fixture(Scenario {
            mutate_deadline: mutation,
            ..Scenario::default()
        });
        assert!(matches!(
            fixture
                .records
                .select_launch_correspondence(&fixture.launch),
            Err(ContractError::InvocationJoin(
                "launch correspondence deadline does not reproduce exact launch"
            ))
        ));
    }
}

#[test]
fn deadline_exact_request_activation_clock_and_qualification_are_load_bearing() {
    fn substitute_request(deadline: &mut Value) {
        deadline["outer_request"] =
            typed_reference("nq.diagnostic_invocation_request.v1", "substituted-request");
    }
    fn substitute_activation(deadline: &mut Value) {
        deadline["activation"] =
            typed_reference("nq.runtime_activation.v1", "substituted-activation");
    }
    fn substitute_clock(deadline: &mut Value) {
        deadline["clock"]["id"] = json!("lab/lookalike-clock");
    }
    fn substitute_clock_qualification(deadline: &mut Value) {
        deadline["clock_qualification"] = typed_reference(
            "nq.native_clock_qualification.v1",
            "substituted-clock-qualification",
        );
    }
    for mutation in [
        substitute_request as Mutation,
        substitute_activation,
        substitute_clock,
        substitute_clock_qualification,
    ] {
        let fixture = fixture(Scenario {
            mutate_deadline: mutation,
            ..Scenario::default()
        });
        assert!(matches!(
            fixture
                .records
                .select_launch_correspondence(&fixture.launch),
            Err(ContractError::InvocationJoin(
                "launch correspondence deadline does not reproduce exact launch"
            ))
        ));
    }
}

#[test]
fn locally_valid_deadline_refusal_cannot_be_used_as_a_launch_precheck() {
    fn refuse_after_request_deadline(deadline: &mut Value) {
        deadline["sample"]["realtime_before"] = json!("2026-07-28T22:03:00.999999000Z");
        deadline["sample"]["realtime_after"] = json!("2026-07-28T22:03:01Z");
        deadline["derived"]["launched_at"] = json!("2026-07-28T22:03:01Z");
        deadline["derived"]["attempt_deadline"] = json!("2026-07-28T22:03:31Z");
        deadline["decision"]["state"] = json!("refused");
        deadline["decision"]["violations"] = json!([
            "request_deadline_exhausted",
            "execution_budget_exceeds_request_deadline"
        ]);
    }
    let fixture = fixture(Scenario {
        mutate_deadline: refuse_after_request_deadline,
        ..Scenario::default()
    });
    assert!(matches!(
        fixture
            .records
            .select_launch_correspondence(&fixture.launch),
        Err(ContractError::InvocationJoin(
            "launch correspondence deadline does not reproduce exact launch"
        ))
    ));
}

fn profile_qualification(context: &QualificationContext<'_>, variant: &str) -> Value {
    seal(
        json!({
            "schema": "nq.native_profile_qualification.v1",
            "qualification_id": digest("placeholder"),
            "namespace": context.namespace,
            "cohort": context.cohort,
            "cohort_generation": context.generation,
            "cohort_semantics_digest": context.semantics,
            "production_profile": context.profile,
            "production_question": context.question,
            "production_build": context.build,
            "native_profile": {
                "descriptor_schema": "nq.profile_descriptor.v1",
                "profile_id": format!("nq.host-resource-{variant}"),
                "profile_version": 1,
                "descriptor_digest": digest(&format!("native-profile-descriptor-{variant}")),
                "semantic_identity_schema": "nq.profile_semantic_id.v1",
                "semantic_identity_digest": digest(&format!("native-profile-semantics-{variant}")),
                "evaluator_source_digest": digest(&format!("native-evaluator-source-{variant}")),
                "helper_protocol_version": "nq.helper.v1",
                "detector_closure": {
                    "schema": "nq.detector_closure.v1",
                    "identity_digest": digest(&format!("native-detector-closure-{variant}")),
                    "detector_count": 0
                }
            },
            "native_evaluator": {
                "artifact_digest": digest(&format!("native-evaluator-artifact-{variant}")),
                "artifact_identity_method": "linux-proc-self-exe-fd-sha256-v1",
                "target_triple": "x86_64-unknown-linux-gnu"
            },
            "qualification_evidence": [
                external_reference(&format!("profile-qualification-evidence-{variant}"))
            ],
            "nonclaims": [
                "relates production and native identities but does not equate them",
                "does not establish invocation, reliance, authorization, or action"
            ]
        }),
        "qualification_id",
    )
}

fn clock_qualification(context: &QualificationContext<'_>, variant: &str) -> Value {
    seal(
        json!({
            "schema": "nq.native_clock_qualification.v1",
            "qualification_id": digest("placeholder"),
            "namespace": context.namespace,
            "cohort": context.cohort,
            "cohort_generation": context.generation,
            "cohort_semantics_digest": context.semantics,
            "production_clock": context.clock,
            "production_build": context.build,
            "platform": context.platform,
            "absolute_time": {
                "semantic_identity_digest": digest(&format!("clock-realtime-semantics-{variant}")),
                "observation_method": "clock_gettime-clock-realtime-v1",
                "clock_id": "CLOCK_REALTIME",
                "epoch": "unix",
                "unit": "nanosecond",
                "accuracy_qualification": {"status": "unqualified"}
            },
            "boottime": {
                "semantic_identity_digest": digest(&format!("clock-boottime-semantics-{variant}")),
                "observation_method": "clock_gettime-clock-boottime-v1",
                "clock_id": "CLOCK_BOOTTIME",
                "boot_epoch_binding_method": "linux-boot-id-v1",
                "unit": "nanosecond",
                "suspend_semantics": "includes_suspended_time"
            },
            "wall_to_monotonic_bridge": {
                "semantic_identity_digest": digest(&format!("clock-bridge-semantics-{variant}")),
                "method": "realtime-boottime-bracket-v1"
            },
            "runner_watchdog": {
                "method": "std-instant-v1",
                "relation_to_governed_deadline": "auxiliary_non_equivalent"
            },
            "qualification_evidence": [
                external_reference(&format!("clock-qualification-evidence-{variant}"))
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
    namespace: &Value,
    request: &RecordRef,
    activation: &RecordRef,
    clock_qualification: &RecordRef,
    clock: &Value,
    request_bounds: &Value,
) -> Value {
    seal(
        json!({
            "schema": "nq.deadline_evaluation.v1",
            "evaluation_id": digest("placeholder"),
            "namespace": namespace,
            "outer_request": request,
            "activation": activation,
            "clock_qualification": clock_qualification,
            "clock": clock,
            "request_bounds": {
                "not_before": request_bounds["not_before"],
                "deadline": request_bounds["deadline"],
                "maximum_execution_ms": request_bounds["maximum_execution_ms"]
            },
            "bracket_policy": {
                "policy": identity("policy", "nq/deadline-bracket", "1", "deadline-policy"),
                "maximum_width_ns": 100_000
            },
            "sample": {
                "realtime_before": "2026-07-28T22:02:01.999999000Z",
                "boottime_at_ns": "10000000000000000",
                "realtime_after": "2026-07-28T22:02:02Z",
                "bracket_width_ns": 1000,
                "boot_epoch": digest("boot-epoch")
            },
            "derived": {
                "launched_at": "2026-07-28T22:02:02Z",
                "attempt_deadline": "2026-07-28T22:02:32Z",
                "boottime_expiry_ns": "10000030000000000"
            },
            "decision": {
                "state": "accepted",
                "violations": []
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

fn cohort_semantics_digest(cohort: &Value) -> Sha256Digest {
    let object = cohort.as_object().expect("cohort object");
    let mut body = Map::new();
    body.insert(
        "semantic_schema".to_owned(),
        json!("nq.static_profile_cohort_semantics.v1"),
    );
    for field in [
        "namespace",
        "cohort",
        "generation",
        "effective_interval",
        "members",
        "compatible_builds",
        "protocol_store_compatibility",
        "nonclaims",
    ] {
        body.insert(field.to_owned(), object[field].clone());
    }
    semantic_digest(&Value::Object(body)).expect("cohort semantic digest")
}

fn reseal_request(request: &mut Value) {
    let mut preimage = request.clone();
    let preimage = preimage.as_object_mut().expect("request object");
    preimage.remove("request_digest");
    preimage.remove("request_preimage_digest");
    preimage.remove("invocation_authorization");
    request["request_preimage_digest"] = Value::String(
        semantic_digest(&Value::Object(preimage.clone()))
            .expect("preimage")
            .to_string(),
    );

    let mut complete = request.clone();
    complete
        .as_object_mut()
        .expect("request object")
        .remove("request_digest");
    request["request_digest"] = Value::String(
        semantic_digest(&complete)
            .expect("request digest")
            .to_string(),
    );
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

fn digest(label: &str) -> String {
    sha256_bytes(label.as_bytes()).to_string()
}

fn external_reference(label: &str) -> Value {
    typed_reference("nq.external_record.v1", label)
}

fn typed_reference(schema: &str, label: &str) -> Value {
    json!({
        "schema": schema,
        "record_id": digest(&format!("{label}-id")),
        "bytes_digest": digest(&format!("{label}-bytes"))
    })
}

fn identity(kind: &str, id: &str, version: &str, descriptor: &str) -> Value {
    json!({
        "kind": kind,
        "id": id,
        "version": version,
        "descriptor_digest": digest(descriptor)
    })
}
