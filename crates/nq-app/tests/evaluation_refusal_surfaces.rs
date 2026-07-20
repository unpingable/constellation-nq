//! Evaluation-refusal preservation through the shipped public surfaces.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::{DateTime, Utc};
use nq_core::config::{ScopeConfig, VantageConfig};
use nq_core::engine::{
    EvaluationContextV1, EvaluationDetectorIdentity, EvaluationEnvelopeSchema,
    EvaluationEnvelopeV2, EvaluationProfileIdentity, EvaluationWatermarkV2,
};
use nq_core::public::{ConditionState, VisibilityState};
use nq_core::{
    CollectionOutcome, EvaluationResultSchema, EvaluationResultV1, FindingSnapshotV3,
    GovernedRefusal, GovernedRefusalOrigin, decode_collection_outcome_ndjson,
};
use nq_profiles::{
    DetectorState, EvidenceWatermark, ProfileKey, ProfileRefusal, ProfileRefusalCode,
    RefusalBoundary, profile_semantic_id, resolve_profile,
};
use nq_store::{
    CanonicalDocument, EvaluationInput, EvaluationProfileBinding, EvaluationWatermark,
    FindingEventInput, ProfileDescriptorInput, RefusalInput, Store,
};
use serde::Serialize;
use serde_json::{Value, json};

const TEST_TIME: &str = "2026-07-20T16:00:00Z";

fn document(value: &impl Serialize) -> CanonicalDocument {
    CanonicalDocument::from_serializable(value).expect("fixture document canonicalizes")
}

fn write_config(root: &Path, name: &str, database: &Path) -> PathBuf {
    let path = root.join(format!("{name}.toml"));
    fs::write(
        &path,
        format!(
            "schema = \"nq.config.v1\"\ndatabase_path = \"{}\"\nsocket_path = \"{}\"\n\
             admissions_dir = \"{}\"\nhelper_runtime_dir = \"{}\"\n",
            database.display(),
            root.join(format!("{name}.sock")).display(),
            root.join(format!("{name}-admissions")).display(),
            root.join(format!("{name}-helpers")).display(),
        ),
    )
    .expect("write test configuration");
    path
}

fn run(nq: &Path, config: &Path, arguments: &[&str]) -> Output {
    Command::new(nq)
        .arg("--config")
        .arg(config)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("shipped nq binary executes")
}

#[allow(clippy::needless_pass_by_value)]
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command output is JSON")
}

#[derive(Clone)]
struct EvaluationFixture {
    instance_id: &'static str,
    subject: String,
    scope: ScopeConfig,
    vantage: VantageConfig,
    detector_id: String,
    detector_version: u32,
    finding_id: &'static str,
    profile: ProfileKey,
    profile_refusal: ProfileRefusal,
    refusal: GovernedRefusal,
    profile_digest: String,
    detector_digest: String,
}

fn append_descriptor(
    store: &mut Store,
    profile: &'static dyn nq_profiles::ProfileModule,
) -> String {
    let descriptor = document(profile.descriptor());
    let profile_digest = descriptor.digest().to_owned();
    let profile_id = &profile.descriptor().profile.id;
    let profile_version = profile.descriptor().profile.version.to_string();
    if store
        .profile_descriptor(profile_id, &profile_version, &profile_digest)
        .expect("read profile descriptor")
        .is_none()
    {
        store
            .append_profile_descriptor(&ProfileDescriptorInput {
                profile_id: profile_id.clone(),
                profile_version,
                descriptor,
                recorded_at: TEST_TIME.to_owned(),
            })
            .expect("append profile descriptor");
    }
    profile_digest
}

#[allow(clippy::too_many_arguments)]
fn fixture(
    store: &mut Store,
    instance_id: &'static str,
    finding_id: &'static str,
    refusal_id: &'static str,
    scope_id: &'static str,
    details: BTreeMap<String, String>,
) -> EvaluationFixture {
    let module = resolve_profile("nq.host", 1).expect("compiled host fixture profile");
    let profile = module.descriptor().profile.clone();
    let profile_digest = append_descriptor(store, module);
    let detector = module.detectors()[0].descriptor();
    let profile_refusal = ProfileRefusal {
        instance_id: instance_id.to_owned(),
        profile: profile.clone(),
        boundary: RefusalBoundary::Detector,
        code: ProfileRefusalCode::CannotEvaluate,
        message: "insufficient current evidence".to_owned(),
        details,
    };
    let refusal = GovernedRefusal::profile(
        refusal_id.to_owned(),
        profile_semantic_id(module.descriptor()).expect("profile semantic identity"),
        profile_refusal.clone(),
    );
    refusal.validate().expect("governed evaluation refusal");
    EvaluationFixture {
        instance_id,
        subject: format!("host:{scope_id}"),
        scope: ScopeConfig {
            kind: "host".to_owned(),
            value: json!({"id": scope_id}),
        },
        vantage: VantageConfig {
            kind: "local".to_owned(),
            value: json!({}),
        },
        detector_id: detector.id.clone(),
        detector_version: detector.version,
        finding_id,
        profile,
        profile_refusal,
        refusal,
        profile_digest,
        detector_digest: detector.digest().expect("detector digest").clone(),
    }
}

#[allow(clippy::too_many_lines)]
fn commit_present_then_cannot_evaluate(
    store: &mut Store,
    fixture: &EvaluationFixture,
    with_prior_finding: bool,
) -> EvaluationEnvelopeV2 {
    let module = resolve_profile(&fixture.profile.id, fixture.profile.version)
        .expect("compiled fixture profile");
    let detector = module.detectors()[0].descriptor();
    let GovernedRefusalOrigin::Profile(governed_profile) = &fixture.refusal.origin else {
        panic!("evaluation fixture refusal must be profile-origin");
    };
    let evaluation_profile = EvaluationProfileIdentity {
        profile: fixture.profile.clone(),
        profile_digest: module.descriptor().digest().expect("profile digest"),
        profile_semantic_id: governed_profile.profile_semantic_id.clone(),
    };
    let store_profile = EvaluationProfileBinding {
        profile_id: fixture.profile.id.clone(),
        profile_version: fixture.profile.version.to_string(),
        profile_digest: fixture.profile_digest.clone(),
        profile_semantic_id: nq_protocol::Sha256Digest::parse(
            governed_profile.profile_semantic_id.as_str(),
        )
        .expect("profile semantic digest"),
    };
    let watermarks = vec![EvaluationWatermark {
        instance_id: fixture.instance_id.to_owned(),
        max_report_sequence: 0,
        watermark_received_at: None,
    }];
    let evaluated_at: DateTime<Utc> = TEST_TIME.parse().expect("fixture timestamp");
    let evaluator_artifact_digest =
        nq_protocol::sha256_bytes(b"evaluation-refusal-surface-evaluator");
    let present = EvaluationResultV1 {
        schema: EvaluationResultSchema::V1,
        profile: evaluation_profile.clone(),
        state: DetectorState::Present,
        condition: detector.condition.clone(),
        summary: "condition is present".to_owned(),
        evidence: Vec::new(),
        limitations: Vec::new(),
        refusal: None,
        watermark: EvidenceWatermark(0),
    };
    let opened = FindingEventInput {
        event_id: format!("event-{}-opened", fixture.finding_id),
        finding_id: fixture.finding_id.to_owned(),
        event_kind: "opened".to_owned(),
        instance_id: fixture.instance_id.to_owned(),
        profile_id: fixture.profile.id.clone(),
        profile_version: fixture.profile.version.to_string(),
        profile_digest: fixture.profile_digest.clone(),
        subject: document(&fixture.subject),
        condition_name: present.condition.clone(),
        condition_state: "present".to_owned(),
        visibility_state: "sufficient".to_owned(),
        operator_work_state: "unreviewed".to_owned(),
        severity: "warning".to_owned(),
        summary: present.summary.clone(),
        limitations: document(&present.limitations),
        safe_next_checks: document(&vec![
            "Inspect the cited admitted evidence".to_owned(),
            "Run `nq watcher test` if collection remains unavailable".to_owned(),
        ]),
        freshness: document(&json!({"state": "current"})),
        basis: document(&json!({
            "profile_digest": fixture.profile_digest,
            "scope": fixture.scope,
            "vantage": fixture.vantage,
        })),
        refusal: None,
        origin_mode: "native".to_owned(),
        historical_refs: document(&Vec::<String>::new()),
        observed_at: None,
        received_at: None,
        created_at: TEST_TIME.to_owned(),
        evidence: Vec::new(),
    };
    let present_id = format!("evaluation-{}-present", fixture.finding_id);
    let present_envelope = EvaluationEnvelopeV2 {
        schema: EvaluationEnvelopeSchema::V2,
        evaluation_id: present_id.clone(),
        trigger_run_id: None,
        context: EvaluationContextV1 {
            instance_id: fixture.instance_id.to_owned(),
            subject: fixture.subject.clone(),
            scope: fixture.scope.clone(),
            vantage: fixture.vantage.clone(),
        },
        detector: EvaluationDetectorIdentity {
            id: fixture.detector_id.clone(),
            version: fixture.detector_version.to_string(),
            digest: fixture.detector_digest.clone(),
        },
        evaluator_artifact_digest: evaluator_artifact_digest.clone(),
        profile: evaluation_profile.clone(),
        started_at: evaluated_at,
        evaluated_at,
        watermark: EvaluationWatermarkV2 {
            instance_id: fixture.instance_id.to_owned(),
            max_report_sequence: 0,
            watermark_received_at: None,
        },
        result: present,
    };
    let present_revision = if with_prior_finding {
        let receipt = store
            .commit_evaluation(
                &EvaluationInput {
                    evaluation_id: present_id.clone(),
                    trigger_run_id: None,
                    detector_id: fixture.detector_id.clone(),
                    detector_version: fixture.detector_version.to_string(),
                    detector_digest: fixture.detector_digest.clone(),
                    evaluator_artifact_digest: evaluator_artifact_digest.to_string(),
                    started_at: TEST_TIME.to_owned(),
                    evaluated_at: TEST_TIME.to_owned(),
                    outcome: "condition_present".to_owned(),
                    detail: document(&present_envelope),
                    profile: store_profile.clone(),
                    watermarks: watermarks.clone(),
                    refusal: None,
                },
                Some(&opened),
            )
            .expect("commit policy-valid present finding");
        assert_eq!(receipt.evaluation_id, present_id);
        Some(receipt.evaluation_revision)
    } else {
        None
    };

    let refused = EvaluationResultV1 {
        schema: EvaluationResultSchema::V1,
        profile: evaluation_profile.clone(),
        state: DetectorState::CannotEvaluate,
        condition: detector.condition.clone(),
        summary: fixture.profile_refusal.message.clone(),
        evidence: Vec::new(),
        limitations: vec!["evaluation refused at a typed profile boundary".to_owned()],
        refusal: Some(fixture.refusal.clone()),
        watermark: EvidenceWatermark(0),
    };
    let mut updated = opened;
    updated.event_id = format!("event-{}-refused", fixture.finding_id);
    "updated".clone_into(&mut updated.event_kind);
    "missing".clone_into(&mut updated.visibility_state);
    updated.limitations = document(&refused.limitations);
    updated.freshness = document(&json!({"state": "missing"}));
    updated.refusal = Some(document(&fixture.refusal));

    let refused_id = format!("evaluation-{}-refused", fixture.finding_id);
    let refused_envelope = EvaluationEnvelopeV2 {
        schema: EvaluationEnvelopeSchema::V2,
        evaluation_id: refused_id.clone(),
        trigger_run_id: None,
        context: EvaluationContextV1 {
            instance_id: fixture.instance_id.to_owned(),
            subject: fixture.subject.clone(),
            scope: fixture.scope.clone(),
            vantage: fixture.vantage.clone(),
        },
        detector: EvaluationDetectorIdentity {
            id: fixture.detector_id.clone(),
            version: fixture.detector_version.to_string(),
            digest: fixture.detector_digest.clone(),
        },
        evaluator_artifact_digest: evaluator_artifact_digest.clone(),
        profile: evaluation_profile,
        started_at: evaluated_at,
        evaluated_at,
        watermark: EvaluationWatermarkV2 {
            instance_id: fixture.instance_id.to_owned(),
            max_report_sequence: 0,
            watermark_received_at: None,
        },
        result: refused,
    };
    let receipt = store
        .commit_evaluation(
            &EvaluationInput {
                evaluation_id: refused_id.clone(),
                trigger_run_id: None,
                detector_id: fixture.detector_id.clone(),
                detector_version: fixture.detector_version.to_string(),
                detector_digest: fixture.detector_digest.clone(),
                evaluator_artifact_digest: evaluator_artifact_digest.to_string(),
                started_at: TEST_TIME.to_owned(),
                evaluated_at: TEST_TIME.to_owned(),
                outcome: "cannot_evaluate".to_owned(),
                detail: document(&refused_envelope),
                profile: store_profile,
                watermarks,
                refusal: Some(RefusalInput {
                    refusal_id: fixture.refusal.refusal_id.clone(),
                    source_kind: "profile".to_owned(),
                    responsible_instance_id: fixture.instance_id.to_owned(),
                    boundary: "detector".to_owned(),
                    code: "cannot_evaluate".to_owned(),
                    profile_semantic_id: Some(
                        governed_profile.profile_semantic_id.as_str().to_owned(),
                    ),
                    detail: document(&fixture.refusal),
                    created_at: TEST_TIME.to_owned(),
                }),
            },
            with_prior_finding.then_some(&updated),
        )
        .expect("commit typed cannot-evaluate update");
    assert_eq!(receipt.evaluation_id, refused_id);
    if let Some(present_revision) = present_revision {
        assert_eq!(receipt.evaluation_revision, present_revision + 1);
    }
    refused_envelope
}

fn assert_exact_pair(findings: &[FindingSnapshotV3], fixtures: &[EvaluationFixture; 2]) {
    assert_eq!(findings.len(), fixtures.len());
    let mut reopened = Vec::new();
    for fixture in fixtures {
        let finding = findings
            .iter()
            .find(|finding| finding.finding_id == fixture.finding_id)
            .unwrap_or_else(|| panic!("missing finding {}", fixture.finding_id));
        assert_eq!(finding.schema, "nq.finding_snapshot.v3");
        assert_eq!(finding.instance_id, fixture.instance_id);
        assert_eq!(finding.detector.id, fixture.detector_id);
        assert_eq!(finding.detector.version, fixture.detector_version);
        assert_eq!(finding.detector.digest, fixture.detector_digest);
        assert_eq!(finding.profile.id, fixture.profile.id);
        assert_eq!(finding.profile.version, fixture.profile.version);
        assert_eq!(finding.profile.digest, fixture.profile_digest);
        assert_eq!(finding.condition.name, "host_load_pressure");
        assert_eq!(finding.condition.state, ConditionState::Present);
        assert_eq!(finding.visibility.state, VisibilityState::Missing);
        assert_eq!(finding.visibility.basis["scope"], json!(fixture.scope));
        assert_eq!(finding.visibility.basis["vantage"], json!(fixture.vantage));

        let typed = finding
            .visibility
            .refusal
            .as_ref()
            .expect("cannot-evaluate finding carries its typed refusal");
        assert_eq!(typed, &fixture.refusal);
        assert_eq!(typed.refusal_id, fixture.refusal.refusal_id);
        let GovernedRefusalOrigin::Profile(profile) = &typed.origin else {
            panic!("evaluation refusal lost its governed profile origin")
        };
        assert_eq!(profile.refusal, fixture.profile_refusal);
        assert_eq!(profile.refusal.boundary, RefusalBoundary::Detector);
        assert_eq!(profile.refusal.code, ProfileRefusalCode::CannotEvaluate);
        assert!(
            !profile.refusal.details.is_empty(),
            "structured details must survive"
        );
        reopened.push(typed.clone());
    }

    let profiles = reopened
        .iter()
        .map(|refusal| match &refusal.origin {
            GovernedRefusalOrigin::Profile(profile) => profile,
            _ => panic!("evaluation refusal lost its governed profile origin"),
        })
        .collect::<Vec<_>>();
    assert_eq!(profiles[0].refusal.code, profiles[1].refusal.code);
    assert_eq!(profiles[0].refusal.boundary, profiles[1].refusal.boundary);
    assert_eq!(profiles[0].refusal.message, profiles[1].refusal.message);
    assert_eq!(
        profiles[0].profile_semantic_id,
        profiles[1].profile_semantic_id
    );
    assert_eq!(profiles[0].refusal.profile, profiles[1].refusal.profile);
    assert_ne!(fixtures[0].scope, fixtures[1].scope);
    assert_ne!(profiles[0].refusal.details, profiles[1].refusal.details);
    assert_ne!(reopened[0].refusal_id, reopened[1].refusal_id);
    assert_ne!(reopened[0], reopened[1]);
}

fn assert_first_refusal_surfaces(store: &Store, expected: &EvaluationEnvelopeV2) {
    assert!(
        nq_core::engine::list_findings(store)
            .expect("read findings")
            .iter()
            .all(|finding| finding.instance_id != expected.context.instance_id),
        "first-ever cannot-evaluate must not invent a finding"
    );
    let status = nq_core::engine::status_snapshot_v3(store).expect("read V3 status");
    let component = status
        .components
        .iter()
        .find(|component| component.id == expected.evaluation_id)
        .expect("first-ever refusal remains visible as evaluation status");
    let nq_core::public::ComponentStatusDetailV3::Evaluation { result, .. } = &component.detail
    else {
        panic!("first-ever refusal must remain typed evaluation detail")
    };
    assert_eq!(result, expected);
    let history = nq_core::engine::evaluation_history_bounded(store, 1_000, None, None)
        .expect("read complete evaluation history");
    assert!(history.complete);
    assert!(
        history
            .records
            .iter()
            .any(|record| &record.result == expected)
    );
    assert!(matches!(
        nq_core::engine::status_snapshot_v2(store),
        Err(nq_core::engine::EngineError::Invariant(message))
            if message == "nq.status_snapshot.v2 cannot emit governed evaluation results; use v3"
    ));
}

fn assert_evaluation_pair_surfaces(store: &Store, expected: &[EvaluationEnvelopeV2]) {
    let status = nq_core::engine::status_snapshot_v3(store).expect("read paired V3 status");
    let reopened = expected
        .iter()
        .map(|expected| {
            let component = status
                .components
                .iter()
                .find(|component| component.id == expected.evaluation_id)
                .unwrap_or_else(|| panic!("missing evaluation status {}", expected.evaluation_id));
            assert_eq!(component.code, "cannot_evaluate");
            let nq_core::public::ComponentStatusDetailV3::Evaluation { result, .. } =
                &component.detail
            else {
                panic!("paired status must carry typed evaluation detail")
            };
            assert_eq!(result, expected);
            result
        })
        .collect::<Vec<_>>();
    assert_ne!(reopened[0], reopened[1]);
    let history = nq_core::engine::evaluation_history_bounded(store, 1_000, None, None)
        .expect("read paired evaluation history");
    for expected in expected {
        assert!(
            history
                .records
                .iter()
                .any(|record| &record.result == expected),
            "evaluation history lost {}",
            expected.evaluation_id
        );
    }
}

fn findings_from_value(value: Value) -> Vec<FindingSnapshotV3> {
    serde_json::from_value(value).expect("CLI findings strictly decode as the public DTO")
}

#[test]
#[allow(clippy::too_many_lines)]
fn same_code_evaluation_refusals_survive_backup_cli_and_cold_archive() {
    let nq = Path::new(env!("CARGO_BIN_EXE_nq"));
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    let database = root.join("nq.db");
    let config = write_config(root, "live", &database);
    let mut store = Store::initialize(&database).expect("initialize store");

    let fixtures = [
        fixture(
            &mut store,
            "evaluation-alpha",
            "finding-evaluation-alpha",
            "refusal-evaluation-alpha",
            "alpha",
            BTreeMap::from([
                ("coverage".to_owned(), "reachability".to_owned()),
                ("missing_basis".to_owned(), "active_probe".to_owned()),
            ]),
        ),
        fixture(
            &mut store,
            "evaluation-beta",
            "finding-evaluation-beta",
            "refusal-evaluation-beta",
            "beta",
            BTreeMap::from([
                ("age_seconds".to_owned(), "121".to_owned()),
                ("reliance_seconds".to_owned(), "60".to_owned()),
            ]),
        ),
    ];
    let pair_evaluations = fixtures
        .iter()
        .map(|fixture| commit_present_then_cannot_evaluate(&mut store, fixture, true))
        .collect::<Vec<_>>();
    let first_refusal_fixture = fixture(
        &mut store,
        "evaluation-first",
        "finding-evaluation-first",
        "refusal-evaluation-first",
        "first",
        BTreeMap::from([("reason".to_owned(), "missing_testimony".to_owned())]),
    );
    let first_refusal =
        commit_present_then_cannot_evaluate(&mut store, &first_refusal_fixture, false);

    let wire_pair = pair_evaluations
        .iter()
        .enumerate()
        .map(|(index, original)| {
            let mut evaluation = original.clone();
            let run_id = format!("wire-run-{index}");
            evaluation.trigger_run_id = Some(run_id.clone());
            let carrier = CollectionOutcome::admitted(
                evaluation.context.instance_id.clone(),
                run_id,
                format!("wire-report-{index}"),
                "failed".to_owned(),
                nq_protocol::sha256_bytes(format!("wire-report-{index}").as_bytes()).into_string(),
                vec![evaluation],
            );
            let wire = nq_protocol::encode_ndjson(&carrier).expect("encode admitted V2 carrier");
            assert_eq!(
                decode_collection_outcome_ndjson(&wire, wire.len())
                    .expect("strictly decode admitted V2 carrier"),
                carrier
            );
            carrier
        })
        .collect::<Vec<_>>();
    assert_ne!(wire_pair[0], wire_pair[1]);

    let mut multi_evaluations = pair_evaluations.clone();
    for (index, evaluation) in multi_evaluations.iter_mut().enumerate() {
        evaluation.evaluation_id = format!("wire-multi-evaluation-{index}");
        evaluation.trigger_run_id = Some("wire-multi-run".to_owned());
        evaluation.context.instance_id = "wire-multi-instance".to_owned();
        evaluation.watermark.instance_id = "wire-multi-instance".to_owned();
        let refusal = evaluation
            .result
            .refusal
            .as_mut()
            .expect("same-code pair carries refusals");
        let GovernedRefusalOrigin::Profile(profile) = &mut refusal.origin else {
            panic!("wire pair remains profile-origin")
        };
        profile.refusal.instance_id = "wire-multi-instance".to_owned();
    }
    let multi = CollectionOutcome::admitted(
        "wire-multi-instance".to_owned(),
        "wire-multi-run".to_owned(),
        "wire-multi-report".to_owned(),
        "failed".to_owned(),
        nq_protocol::sha256_bytes(b"wire-multi-report").into_string(),
        multi_evaluations,
    );
    let multi_wire = nq_protocol::encode_ndjson(&multi).expect("encode multi-evaluation carrier");
    assert_eq!(
        decode_collection_outcome_ndjson(&multi_wire, multi_wire.len())
            .expect("strict multi-evaluation round trip"),
        multi
    );
    let multi_value = serde_json::to_value(&multi).expect("multi carrier value");
    let hostile_wire = |value: &Value| {
        let mut bytes = nq_protocol::canonical_json_bytes(value).expect("hostile canonical body");
        bytes.push(b'\n');
        bytes
    };
    let mut reordered = multi_value.clone();
    reordered["result"]["evaluations"]
        .as_array_mut()
        .expect("evaluation vector")
        .reverse();
    let reordered = hostile_wire(&reordered);
    assert!(decode_collection_outcome_ndjson(&reordered, reordered.len()).is_err());
    let mut duplicated = multi_value.clone();
    let first = duplicated["result"]["evaluations"][0].clone();
    duplicated["result"]["evaluations"]
        .as_array_mut()
        .expect("evaluation vector")
        .push(first);
    let duplicated = hostile_wire(&duplicated);
    assert!(decode_collection_outcome_ndjson(&duplicated, duplicated.len()).is_err());
    let mut substituted = multi_value;
    substituted["result"]["evaluations"][1]["result"]["refusal"]["origin"]["payload"]["refusal"]
        ["details"]["age_seconds"] = json!("122");
    let substituted = hostile_wire(&substituted);
    let substituted = decode_collection_outcome_ndjson(&substituted, substituted.len())
        .expect("a different exact governed payload remains a valid distinct carrier");
    assert_ne!(substituted, multi);
    let mut legacy_schema = serde_json::to_value(&multi).expect("multi carrier value");
    legacy_schema["schema"] = json!("nq.collection_outcome.v1");
    let legacy_schema = hostile_wire(&legacy_schema);
    assert!(
        decode_collection_outcome_ndjson(&legacy_schema, legacy_schema.len()).is_err(),
        "admitted evaluation testimony must never be relabeled as collection v1"
    );

    let mut omitted = serde_json::to_value(&wire_pair[0]).expect("wire carrier value");
    omitted["result"]
        .as_object_mut()
        .expect("admitted result object")
        .remove("evaluations");
    let mut omitted_wire =
        nq_protocol::canonical_json_bytes(&omitted).expect("canonical hostile omission");
    omitted_wire.push(b'\n');
    assert!(
        decode_collection_outcome_ndjson(&omitted_wire, omitted_wire.len()).is_err(),
        "strict product decoder must reject an omitted governed evaluation set"
    );
    store.validate().expect("committed store validates");
    assert_exact_pair(
        &nq_core::engine::list_findings(&store).expect("read committed public findings"),
        &fixtures,
    );
    assert_first_refusal_surfaces(&store, &first_refusal);
    assert_evaluation_pair_surfaces(&store, &pair_evaluations);

    drop(store);
    let reopened = Store::open(&database).expect("reopen committed store");
    assert_exact_pair(
        &nq_core::engine::list_findings(&reopened).expect("read reopened public findings"),
        &fixtures,
    );
    assert_first_refusal_surfaces(&reopened, &first_refusal);
    assert_evaluation_pair_surfaces(&reopened, &pair_evaluations);

    let backup = root.join("verified-backup.db");
    let artifact = reopened
        .backup_verified(&backup)
        .expect("create and verify SQLite backup");
    assert_eq!(artifact.path, backup);
    assert!(artifact.sha256.starts_with("sha256:"));
    assert!(artifact.size_bytes > 0);
    drop(reopened);

    let backup_store = Store::open(&backup).expect("reopen verified backup");
    backup_store.validate().expect("backup validates");
    assert_exact_pair(
        &nq_core::engine::list_findings(&backup_store).expect("read backup public findings"),
        &fixtures,
    );
    assert_first_refusal_surfaces(&backup_store, &first_refusal);
    assert_evaluation_pair_surfaces(&backup_store, &pair_evaluations);
    drop(backup_store);

    let live_cli = success(run(nq, &config, &["findings", "export"]));
    assert_exact_pair(&findings_from_value(live_cli.clone()), &fixtures);
    let live_status = success(run(nq, &config, &["status", "export"]));
    assert_eq!(live_status["schema"], "nq.status_snapshot.v3");
    assert!(
        live_status["components"]
            .as_array()
            .expect("CLI status components")
            .iter()
            .any(|component| component["detail"]["result"]
                == serde_json::to_value(&first_refusal).expect("first refusal serializes"))
    );
    for expected in &pair_evaluations {
        let component = live_status["components"]
            .as_array()
            .expect("CLI status components")
            .iter()
            .find(|component| component["id"] == expected.evaluation_id)
            .unwrap_or_else(|| panic!("CLI status lost {}", expected.evaluation_id));
        assert_eq!(component["code"], "cannot_evaluate");
        assert_eq!(
            component["detail"]["result"],
            serde_json::to_value(expected).expect("paired evaluation serializes")
        );
    }
    let live_evaluations = success(run(nq, &config, &["evaluations", "export"]));
    assert_eq!(live_evaluations["schema"], "nq.evaluation_history.v1");
    assert_eq!(live_evaluations["complete"], true);
    assert!(
        live_evaluations["records"]
            .as_array()
            .expect("CLI evaluation records")
            .iter()
            .any(|record| record["result"]
                == serde_json::to_value(&first_refusal).expect("first refusal serializes"))
    );
    for expected in &pair_evaluations {
        assert!(
            live_evaluations["records"]
                .as_array()
                .expect("CLI evaluation records")
                .iter()
                .any(|record| record["result"]
                    == serde_json::to_value(expected).expect("paired evaluation serializes"))
        );
    }

    let archive = root.join("cold-archive");
    let archive_report = success(run(
        nq,
        &config,
        &[
            "admin",
            "archive",
            "--destination",
            archive.to_str().expect("archive path is UTF-8"),
        ],
    ));
    assert_eq!(archive_report["archive_format"], "nq.cold_archive.v1");
    assert_eq!(archive_report["source_openable"], true);

    let archived_nq = archive.join("bin/nq");
    let verification = success(run(
        &archived_nq,
        &config,
        &[
            "admin",
            "archive-verify",
            archive.to_str().expect("archive path is UTF-8"),
        ],
    ));
    assert_eq!(verification["integrity_verified"], true);
    assert_eq!(verification["historical_database_verified"], true);
    assert_eq!(
        verification["historical_admitted_report_semantics_verified"],
        true
    );
    assert_eq!(verification["historical_admitted_reports_verified"], 0);
    assert_eq!(verification["historical_status_events_verified"], 0);
    assert_eq!(
        verification["historical_rejected_custody_records_verified"],
        0
    );
    assert_eq!(
        verification["historical_evaluation_refusal_semantics_verified"],
        true
    );
    assert_eq!(verification["historical_evaluation_records_verified"], 5);
    assert_eq!(verification["grants_authority"], false);

    let archived_database = archive.join("db/nq.db");
    let archived_store =
        Store::open_immutable(&archived_database).expect("reopen archived database immutably");
    assert_exact_pair(
        &nq_core::engine::list_findings(&archived_store).expect("read archived public findings"),
        &fixtures,
    );
    assert_first_refusal_surfaces(&archived_store, &first_refusal);
    assert_evaluation_pair_surfaces(&archived_store, &pair_evaluations);
    drop(archived_store);

    let reopen_root = root.join("archive-reopen");
    fs::create_dir(&reopen_root).expect("create archive reopen directory");
    let archived_config = write_config(&reopen_root, "archived", &archived_database);
    let archived_cli = success(run(&archived_nq, &archived_config, &["findings", "export"]));
    assert_eq!(archived_cli, live_cli);
    assert_exact_pair(&findings_from_value(archived_cli), &fixtures);
    let archived_status = success(run(&archived_nq, &archived_config, &["status", "export"]));
    assert_eq!(archived_status["schema"], live_status["schema"]);
    assert_eq!(
        archived_status["evaluation_through_sequence"],
        live_status["evaluation_through_sequence"]
    );
    assert_eq!(archived_status["components"], live_status["components"]);
    let archived_evaluations = success(run(
        &archived_nq,
        &archived_config,
        &["evaluations", "export"],
    ));
    for field in [
        "schema",
        "limit",
        "after_sequence",
        "through_sequence",
        "records",
        "next_after_sequence",
        "complete",
    ] {
        assert_eq!(archived_evaluations[field], live_evaluations[field]);
    }
}
