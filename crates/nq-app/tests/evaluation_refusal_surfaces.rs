//! Evaluation-refusal preservation through the shipped public surfaces.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use nq_core::engine::EvaluationProfileIdentity;
use nq_core::public::{ConditionState, VisibilityState};
use nq_core::{
    EvaluationResultSchema, EvaluationResultV1, FindingSnapshotV3, GovernedRefusal,
    GovernedRefusalOrigin,
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

fn digest(label: &str) -> String {
    nq_protocol::sha256_bytes(label.as_bytes()).into_string()
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
    detector_id: &'static str,
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
    store
        .append_profile_descriptor(&ProfileDescriptorInput {
            profile_id: profile.descriptor().profile.id.clone(),
            profile_version: profile.descriptor().profile.version.to_string(),
            descriptor,
            recorded_at: TEST_TIME.to_owned(),
        })
        .expect("append profile descriptor");
    profile_digest
}

#[allow(clippy::too_many_arguments)]
fn fixture(
    store: &mut Store,
    instance_id: &'static str,
    detector_id: &'static str,
    finding_id: &'static str,
    refusal_id: &'static str,
    profile_id: &'static str,
    profile_version: u32,
    details: BTreeMap<String, String>,
) -> EvaluationFixture {
    let module = resolve_profile(profile_id, profile_version).expect("compiled fixture profile");
    let profile = module.descriptor().profile.clone();
    let profile_digest = append_descriptor(store, module);
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
        detector_id,
        detector_version: 1,
        finding_id,
        profile,
        profile_refusal,
        refusal,
        profile_digest,
        detector_digest: digest(detector_id),
    }
}

#[allow(clippy::too_many_lines)]
fn commit_present_then_cannot_evaluate(store: &mut Store, fixture: &EvaluationFixture) {
    let module = resolve_profile(&fixture.profile.id, fixture.profile.version)
        .expect("compiled fixture profile");
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
    let present = EvaluationResultV1 {
        schema: EvaluationResultSchema::V1,
        profile: evaluation_profile.clone(),
        state: DetectorState::Present,
        condition: "transport.same_code".to_owned(),
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
        subject: document(&json!({"instance": fixture.instance_id})),
        condition_name: present.condition.clone(),
        condition_state: "present".to_owned(),
        visibility_state: "sufficient".to_owned(),
        operator_work_state: "unreviewed".to_owned(),
        severity: "warning".to_owned(),
        summary: present.summary.clone(),
        limitations: document(&present.limitations),
        safe_next_checks: document(&vec!["collect sufficient current evidence"]),
        freshness: document(&json!({"state": "current"})),
        basis: document(&json!({
            "profile_id": fixture.profile.id,
            "profile_version": fixture.profile.version,
            "profile_digest": fixture.profile_digest,
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
    let receipt = store
        .commit_evaluation(
            &EvaluationInput {
                evaluation_id: present_id.clone(),
                detector_id: fixture.detector_id.to_owned(),
                detector_version: fixture.detector_version.to_string(),
                detector_digest: fixture.detector_digest.clone(),
                evaluator_artifact_digest: digest("evaluation-refusal-surface-evaluator"),
                started_at: TEST_TIME.to_owned(),
                evaluated_at: TEST_TIME.to_owned(),
                outcome: "condition_present".to_owned(),
                detail: document(&present),
                profile: store_profile.clone(),
                watermarks: watermarks.clone(),
                refusal: None,
            },
            Some(&opened),
        )
        .expect("commit policy-valid present finding");
    assert_eq!(receipt.evaluation_id, present_id);
    assert_eq!(receipt.evaluation_revision, 1);

    let refused = EvaluationResultV1 {
        schema: EvaluationResultSchema::V1,
        profile: evaluation_profile,
        state: DetectorState::CannotEvaluate,
        condition: "transport.same_code".to_owned(),
        summary: fixture.profile_refusal.message.clone(),
        evidence: Vec::new(),
        limitations: vec!["evaluation refused at a typed profile boundary".to_owned()],
        refusal: Some(fixture.refusal.clone()),
        watermark: EvidenceWatermark(0),
    };
    let mut updated = opened;
    updated.event_id = format!("event-{}-refused", fixture.finding_id);
    "updated".clone_into(&mut updated.event_kind);
    "refused".clone_into(&mut updated.visibility_state);
    updated.limitations = document(&refused.limitations);
    updated.freshness = document(&json!({"state": "cannot_evaluate"}));
    updated.refusal = Some(document(&fixture.refusal));

    let refused_id = format!("evaluation-{}-refused", fixture.finding_id);
    let receipt = store
        .commit_evaluation(
            &EvaluationInput {
                evaluation_id: refused_id.clone(),
                detector_id: fixture.detector_id.to_owned(),
                detector_version: fixture.detector_version.to_string(),
                detector_digest: fixture.detector_digest.clone(),
                evaluator_artifact_digest: digest("evaluation-refusal-surface-evaluator"),
                started_at: TEST_TIME.to_owned(),
                evaluated_at: TEST_TIME.to_owned(),
                outcome: "cannot_evaluate".to_owned(),
                detail: document(&refused),
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
            Some(&updated),
        )
        .expect("commit typed cannot-evaluate update");
    assert_eq!(receipt.evaluation_id, refused_id);
    assert_eq!(receipt.evaluation_revision, 2);
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
        assert_eq!(finding.condition.name, "transport.same_code");
        assert_eq!(finding.condition.state, ConditionState::Present);
        assert_eq!(finding.visibility.state, VisibilityState::Refused);

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
    assert_ne!(
        profiles[0].profile_semantic_id,
        profiles[1].profile_semantic_id
    );
    assert_ne!(profiles[0].refusal.profile, profiles[1].refusal.profile);
    assert_ne!(profiles[0].refusal.details, profiles[1].refusal.details);
    assert_ne!(reopened[0].refusal_id, reopened[1].refusal_id);
    assert_ne!(reopened[0], reopened[1]);
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
            "evaluation-conformance",
            "transport.detector.conformance",
            "finding-evaluation-conformance",
            "refusal-evaluation-conformance",
            "nq.conformance",
            1,
            BTreeMap::from([
                ("coverage".to_owned(), "reachability".to_owned()),
                ("missing_basis".to_owned(), "active_probe".to_owned()),
            ]),
        ),
        fixture(
            &mut store,
            "evaluation-host",
            "transport.detector.host",
            "finding-evaluation-host",
            "refusal-evaluation-host",
            "nq.host",
            1,
            BTreeMap::from([
                ("age_seconds".to_owned(), "121".to_owned()),
                ("reliance_seconds".to_owned(), "60".to_owned()),
            ]),
        ),
    ];
    for fixture in &fixtures {
        commit_present_then_cannot_evaluate(&mut store, fixture);
    }
    store.validate().expect("committed store validates");
    assert_exact_pair(
        &nq_core::engine::list_findings(&store).expect("read committed public findings"),
        &fixtures,
    );

    drop(store);
    let reopened = Store::open(&database).expect("reopen committed store");
    assert_exact_pair(
        &nq_core::engine::list_findings(&reopened).expect("read reopened public findings"),
        &fixtures,
    );

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
    drop(backup_store);

    let live_cli = success(run(nq, &config, &["findings", "export"]));
    assert_exact_pair(&findings_from_value(live_cli.clone()), &fixtures);

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
    assert_eq!(verification["historical_status_events_verified"], 0);
    assert_eq!(
        verification["historical_rejected_custody_records_verified"],
        0
    );
    assert_eq!(
        verification["historical_evaluation_refusal_semantics_verified"],
        true
    );
    assert_eq!(verification["historical_evaluation_records_verified"], 4);
    assert_eq!(verification["grants_authority"], false);

    let archived_database = archive.join("db/nq.db");
    let archived_store =
        Store::open_immutable(&archived_database).expect("reopen archived database immutably");
    assert_exact_pair(
        &nq_core::engine::list_findings(&archived_store).expect("read archived public findings"),
        &fixtures,
    );
    drop(archived_store);

    let reopen_root = root.join("archive-reopen");
    fs::create_dir(&reopen_root).expect("create archive reopen directory");
    let archived_config = write_config(&reopen_root, "archived", &archived_database);
    let archived_cli = success(run(&archived_nq, &archived_config, &["findings", "export"]));
    assert_eq!(archived_cli, live_cli);
    assert_exact_pair(&findings_from_value(archived_cli), &fixtures);
}
