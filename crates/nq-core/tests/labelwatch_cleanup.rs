use nq_core::labelwatch_cleanup::{Request, qualify, replay};
use serde_json::{Value, json};

// Reuse the exact earlier profile's meaningful fixture and controls. Its
// production implementation and original tests remain unchanged.
mod held {
    include!("labelwatch_relief.rs");
    pub fn inputs() -> (Value, Request) {
        fixture()
    }
}

fn fixture() -> (Value, Request) {
    let (source, mut held_request) = held::inputs();
    held_request.schema = "nq.labelwatch-held-acquisition-request/v1".into();
    let backup = json!({"device":2,"inode":3,"bytes":4096,"uid":1000,"gid":1000,"mode":384,"sha256":"d".repeat(64)});
    let mut restore = backup.clone();
    restore["inode"] = json!(4);
    let copy = |path: &str, identity: &Value| {
        json!({"state":"OBSERVED","value":{
        "path":path,"identity":identity,"verification_sha256":"b".repeat(64),"integrity":"ok","application_schema":23}})
    };
    let stamp = |path: &str, identity: Value| {
        let mut result = identity;
        result.as_object_mut().unwrap().remove("sha256");
        result["path"] = json!(path);
        result["mtime_ns"] = json!("100");
        result["ctime_ns"] = json!("100");
        result
    };
    let custody = json!({"state":"OBSERVED", "value":{"hold_sha256":"f".repeat(64),
        "files":{"source":stamp(&held_request.source, source["database"]["value"]["identity"].clone()),
            "original":stamp(&held_request.original, serde_json::to_value(&held_request.original_identity).unwrap()),
            "backup":stamp("/backup/backup.sqlite",backup.clone()),"restore":stamp("/backup/restore.sqlite",restore.clone())},
        "writers":source["writers"]["value"]}});
    let envelope = json!({"schema":"labelwatch.sqlite-cleanup-observation/v2", "source_owner":"Labelwatch read-only observer",
        "started_at":"2026-09-08T00:00:00Z", "completed_at":"2026-09-08T00:00:02Z", "held_source":source,
        "currentness_started_at":"2026-09-08T00:00:02Z","currentness_completed_at":"2026-09-08T00:00:02Z",
        "acquisition_budget_seconds":30,"acquisition_duration_ms":2000,"acquisition_exclusions":["enrolled policy fixture"],
        "opening_custody":custody,"final_custody":custody,
        "backup":copy("/backup/backup.sqlite", &backup),"restore":copy("/backup/restore.sqlite", &restore),
        "unknowns":[],"limitations":["policy fixture, not actual filesystem observation"]});
    let request = serde_json::from_value(json!({"schema":"nq.labelwatch-cleanup-request/v2", "held_request":held_request,
        "expected_hold_sha256":"f".repeat(64),"acquisition_budget_seconds":30,"maximum_currentness_age_seconds":30,
        "evaluated_at":"2026-09-08T00:00:02Z",
        "backup":"/backup/backup.sqlite", "restore":"/backup/restore.sqlite", "backup_identity":backup,"restore_identity":restore})).unwrap();
    (envelope, request)
}

#[test]
fn established_copies_replay_but_changed_contents_or_same_device_refute() {
    let (source, request) = fixture();
    let positive = qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap();
    assert_eq!(positive["disposition"], "ESTABLISHED");
    replay(&positive).unwrap();
    for field in ["backup", "restore"] {
        let mut changed = source.clone();
        changed[field]["value"]["verification_sha256"] = json!("e".repeat(64));
        assert_eq!(
            qualify(&serde_json::to_vec(&changed).unwrap(), &request).unwrap()["disposition"],
            "REFUTED"
        );
        changed = source.clone();
        changed[field]["value"]["identity"]["device"] = json!(1);
        assert_eq!(
            qualify(&serde_json::to_vec(&changed).unwrap(), &request).unwrap()["disposition"],
            "REFUTED"
        );
    }
}

#[test]
fn missing_copy_stale_and_structural_disagreement_remain_distinct() {
    let (mut source, mut request) = fixture();
    source["restore"] = json!({"state":"NOT_OBSERVABLE","value":null});
    source["unknowns"] = json!([{"slot":"restore","reason":"read unavailable"}]);
    assert_eq!(
        qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap()["disposition"],
        "NOT_OBSERVABLE"
    );
    source["unknowns"] = json!([]);
    assert!(qualify(&serde_json::to_vec(&source).unwrap(), &request).is_err());
    let (source, _) = fixture();
    request.evaluated_at = "2026-09-08T00:01:00Z".parse().unwrap();
    assert_eq!(
        qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap()["disposition"],
        "NOT_OBSERVABLE"
    );
    let (_, request) = fixture();
    let raw = serde_json::to_string(&source).unwrap();
    assert!(
        qualify(
            raw.replacen('{', "{\"schema\":\"duplicate\",", 1)
                .as_bytes(),
            &request
        )
        .is_err()
    );
    let mut receipt = qualify(raw.as_bytes(), &request).unwrap();
    receipt["claim"] = json!("cleanup_authorized");
    assert!(replay(&receipt).is_err());
}

#[test]
fn long_bounded_acquisition_needs_distinct_fresh_unchanged_custody() {
    let (mut source, mut request) = fixture();
    source["held_source"]["completed_at"] = json!("2026-09-08T00:01:00Z");
    source["completed_at"] = json!("2026-09-08T00:01:10Z");
    source["acquisition_budget_seconds"] = json!(180);
    source["acquisition_duration_ms"] = json!(70000);
    source["currentness_started_at"] = json!("2026-09-08T00:01:11Z");
    source["currentness_completed_at"] = json!("2026-09-08T00:01:12Z");
    request.held_request.maximum_age_seconds = 180;
    request.held_request.evaluated_at = "2026-09-08T00:01:10Z".parse().unwrap();
    request.acquisition_budget_seconds = 180;
    request.evaluated_at = "2026-09-08T00:01:12Z".parse().unwrap();
    let receipt = qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap();
    assert_eq!(receipt["disposition"], "ESTABLISHED");
    replay(&receipt).unwrap();
    let mut changed = source.clone();
    changed["final_custody"]["value"]["files"]["source"]["ctime_ns"] = json!("101");
    assert_eq!(
        qualify(&serde_json::to_vec(&changed).unwrap(), &request).unwrap()["disposition"],
        "REFUTED"
    );
    changed = source.clone();
    changed["final_custody"]["value"]["hold_sha256"] = json!("0".repeat(64));
    assert_eq!(
        qualify(&serde_json::to_vec(&changed).unwrap(), &request).unwrap()["disposition"],
        "REFUTED"
    );
    source["acquisition_duration_ms"] = json!(181000);
    assert_eq!(
        qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap()["disposition"],
        "NOT_OBSERVABLE"
    );
    let mut old_policy = request.held_request.clone();
    old_policy.schema = "nq.labelwatch-relief-request/v1".into();
    old_policy.maximum_age_seconds = 30;
    assert_eq!(
        nq_core::labelwatch_relief::qualify(
            &serde_json::to_vec(&source["held_source"]).unwrap(),
            &old_policy
        )
        .unwrap()["disposition"],
        "NOT_OBSERVABLE"
    );
}

#[test]
fn final_freshness_boundary_future_witness_and_writer_substitution_refuse() {
    let (source, mut request) = fixture();
    request.evaluated_at = "2026-09-08T00:00:31.999Z".parse().unwrap();
    assert_eq!(
        qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap()["disposition"],
        "ESTABLISHED"
    );
    request.evaluated_at = "2026-09-08T00:00:32Z".parse().unwrap();
    assert_eq!(
        qualify(&serde_json::to_vec(&source).unwrap(), &request).unwrap()["disposition"],
        "NOT_OBSERVABLE"
    );
    let (_, request) = fixture();
    let mut future = source.clone();
    future["currentness_started_at"] = json!("2026-09-08T00:00:03Z");
    future["currentness_completed_at"] = json!("2026-09-08T00:00:04Z");
    assert!(qualify(&serde_json::to_vec(&future).unwrap(), &request).is_err());
    for custody in ["opening_custody", "final_custody"] {
        for field in ["pid", "start_ticks"] {
            let mut changed = source.clone();
            changed[custody]["value"]["writers"]["main"][field] = json!(999);
            assert_eq!(
                qualify(&serde_json::to_vec(&changed).unwrap(), &request).unwrap()["disposition"],
                "REFUTED"
            );
        }
    }
}
