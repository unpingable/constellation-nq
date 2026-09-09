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
    let (source, held_request) = held::inputs();
    let backup = json!({"device":2,"inode":3,"bytes":4096,"uid":1000,"gid":1000,"mode":384,"sha256":"d".repeat(64)});
    let mut restore = backup.clone();
    restore["inode"] = json!(4);
    let copy = |path: &str, identity: &Value| {
        json!({"state":"OBSERVED","value":{
        "path":path,"identity":identity,"verification_sha256":"b".repeat(64),"integrity":"ok","application_schema":23}})
    };
    let envelope = json!({"schema":"labelwatch.sqlite-cleanup-observation/v1", "source_owner":"Labelwatch read-only observer",
        "started_at":"2026-09-08T00:00:00Z", "completed_at":"2026-09-08T00:00:02Z", "held_source":source,
        "backup":copy("/backup/backup.sqlite", &backup),"restore":copy("/backup/restore.sqlite", &restore),
        "unknowns":[],"limitations":["policy fixture, not actual filesystem observation"]});
    let request = serde_json::from_value(json!({"schema":"nq.labelwatch-cleanup-request/v1", "held_request":held_request,
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
    request.held_request.evaluated_at = "2026-09-08T00:01:00Z".parse().unwrap();
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
