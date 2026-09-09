use nq_core::labelwatch_relief::{Request, qualify, replay};
use serde_json::{Value, json};

fn fixture() -> (Value, Request) {
    let file = json!({"device":1,"inode":2,"bytes":4096,"uid":1000,"gid":1000,"mode":384,"sha256":"a".repeat(64)});
    let writers = json!({"main":{"active":true,"pid":10,"start_ticks":1},"discovery":{"active":true,"pid":11,"start_ticks":2}});
    let s = json!({"schema":"labelwatch.sqlite-relief-observation/v1","source_owner":"Labelwatch read-only observer",
        "operation":"fixture", "source":"/fixture/source.sqlite","original":"/fixture/original.sqlite",
        "application_revision":"a".repeat(40),"started_at":"2026-09-08T00:00:00Z","completed_at":"2026-09-08T00:00:01Z",
        "database":{"state":"OBSERVED","value":{"identity":file,"verification_sha256":"b".repeat(64),
            "matches_declared_cut":true,"application_schema":23,"integrity":"ok","progress_meta_sha256":"c".repeat(64)}},
        "filesystem":{"state":"OBSERVED","value":{"device":1,"free_bytes":100000}},
        "original_presence":{"state":"OBSERVED","value":{"present":true,"identity":file}},
        "write_hold":{"state":"OBSERVED","value":true},"writers":{"state":"OBSERVED","value":writers},
        "unknowns":[],"limitations":["explicitly labeled policy fixture, not an actual observation"]});
    let r = serde_json::from_value(json!({"schema":"nq.labelwatch-relief-request/v1","operation":"fixture",
        "source":"/fixture/source.sqlite","original":"/fixture/original.sqlite","application_revision":"a".repeat(40),
        "expected_cut_sha256":"b".repeat(64),"original_identity":file,"replacement_device":1,"replacement_inode":2,
        "writer_identities":{"main":{"pid":10,"start_ticks":1},"discovery":{"pid":11,"start_ticks":2}},
        "phase":"pre_ingest","required_free_bytes":50000,"evaluated_at":"2026-09-08T00:00:02Z",
        "maximum_age_seconds":30,"pre_ingest_qualification":null})).unwrap();
    (s, r)
}

fn run(s: &Value, r: &Request) -> Value {
    qualify(&serde_json::to_vec(s).unwrap(), r).unwrap()
}

#[test]
fn pre_ingest_then_post_release_requires_exact_qualified_predecessor() {
    let (mut s, mut r) = fixture();
    let before = run(&s, &r);
    assert_eq!(before["disposition"], "ESTABLISHED");
    replay(&before).unwrap();
    r.phase = nq_core::labelwatch_relief::Phase::PostRelease;
    r.pre_ingest_qualification = Some(before);
    r.evaluated_at = "2026-09-08T00:00:05Z".parse().unwrap();
    s["started_at"] = json!("2026-09-08T00:00:03Z");
    s["completed_at"] = json!("2026-09-08T00:00:04Z");
    s["original_presence"]["value"] =
        json!({"present":false,"scope":"enrolled original pathname, not whole filesystem"});
    s["write_hold"]["value"] = json!(false);
    let after = run(&s, &r);
    assert_eq!(after["disposition"], "ESTABLISHED");
    replay(&after).unwrap();
    r.pre_ingest_qualification = None;
    assert_eq!(run(&s, &r)["disposition"], "NOT_OBSERVABLE");
}

#[test]
fn changed_content_unknown_and_false_are_distinct() {
    let (mut s, r) = fixture();
    s["database"]["value"]["verification_sha256"] = json!("d".repeat(64));
    s["database"]["value"]["matches_declared_cut"] = json!(false);
    assert_eq!(run(&s, &r)["disposition"], "REFUTED");
    s["database"] = json!({"state":"NOT_OBSERVABLE","value":null});
    s["unknowns"] = json!([{"slot":"database","reason":"read failed"}]);
    assert_eq!(run(&s, &r)["disposition"], "NOT_OBSERVABLE");
    s["database"]["state"] = json!("OBSERVED");
    assert!(qualify(&serde_json::to_vec(&s).unwrap(), &r).is_err());
}

#[test]
fn stale_future_wrong_subject_duplicate_keys_and_replay_changes_refuse() {
    let (mut s, mut r) = fixture();
    r.evaluated_at = "2026-09-08T00:01:00Z".parse().unwrap();
    assert_eq!(run(&s, &r)["disposition"], "NOT_OBSERVABLE");
    r.evaluated_at = "2026-09-07T00:00:00Z".parse().unwrap();
    assert!(qualify(&serde_json::to_vec(&s).unwrap(), &r).is_err());
    let (_, r) = fixture();
    let raw = serde_json::to_string(&s).unwrap();
    let duplicated = raw.replacen('{', "{\"operation\":\"fixture\",", 1);
    assert!(qualify(duplicated.as_bytes(), &r).is_err());
    let mut receipt = run(&s, &r);
    receipt["claim"] = json!("action_authorized");
    assert!(replay(&receipt).is_err());
    s["source"] = json!("/another/source.sqlite");
    assert!(qualify(&serde_json::to_vec(&s).unwrap(), &r).is_err());
}
