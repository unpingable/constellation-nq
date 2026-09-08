use nq_core::fixed_queue::{admit, digest, replay, support};
use serde_json::{Value, json};

fn fixture() -> (Value, Value) {
    let cat: Value = serde_json::from_str(include_str!(
        "../../../fixtures/bounded-predicate/queue-profile.json"
    ))
    .unwrap();
    let p = &cat["profiles"][0];
    let inventory = json!({"schema":"monitor.project-observation.inventory/v1","project":p["subject"]["project"],"acquisition":{"disposition":"ACQUIRED_AND_VALIDATED","exit_code":0,"stdout_bytes":1,"binding_schema":"project.observation-binding/v1","repository_revision_is_deployment_provenance":false,"producer":p["accepted_producers"][0],"manifest_digest":p["accepted_manifest_digests"][0],"status_digest":format!("sha256:{}","a".repeat(64))},"validation_issues":[],"concerns":[{"declaration":{"id":p["subject"]["concern"],"question":p["question"],"profile":p["declaration_profile"]},"monitor_state":"OBSERVED","observation":{"observation_present":true,"observed_at":"2026-09-08T12:00:00Z","valid_for_seconds":300,"facts":{"queue":{"depth":12}}}}]});
    let mut inventory = inventory;
    inventory["repository"] = json!("/fixture/sprocket");
    inventory["acquisition"]["acquired_at_unix_ms"] = json!(1788868800000_u64);
    inventory["acquisition"]["stderr_bytes"] = json!(0);
    inventory["concerns"][0]["declaration"]["required"] = json!(true);
    inventory["concerns"][0]["declaration"]["description"] = json!("bounded queue");
    inventory["concerns"][0]["observation"]["local_state"] = json!("PRESENT");
    inventory["concerns"][0]["observation"]["reason"] = json!("fixture");
    (inventory, cat)
}

#[test]
fn fixed_queue_positive_false_replay_and_mutation() {
    let (i, c) = fixture();
    let concern = c["profiles"][0]["subject"]["concern"].as_str().unwrap();
    let r = admit(
        &i,
        &c,
        &digest(&c).unwrap(),
        concern,
        "2026-09-08T12:01:00Z",
    )
    .unwrap();
    assert_eq!(r["semantic_conclusion"], true);
    assert!(replay(&r, &i, &c).unwrap());
    assert_eq!(
        support(&r, &i, &c, &json!({"queue":{"depth":18}})).unwrap()["semantic_conclusion"],
        false
    );
    assert!(support(&r, &i, &c, &json!({"queue":{}})).is_err());
    let mut changed = i.clone();
    changed["concerns"][0]["observation"]["facts"]["queue"]["depth"] = json!(13);
    assert!(!replay(&r, &changed, &c).unwrap());
    let mut forged = r.clone();
    forged["semantic_conclusion"] = json!(false);
    assert!(!replay(&forged, &i, &c).unwrap());
}

#[test]
fn fixed_queue_refusal_boundaries() {
    let (i, c) = fixture();
    let concern = c["profiles"][0]["subject"]["concern"].as_str().unwrap();
    for at in ["2026-09-08T11:59:59Z", "2026-09-08T12:05:00Z"] {
        assert!(admit(&i, &c, &digest(&c).unwrap(), concern, at).is_err());
    }
    for pointer in [
        "/acquisition/producer",
        "/acquisition/manifest_digest",
        "/acquisition/status_digest",
        "/acquisition/binding_schema",
        "/concerns/0/declaration/question",
        "/concerns/0/observation/facts/queue/depth",
    ] {
        let mut changed = i.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("wrong");
        assert!(
            admit(
                &changed,
                &c,
                &digest(&c).unwrap(),
                concern,
                "2026-09-08T12:01:00Z"
            )
            .is_err(),
            "{pointer}"
        );
    }
    let mut changed = c.clone();
    changed["profiles"][0]["predicate"]["value"]["value"] = json!(19);
    assert!(
        admit(
            &i,
            &changed,
            &digest(&changed).unwrap(),
            concern,
            "2026-09-08T12:01:00Z"
        )
        .is_err()
    );
}

#[test]
fn fixed_queue_all_preserved_cohort_forms() {
    let catalog: Value = serde_json::from_str(include_str!(
        "../../../fixtures/bounded-predicate/specimen-profiles.json"
    ))
    .unwrap();
    for p in catalog["profiles"].as_array().unwrap() {
        let (mut i, _) = fixture();
        i["project"] = p["subject"]["project"].clone();
        i["acquisition"]["producer"] = p["accepted_producers"][0].clone();
        i["acquisition"]["manifest_digest"] = p["accepted_manifest_digests"][0].clone();
        i["concerns"][0]["declaration"] = json!({"id":p["subject"]["concern"],"question":p["question"],"profile":p["declaration_profile"]});
        i["concerns"][0]["declaration"]["required"] = json!(true);
        i["concerns"][0]["declaration"]["description"] = json!("bounded cohort");
        i["concerns"][0]["observation"]["facts"] = json!({"exists":true,"readable":true,"write_transaction_available":true,"quick_check":"ok","write_transaction_acquired":true,"free_bytes":15032385536_u64,"freelist_count":5000000});
        let r = admit(
            &i,
            &catalog,
            &digest(&catalog).unwrap(),
            p["subject"]["concern"].as_str().unwrap(),
            "2026-09-08T12:01:00Z",
        )
        .unwrap();
        assert_eq!(r["semantic_conclusion"], true);
        assert!(replay(&r, &i, &catalog).unwrap());
    }
}

#[test]
fn entire_inventory_must_remain_well_formed() {
    let (i, c) = fixture();
    let concern = c["profiles"][0]["subject"]["concern"].as_str().unwrap();
    let rejects = |candidate: &Value| {
        assert!(
            admit(
                candidate,
                &c,
                &digest(&c).unwrap(),
                concern,
                "2026-09-08T12:01:00Z"
            )
            .is_err()
        );
    };
    let mut missing_repository = i.clone();
    missing_repository
        .as_object_mut()
        .unwrap()
        .remove("repository");
    rejects(&missing_repository);
    let mut empty_repository = i.clone();
    empty_repository["repository"] = json!("");
    rejects(&empty_repository);
    for state in ["OBSERVED", "unrecognized-state"] {
        let mut malformed = i.clone();
        malformed["concerns"].as_array_mut().unwrap().push(json!({
            "declaration":{"id":"unselected"},"monitor_state":state,"observation":null
        }));
        rejects(&malformed);
    }
    let mut duplicate = i.clone();
    let extra = json!({"declaration":{"id":"unselected"},"monitor_state":"MISSING_OPTIONAL_OBSERVATION","observation":null});
    duplicate["concerns"]
        .as_array_mut()
        .unwrap()
        .extend([extra.clone(), extra]);
    rejects(&duplicate);
    let mut inconsistent = i.clone();
    inconsistent["concerns"].as_array_mut().unwrap().push(json!({
        "declaration":{"id":"unselected"},"monitor_state":"MISSING_REQUIRED_OBSERVATION","observation":{}
    }));
    rejects(&inconsistent);
    for observation in [
        json!(false),
        json!("not an observation"),
        json!({}),
        json!({"observation_present":"true"}),
    ] {
        let mut malformed = i.clone();
        let mut row = i["concerns"][0].clone();
        row["declaration"]["id"] = json!("unselected");
        row["observation"] = observation;
        malformed["concerns"].as_array_mut().unwrap().push(row);
        rejects(&malformed);
    }
}
