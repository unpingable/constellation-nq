//! Native condition-bearing local pages under an explicit operator policy.

use nq_protocol::sha256_bytes;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn run(config: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nq"))
        .arg("--config")
        .arg(config)
        .arg("--json")
        .args(arguments)
        .output()
        .unwrap()
}

fn success(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn policy() -> Value {
    json!({
        "schema":"nq.escalation_policy.v1",
        "anchors":[
            {"rule":"service-down", "components":["service"], "response_classes":["page"]},
            {"rule":"other-rule", "components":["service"], "response_classes":["page"]}
        ],
        "routes":[{
            "reference":"local-pages", "anchors":["service-down"],
            "response_classes":["page"],
            "handler":{"kind":"local_file", "max_message_bytes":4096}
        }]
    })
}

fn prepare(root: &Path, policy: Option<&Value>) -> std::path::PathBuf {
    fs::create_dir(root.join("inbox")).unwrap();
    fs::set_permissions(root.join("inbox"), fs::Permissions::from_mode(0o711)).unwrap();
    let binding = policy.map_or_else(String::new, |document| {
        let bytes = serde_json::to_vec(document).unwrap();
        fs::write(root.join("policy.json"), &bytes).unwrap();
        format!(
            "[escalation_policy]\npath = \"{}/policy.json\"\nsha256 = \"{}\"\n",
            root.display(),
            sha256_bytes(&bytes)
        )
    });
    let config = root.join("nq.toml");
    fs::write(
        &config,
        format!(
            r#"schema = "nq.config.v1"
database_path = "{0}/notification.db"
socket_path = "{0}/nqd.sock"
admissions_dir = "{0}/admissions"
helper_runtime_dir = "{0}/helpers"
{binding}
[[notification_routes]]
reference = "local-pages"
transport = "local_file"
local_inbox_directory = "{0}/inbox"
"#,
            root.display()
        ),
    )
    .unwrap();
    success(&run(&config, &["init"]));
    config
}

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/notifications/condition-page-v2.json"
    ))
    .unwrap()
}

fn deliver(root: &Path, config: &Path, intent: &Value) -> Output {
    let path = root.join("intent.json");
    fs::write(&path, serde_json::to_vec(intent).unwrap()).unwrap();
    run(
        config,
        &[
            "notification",
            "deliver-local",
            "--intent",
            path.to_str().unwrap(),
            "--route",
            "local-pages",
        ],
    )
}

#[test]
fn condition_v2_local_trigger_resolve_and_registry_use_the_same_authority() {
    let root = tempfile::tempdir().unwrap();
    let config = prepare(root.path(), Some(&policy()));
    let registry = root.path().join("registry.json");
    fs::write(
        &registry,
        serde_json::to_vec(&json!({
            "schema":"nq.escalation_registry.v1",
            "anchors":[{"rule":"service-down", "components":["service"], "response_classes":["page"]}]
        }))
        .unwrap(),
    )
    .unwrap();
    success(&run(
        &config,
        &[
            "notification",
            "policy",
            "--check-registry",
            registry.to_str().unwrap(),
            "--route",
            "local-pages",
        ],
    ));
    let mut intent = vector();
    for action in ["trigger", "resolve"] {
        intent["action"] = json!(action);
        intent["stable_event_id"] = json!(format!("condition-page-{action}"));
        intent["transition_id"] = intent["stable_event_id"].clone();
        let first = success(&deliver(root.path(), &config, &intent));
        assert_eq!(first["delivery_state"], "accepted");
        assert_eq!(first["human_receipt"], "not_established");
        assert!(first.get("dedup_key").is_none());
        let id = first["notification_id"].as_str().unwrap();
        let message: Value = serde_json::from_slice(
            &fs::read(root.path().join("inbox").join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(message["schema"], "nq.local-inbox-message/v2");
        assert_eq!(
            message["condition"],
            json!({
                "site":"page-qualification", "component":"service",
                "rule":"service-down", "target_class":"nginx"
            })
        );
        assert_eq!(message["action"], action);
        assert_eq!(message["response_class"], "page");
        let duplicate = success(&deliver(root.path(), &config, &intent));
        assert_eq!(duplicate["notification_id"], id);
        assert_eq!(duplicate["delivery_state"], "accepted");
        let inspected = success(&run(
            &config,
            &["notification", "inspect", "--notification-id", id],
        ));
        assert_eq!(inspected[0]["condition_delivery"]["action"], action);
        assert_eq!(
            inspected[0]["condition_delivery"]["condition"],
            message["condition"]
        );
        assert!(inspected[0].get("pagerduty").is_none());
        let refused = run(
            &config,
            &[
                "notification",
                "resubmit",
                "--notification-id",
                id,
                "--stable-event-id",
                "unsafe-local-retry",
            ],
        );
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("resubmit is defined only"));
    }
    assert_eq!(fs::read_dir(root.path().join("inbox")).unwrap().count(), 2);
}

#[test]
fn condition_v2_local_denies_unauthorized_tuples_before_custody_or_file_effects() {
    for case in [
        "rule",
        "component",
        "route-anchor",
        "route-class",
        "anchor-class",
        "destination",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut policy = policy();
        let mut intent = vector();
        match case {
            "rule" => intent["condition"]["rule"] = json!("unlisted-rule"),
            "component" => intent["condition"]["component"] = json!("docket"),
            "route-anchor" => intent["condition"]["rule"] = json!("other-rule"),
            "route-class" => policy["routes"][0]["response_classes"] = json!(["attention"]),
            "anchor-class" => policy["anchors"][0]["response_classes"] = json!(["attention"]),
            "destination" => intent["destination_identity"] = json!("local-inbox:another-route"),
            _ => unreachable!(),
        }
        let config = prepare(root.path(), Some(&policy));
        let denied = deliver(root.path(), &config, &intent);
        assert!(!denied.status.success(), "{case}");
        assert_eq!(
            fs::read_dir(root.path().join("inbox")).unwrap().count(),
            0,
            "{case}"
        );
        assert_eq!(
            success(&run(&config, &["notification", "inspect"])),
            json!([]),
            "{case}"
        );
    }
}

#[test]
fn condition_v2_local_missing_policy_retains_refusal_without_a_message() {
    let root = tempfile::tempdir().unwrap();
    let config = prepare(root.path(), None);
    let result = success(&deliver(root.path(), &config, &vector()));
    assert_eq!(result["delivery_state"], "refused");
    assert_eq!(fs::read_dir(root.path().join("inbox")).unwrap().count(), 0);
    let inspected = success(&run(&config, &["notification", "inspect"]));
    assert_eq!(
        inspected[0]["condition_delivery"]["last_event"]["detail"]["reason"],
        "escalation_policy_missing"
    );
}

#[test]
fn condition_v2_local_non_page_classes_stay_retained_refusals() {
    for class in [None, Some("attention"), Some("informational")] {
        let root = tempfile::tempdir().unwrap();
        let config = prepare(root.path(), Some(&policy()));
        let mut intent = vector();
        match class {
            Some(class) => intent["response_class"] = json!(class),
            None => {
                intent.as_object_mut().unwrap().remove("response_class");
            }
        }
        let result = success(&deliver(root.path(), &config, &intent));
        assert_eq!(result["delivery_state"], "refused");
        assert_eq!(fs::read_dir(root.path().join("inbox")).unwrap().count(), 0);
        let inspected = success(&run(&config, &["notification", "inspect"]));
        assert_eq!(
            inspected[0]["condition_delivery"]["last_event"]["detail"]["reason"],
            "response_class_not_page"
        );
    }
}

#[test]
fn condition_v2_local_render_bound_precedes_custody() {
    let root = tempfile::tempdir().unwrap();
    let config = prepare(root.path(), Some(&policy()));
    let mut intent = vector();
    intent["summary"] = json!("\"".repeat(1024));
    intent["inspection_reference"] = json!("\"".repeat(1024));
    let result = deliver(root.path(), &config, &intent);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("local inbox message exceeds"));
    assert_eq!(fs::read_dir(root.path().join("inbox")).unwrap().count(), 0);
    assert_eq!(
        success(&run(&config, &["notification", "inspect"])),
        json!([])
    );
}

#[test]
fn legacy_v1_local_page_keeps_its_existing_message_shape() {
    let root = tempfile::tempdir().unwrap();
    let config = prepare(root.path(), Some(&policy()));
    let mut intent = vector();
    intent["schema"] = json!("nq.notification_delivery_intent.v1");
    for field in ["action", "condition", "severity"] {
        intent.as_object_mut().unwrap().remove(field);
    }
    let result = success(&deliver(root.path(), &config, &intent));
    assert_eq!(result["delivery_state"], "accepted");
    let message: Value = serde_json::from_slice(
        &fs::read(root.path().join("inbox").join(format!(
            "{}.json",
            result["notification_id"].as_str().unwrap()
        )))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(message["schema"], "nq.local-inbox-message/v1");
    assert_eq!(message.as_object().unwrap().len(), 8);
    assert!(message.get("condition").is_none());
    assert_eq!(
        message["summary"],
        "[page] TEST: authorized condition page projection"
    );
}

#[test]
fn discord_v2_rendered_boundary_is_a_native_precustody_refusal() {
    for (supplementary, units, inspection_chars, accepted) in [
        (false, 2000, 885, true),
        (false, 2001, 886, false),
        (true, 2000, 887, true),
        (true, 2001, 888, false),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut policy = policy();
        policy["routes"][0]["reference"] = json!("discord-pages");
        policy["routes"][0]["handler"] =
            json!({"kind":"discord", "timeout_ms":10000, "max_response_bytes":4096});
        let bytes = serde_json::to_vec(&policy).unwrap();
        fs::write(root.path().join("policy.json"), &bytes).unwrap();
        let config = root.path().join("nq.toml");
        fs::write(
            &config,
            format!(
                r#"schema = "nq.config.v1"
database_path = "{0}/notification.db"
socket_path = "{0}/nqd.sock"
admissions_dir = "{0}/admissions"
helper_runtime_dir = "{0}/helpers"
[escalation_policy]
path = "{0}/policy.json"
sha256 = "{1}"
[[notification_routes]]
reference = "discord-pages"
transport = "discord"
endpoint_secret_locator = "NQ_QUALIFICATION_UNUSED_DISCORD_URL"
timeout_ms = 10000
max_response_bytes = 4096
"#,
                root.path().display(),
                sha256_bytes(&bytes)
            ),
        )
        .unwrap();
        success(&run(&config, &["init"]));
        let summary = if supplementary {
            format!("{}😀", "s".repeat(1020))
        } else {
            "s".repeat(1024)
        };
        let inspection = format!("https://{}", "i".repeat(inspection_chars - 8));
        let expected = format!(
            "[page] TRIGGER page-qualification:service:service-down:nginx\nAttention required: {summary}\nInspect: {inspection}"
        );
        assert_eq!(expected.encode_utf16().count(), units);
        assert_eq!(expected.chars().count(), units - usize::from(supplementary));
        let mut intent = vector();
        intent["summary"] = json!(summary);
        intent["inspection_reference"] = json!(inspection);
        intent["route_reference"] = json!("discord-pages");
        intent["destination_identity"] = json!("discord:discord-pages");
        let path = root.path().join("intent.json");
        fs::write(&path, serde_json::to_vec(&intent).unwrap()).unwrap();
        // No network enablement or endpoint value: this exercises the real CLI
        // up to its retained dispatch refusal without contacting a destination.
        let result = run(
            &config,
            &[
                "notification",
                "submit",
                "--intent",
                path.to_str().unwrap(),
                "--route",
                "discord-pages",
            ],
        );
        if accepted {
            assert_eq!(success(&result)["delivery_state"], "refused");
            let inspected = success(&run(&config, &["notification", "inspect"]));
            assert_eq!(
                inspected[0]["condition_delivery"]["last_event"]["detail"]["reason"],
                "network_dispatch_not_explicitly_enabled"
            );
            let connection =
                rusqlite::Connection::open(root.path().join("notification.db")).unwrap();
            let payload: Vec<u8> = connection
                .query_row("SELECT payload_json FROM notification_outbox", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let payload: Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(payload["content"], expected);
            let retained: Vec<u8> = connection
                .query_row(
                    "SELECT intent_json FROM notification_delivery_intents",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&retained).unwrap(), intent);
        } else {
            assert!(!result.status.success());
            assert!(
                String::from_utf8_lossy(&result.stderr)
                    .contains("discord_content_exceeds_2000_utf16_units")
            );
            assert_eq!(
                success(&run(&config, &["notification", "inspect"])),
                json!([])
            );
        }
    }
}
