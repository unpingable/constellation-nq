//! Policy admission and observation through shipped CLI/startup surfaces.

use nq_protocol::sha256_bytes;
use serde_json::{Value, json};
use std::fs;
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

fn config(root: &Path, pin: Option<&str>) -> String {
    let binding = pin.map_or_else(String::new, |digest| {
        format!(
            r#"
[escalation_policy]
path = "{}/policy.json"
sha256 = "{digest}"
"#,
            root.display()
        )
    });
    format!(
        r#"schema = "nq.config.v1"
database_path = "{0}/absent.db"
socket_path = "{0}/absent.sock"
admissions_dir = "{0}/absent-admissions"
helper_runtime_dir = "{0}/absent-helpers"
{binding}
[[notification_routes]]
reference = "pagerduty-ops"
transport = "pagerduty"
routing_key_env = "NQ_FIXTURE_ROUTING_KEY"
max_response_bytes = 4096
"#,
        root.display()
    )
}

fn example() -> Value {
    let bytes = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/escalation-policy.example.json"),
    )
    .unwrap();
    let mut document: Value = serde_json::from_slice(&bytes).unwrap();
    let pagerduty = document["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["reference"] == "pagerduty-ops")
        .unwrap()
        .clone();
    document["routes"] = json!([pagerduty]);
    document
}

#[test]
fn inspect_policy_check_registry_and_removal_need_no_database() {
    let root = tempfile::tempdir().unwrap();
    let active = root.path().join("nq.toml");
    fs::write(&active, config(root.path(), None)).unwrap();
    let missing = success(&run(&active, &["notification", "policy"]));
    assert_eq!(missing["source"], "missing");
    assert!(missing.get("policy").is_none());
    let mut document = example();
    let anchor = json!({"rule":"remediation-journal-critical", "components":["service"], "response_classes":["page"]});
    document["anchors"]
        .as_array_mut()
        .unwrap()
        .push(anchor.clone());
    document["routes"][0]["anchors"]
        .as_array_mut()
        .unwrap()
        .push(json!("remediation-journal-critical"));
    let mirror = root.path().join("registry.json");
    fs::write(
        &mirror,
        serde_json::to_vec(&json!({"schema":"nq.escalation_registry.v1", "anchors":[anchor]}))
            .unwrap(),
    )
    .unwrap();
    let registry_args = [
        "notification",
        "policy",
        "--check-registry",
        mirror.to_str().unwrap(),
    ];
    for args in [&registry_args[..], &["config", "check"]] {
        let failure = run(&active, args);
        assert!(!failure.status.success());
        let error = String::from_utf8_lossy(&failure.stderr);
        assert!(
            error.contains("missing escalation policy document"),
            "{error}"
        );
    }
    let bytes = serde_json::to_vec_pretty(&document).unwrap();
    let digest = sha256_bytes(&bytes);
    fs::write(root.path().join("policy.json"), bytes).unwrap();
    let candidate = root.path().join("candidate.toml");
    fs::write(&candidate, config(root.path(), Some(digest.as_str()))).unwrap();
    // An instance without a document can preview and activate its first pin.
    success(&run(
        &active,
        &["config", "diff", candidate.to_str().unwrap()],
    ));
    success(&run(
        &active,
        &["config", "apply", candidate.to_str().unwrap()],
    ));
    let installed = success(&run(&active, &registry_args));
    assert_eq!(installed["source"], "installed");
    assert_eq!(installed["digest"], digest.as_str());
    assert_eq!(installed["policy"], document);
    success(&run(&active, &["config", "check"]));
    fs::remove_file(root.path().join("policy.json")).unwrap();
    assert!(!run(&active, &["notification", "policy"]).status.success());
    fs::write(&active, config(root.path(), None)).unwrap();
    assert_eq!(success(&run(&active, &["notification", "policy"])), missing);
    for path in [
        "absent.db",
        "absent.sock",
        "absent-admissions",
        "absent-helpers",
    ] {
        assert!(!root.path().join(path).exists(), "read created {path}");
    }
}

#[test]
fn invalid_pinned_policy_stops_every_delivery_surface_before_effects() {
    let root = tempfile::tempdir().unwrap();
    let active = root.path().join("nq.toml");
    fs::write(&active, config(root.path(), None)).unwrap();
    let valid = example();
    for invalid in ["digest", "oversize", "enum"] {
        let mut document = valid.clone();
        document["routes"][0]["handler"]["kind"] = json!("unsupported");
        let bytes = match invalid {
            "oversize" => vec![b' '; 131_073],
            "enum" => serde_json::to_vec(&document).unwrap(),
            _ => serde_json::to_vec(&valid).unwrap(),
        };
        let digest = if invalid == "digest" {
            sha256_bytes(b"other policy")
        } else {
            sha256_bytes(&bytes)
        };
        fs::write(root.path().join("policy.json"), bytes).unwrap();
        fs::write(&active, config(root.path(), Some(digest.as_str()))).unwrap();
        for args in [
            vec!["config", "check"],
            vec!["notification", "policy"],
            vec![
                "notification",
                "submit",
                "--intent",
                "/absent-intent",
                "--route",
                "pagerduty-ops",
                "--enable-network",
            ],
            vec![
                "notification",
                "resubmit",
                "--notification-id",
                "absent",
                "--stable-event-id",
                "new",
                "--enable-network",
            ],
            vec![
                "notification",
                "deliver-local",
                "--intent",
                "/absent-intent",
                "--route",
                "pagerduty-ops",
            ],
        ] {
            let output = run(&active, &args);
            assert!(!output.status.success(), "{invalid} {args:?}");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("escalation policy"),
                "{invalid} {args:?}: {error}"
            );
        }
        for path in [
            "absent.db",
            "absent.sock",
            "absent-admissions",
            "absent-helpers",
        ] {
            assert!(!root.path().join(path).exists(), "failure created {path}");
        }
    }
}

#[test]
fn config_apply_cannot_activate_a_bad_pin_and_binding_is_strict() {
    let root = tempfile::tempdir().unwrap();
    let active = root.path().join("nq.toml");
    let original = config(root.path(), None);
    fs::write(&active, &original).unwrap();
    let candidate = root.path().join("candidate.toml");
    fs::write(
        &candidate,
        config(root.path(), Some(sha256_bytes(b"uninstalled").as_str())),
    )
    .unwrap();
    for command in ["diff", "apply"] {
        assert!(
            !run(&active, &["config", command, candidate.to_str().unwrap()])
                .status
                .success()
        );
        assert_eq!(fs::read_to_string(&active).unwrap(), original);
    }
    for binding in [
        "[escalation_policy]\npath = \"/tmp/policy\"\n",
        "[escalation_policy]\npath = \"relative\"\nsha256 = \"invalid\"\n",
        "[escalation_policy]\npath = \"/tmp/policy\"\nsha256 = \"invalid\"\n",
    ] {
        // A minimal route-free config isolates configuration shape validation.
        let basic = format!(
            "schema = \"nq.config.v1\"\ndatabase_path = \"/tmp/absent.db\"\nadmissions_dir = \"/tmp/absent-admissions\"\n{binding}"
        );
        fs::write(&candidate, basic).unwrap();
        assert!(!run(&candidate, &["config", "check"]).status.success());
    }
}

#[test]
fn broken_policy_does_not_stop_observation_but_refuses_notification_admission() {
    let root = tempfile::tempdir().unwrap();
    let active = root.path().join("nq.toml");
    // Observation must also survive invalid approval metadata, not just bad JSON.
    for broken in ["unconfigured", "missing", "malformed", "pin", "relative"] {
        let bytes = b"{broken JSON";
        fs::write(root.path().join("policy.json"), bytes).unwrap();
        let digest = if broken == "pin" {
            "invalid".to_owned()
        } else {
            sha256_bytes(bytes).into_string()
        };
        let mut configuration = config(
            root.path(),
            if broken == "unconfigured" {
                None
            } else {
                Some(&digest)
            },
        );
        if broken == "missing" {
            fs::remove_file(root.path().join("policy.json")).unwrap();
        } else if broken == "relative" {
            configuration = configuration.replace(
                &format!("{}/policy.json", root.path().display()),
                "relative.json",
            );
        }
        fs::write(&active, configuration).unwrap();
        if broken == "unconfigured" {
            let initialized = success(&run(&active, &["init"]));
            assert_eq!(initialized["escalation_policy"]["state"], "missing");
        }
        let doctor = success(&run(&active, &["doctor"]));
        assert_eq!(
            doctor["escalation_policy"]["state"],
            if broken == "unconfigured" {
                "missing"
            } else {
                "failed"
            },
            "{broken}"
        );
        let daemon = Command::new(env!("CARGO_BIN_EXE_nqd"))
            .args(["--config", active.to_str().unwrap(), "--once"])
            .output()
            .unwrap();
        assert!(
            daemon.status.success(),
            "{broken}: {}",
            String::from_utf8_lossy(&daemon.stderr)
        );
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&daemon.stdout),
            String::from_utf8_lossy(&daemon.stderr)
        );
        assert!(log.contains("observation continues"), "{broken}: {log}");
        let output = run(
            &active,
            &[
                "notification",
                "submit",
                "--intent",
                "/absent-intent",
                "--route",
                "pagerduty-ops",
            ],
        );
        assert!(!output.status.success(), "{broken}");
        if broken != "unconfigured" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("escalation policy"));
        }
        assert!(!run(&active, &["config", "check"]).status.success());
    }
}
