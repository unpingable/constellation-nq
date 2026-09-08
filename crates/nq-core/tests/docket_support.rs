use nq_core::docket_support::{Acquisition, Request, qualify, replay};
use nq_protocol::{semantic_digest, sha256_bytes};
use serde_json::{Value, json};

#[test]
#[ignore = "real Docket source stores/binary and native NQ binary required"]
fn real_docket_acquisition_and_closed_policy_controls() {
    let root = std::path::PathBuf::from(std::env::var("DOCKET_NQ_FIXTURE_ROOT").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NQ_DOCKET_OUTPUT").unwrap());
    std::fs::create_dir(&output).unwrap();
    let executable = std::env::var("DOCKET_BIN").unwrap();
    let executable_digest = sha256_bytes(&std::fs::read(&executable).unwrap()).to_string();
    let nq = std::env::var("NQ_DOCKET_BIN").unwrap();
    for state in ["prepared", "committed", "refused", "indeterminate"] {
        let directory = root.join(format!("retirement-{state}"));
        let source: Value =
            serde_json::from_slice(&std::fs::read(directory.join("source.json")).unwrap()).unwrap();
        let subject = source["identity"]["ref_continuity_subject"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("docket:attempt:{}", source["attempt"].as_str().unwrap()));
        let request = Request {
            attempt: source["attempt"].as_str().unwrap().into(),
            subject,
            consumer: "nightshift-readonly".into(),
            purpose: "continue_observing".into(),
            claim: "docket_attempt_settled".into(),
            evaluated_at: chrono::Utc::now(),
            continuity_support: None,
        };
        let path = output.join(format!("{state}-request.json"));
        std::fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
        let run = |digest: &str, state_path: &std::path::Path| {
            std::process::Command::new(&nq)
                .args([
                    "docket-purpose-support",
                    "--docket-binary",
                    &executable,
                    "--docket-sha256",
                    digest,
                    "--state",
                ])
                .arg(state_path)
                .arg("--request")
                .arg(&path)
                .output()
                .unwrap()
        };
        let result = run(&executable_digest, &directory);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let bytes = result.stdout.strip_suffix(b"\n").unwrap_or(&result.stdout);
        let receipt: Value = serde_json::from_slice(bytes).unwrap();
        replay(&receipt).unwrap();
        assert_eq!(
            receipt["decision"],
            if state == "committed" {
                "supported_readonly"
            } else {
                "claim_not_verified"
            }
        );
        std::fs::write(output.join(format!("{state}.json")), bytes).unwrap();
        assert!(
            !run(&sha256_bytes(b"wrong binary").to_string(), &directory)
                .status
                .success()
        );
        assert!(
            !run(&executable_digest, &directory.join("missing"))
                .status
                .success()
        );
        let r: Request = serde_json::from_value(receipt["request"].clone()).unwrap();
        let raw = receipt["source_record_utf8"].as_str().unwrap().as_bytes();
        let a: Acquisition = serde_json::from_value(receipt["acquisition"].clone()).unwrap();
        let mut wrong = r.clone();
        wrong.attempt = "different".into();
        assert!(qualify(raw, &wrong, Some(&a)).is_err());
        if state != "committed" {
            continue;
        }
        assert_eq!(
            qualify(raw, &r, None).unwrap()["decision"],
            "custody_basis_not_accepted"
        );
        wrong = r.clone();
        wrong.claim = "host_is_fine".into();
        assert_eq!(
            qualify(raw, &wrong, Some(&a)).unwrap()["decision"],
            "claim_not_authorized_for_consumer"
        );
        wrong = r.clone();
        wrong.purpose = "execute".into();
        assert_eq!(
            qualify(raw, &wrong, Some(&a)).unwrap()["decision"],
            "purpose_not_authorized"
        );
        wrong = r.clone();
        wrong.evaluated_at += chrono::Duration::seconds(900);
        assert_eq!(
            qualify(raw, &wrong, Some(&a)).unwrap()["decision"],
            "stale_evidence"
        );
        for purpose in ["wait", "request_evidence", "stop", "human_escalation"] {
            wrong = r.clone();
            wrong.purpose = purpose.into();
            let result = qualify(raw, &wrong, Some(&a)).unwrap();
            assert_eq!(result["decision"], "supported_readonly");
            std::fs::write(
                output.join(format!("{purpose}.json")),
                nq_protocol::canonical_json_bytes(&result).unwrap(),
            )
            .unwrap();
        }
        let source: Value = serde_json::from_slice(raw).unwrap();
        for (pointer, value, expected) in [
            (
                "/observation/residual_obligations",
                json!([{"obligation":"unresolved","kind":"verify","recorded_at_ms":30}]),
                "residual_obligations_unresolved",
            ),
            (
                "/execution/settlement",
                json!("indeterminate"),
                "contradiction_retained",
            ),
        ] {
            let mut changed = source.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let raw = serde_json::to_vec(&changed).unwrap();
            let mut changed_a = a.clone();
            changed_a.raw_digest = sha256_bytes(&raw);
            let result = qualify(&raw, &r, Some(&changed_a)).unwrap();
            assert_eq!(result["decision"], expected);
            std::fs::write(
                output.join(format!("{expected}.json")),
                nq_protocol::canonical_json_bytes(&result).unwrap(),
            )
            .unwrap();
        }
        let mut changed = source.clone();
        changed["identity"]["settlement_premises"] = json!([""]);
        let malformed = serde_json::to_vec(&changed).unwrap();
        let mut changed_a = a.clone();
        changed_a.raw_digest = sha256_bytes(&malformed);
        assert!(qualify(&malformed, &r, Some(&changed_a)).is_err());
        let duplicate = String::from_utf8(raw.to_vec()).unwrap().replace(
            "\"state\":\"committed\"",
            "\"state\":\"prepared\",\"state\":\"committed\"",
        );
        changed_a.raw_digest = sha256_bytes(duplicate.as_bytes());
        assert!(qualify(duplicate.as_bytes(), &r, Some(&changed_a)).is_err());
        let mut gated = r.clone();
        gated.consumer = "nightshift-readonly-continuity".into();
        assert_eq!(
            qualify(raw, &gated, Some(&a)).unwrap()["decision"],
            "supporting_evidence_missing"
        );
        let memory = std::fs::read(std::env::var("NQ_CONTINUITY_SOURCE_EXPORT").unwrap()).unwrap();
        let m: Value = serde_json::from_slice(&memory).unwrap();
        let binding = nq_core::continuity_support::ContinuityBinding {
            store_id: m["source"]["store_id"].as_str().unwrap().into(),
            memory_id: m["subject"]["memory_id"].as_str().unwrap().into(),
            scope: m["subject"]["scope"].as_str().unwrap().into(),
            subject_digest: semantic_digest(&gated.subject).unwrap(),
            principal: gated.consumer.clone(),
            purpose: "continue_observing".into(),
            raw_source_digest: sha256_bytes(&memory),
        };
        gated.continuity_support =
            Some(nq_core::continuity_support::qualify(&memory, &binding).unwrap());
        let result = qualify(raw, &gated, Some(&a)).unwrap();
        assert_eq!(result["decision"], "supported_readonly");
        replay(&result).unwrap();
        std::fs::write(
            output.join("continuity.json"),
            nq_protocol::canonical_json_bytes(&result).unwrap(),
        )
        .unwrap();
        gated
            .continuity_support
            .as_mut()
            .unwrap()
            .binding
            .subject_digest = sha256_bytes(b"different subject");
        assert!(qualify(raw, &gated, Some(&a)).is_err());
    }
}
