use nq_core::continuity_support::{ContinuityBinding, qualify, replay};

#[test]
#[ignore = "requires actual contctl campaign fixture directory NQ_CONTINUITY_FIXTURES"]
fn real_continuity_positive_refusal_unknown_and_exact_replay() {
    let directory = std::path::PathBuf::from(std::env::var("NQ_CONTINUITY_FIXTURES").unwrap());
    for (name, expected) in [
        ("eligible", "eligible"),
        ("revoked", "not_eligible"),
        ("uncommitted", "indeterminate"),
    ] {
        let raw = std::fs::read(directory.join(format!("{name}.json"))).unwrap();
        let source: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let binding = ContinuityBinding {
            store_id: source["source"]["store_id"].as_str().unwrap().into(),
            memory_id: source["subject"]["memory_id"].as_str().unwrap().into(),
            scope: source["subject"]["scope"].as_str().unwrap().into(),
            subject_digest: nq_protocol::sha256_bytes(b"exact subject"),
            principal: "nightshift-readonly-continuity".into(),
            purpose: "continue_observing".into(),
            raw_source_digest: nq_protocol::sha256_bytes(&raw),
        };
        let receipt = qualify(&raw, &binding).unwrap();
        assert_eq!(receipt.disposition, expected);
        replay(&receipt).unwrap();
        assert!(
            receipt
                .limitations
                .iter()
                .any(|s| s.contains("authoring_tier"))
        );
        let mut wrong = binding.clone();
        wrong.memory_id = "different".into();
        assert!(qualify(&raw, &wrong).is_err());
        wrong = binding.clone();
        wrong.purpose = "execute".into();
        assert!(qualify(&raw, &wrong).is_err());
        wrong = binding.clone();
        wrong.principal = "different".into();
        assert!(qualify(&raw, &wrong).is_err());
        let mut changed = raw.clone();
        changed.push(b' ');
        assert!(qualify(&changed, &binding).is_err());
        let mut contradiction = source.clone();
        contradiction["rely"]["rely_ok"] = serde_json::json!(source["rely"]["code"] != "eligible");
        let bytes = serde_json::to_vec(&contradiction).unwrap();
        wrong = binding.clone();
        wrong.raw_source_digest = nq_protocol::sha256_bytes(&bytes);
        assert!(qualify(&bytes, &wrong).is_err());
        if name == "eligible" {
            let history = std::path::PathBuf::from(std::env::var("NQ_CONTINUITY_HISTORY").unwrap());
            let guarded =
                nq_core::continuity_support::qualify_with_history(&raw, &binding, &history)
                    .unwrap();
            replay(&guarded).unwrap();
            assert!(guarded.snapshot_context.is_some());
            assert_eq!(
                guarded,
                nq_core::continuity_support::qualify_with_history(&raw, &binding, &history)
                    .unwrap()
            );
            let mut envelope = source.clone();
            envelope["export_id"] = serde_json::json!(nq_protocol::sha256_bytes(b"reexport"));
            envelope["history"]["event_count"] = serde_json::json!(100);
            let reexport = serde_json::to_vec(&envelope).unwrap();
            let mut rebind = binding.clone();
            rebind.raw_source_digest = nq_protocol::sha256_bytes(&reexport);
            assert!(
                nq_core::continuity_support::qualify_with_history(&reexport, &rebind, &history)
                    .is_ok()
            );
            let mut altered = source.clone();
            altered["content_hash"] =
                serde_json::json!(nq_protocol::sha256_bytes(b"different contents"));
            let changed = serde_json::to_vec(&altered).unwrap();
            rebind.raw_source_digest = nq_protocol::sha256_bytes(&changed);
            assert!(
                nq_core::continuity_support::qualify_with_history(&changed, &rebind, &history)
                    .unwrap_err()
                    .contains("SnapshotSubstitution")
            );
            altered["evaluation_time"] = serde_json::json!("2027-01-01T00:00:00Z");
            let later = serde_json::to_vec(&altered).unwrap();
            rebind.raw_source_digest = nq_protocol::sha256_bytes(&later);
            assert!(
                nq_core::continuity_support::qualify_with_history(&later, &rebind, &history)
                    .is_ok()
            );
            let interrupted = history.join("interrupted");
            std::fs::create_dir(&interrupted).unwrap();
            let key = guarded
                .snapshot_context
                .as_ref()
                .unwrap()
                .snapshot_key
                .to_string();
            std::fs::write(
                interrupted.join(format!("{}.json", key.trim_start_matches("sha256:"))),
                b"",
            )
            .unwrap();
            assert!(
                nq_core::continuity_support::qualify_with_history(&raw, &binding, &interrupted)
                    .is_err()
            );
            let concurrent = history.join("concurrent");
            std::fs::create_dir(&concurrent).unwrap();
            rebind.raw_source_digest = nq_protocol::sha256_bytes(&changed);
            let results = std::thread::scope(|scope| {
                let first = scope.spawn(|| {
                    nq_core::continuity_support::qualify_with_history(&raw, &binding, &concurrent)
                });
                let second = scope.spawn(|| {
                    nq_core::continuity_support::qualify_with_history(
                        &changed,
                        &rebind,
                        &concurrent,
                    )
                });
                [
                    first.join().unwrap().is_ok(),
                    second.join().unwrap().is_ok(),
                ]
            });
            assert_eq!(results.into_iter().filter(|ok| *ok).count(), 1);
            // Source-owned reason array, not substring search over arbitrary details.
            let mut bad = source.clone();
            bad["rely"]["rely_ok"] = serde_json::json!(false);
            bad["rely"]["code"] = serde_json::json!("hard_premise_unavailable");
            bad["rely"]["details"]["unrelated"] = serde_json::json!("noise:missing");
            for (reason, expected) in [("revoked", "not_eligible"), ("missing", "indeterminate")] {
                bad["rely"]["details"]["bad_premises"] =
                    serde_json::json!([format!("memory:{reason}")]);
                let bytes = serde_json::to_vec(&bad).unwrap();
                rebind.raw_source_digest = nq_protocol::sha256_bytes(&bytes);
                assert_eq!(qualify(&bytes, &rebind).unwrap().disposition, expected);
            }
            bad["rely"]["details"]["bad_premises"] = serde_json::json!(["memory:unknown"]);
            let bytes = serde_json::to_vec(&bad).unwrap();
            rebind.raw_source_digest = nq_protocol::sha256_bytes(&bytes);
            assert!(qualify(&bytes, &rebind).is_err());
            // Otherwise valid source and matching custody digest: parser, not
            // an unrelated digest mismatch, must reject duplicate keys.
            let json = serde_json::to_string(&source).unwrap();
            let duplicate = json.replace("\"rely_ok\":true", "\"rely_ok\":false,\"rely_ok\":true");
            assert_ne!(json, duplicate);
            wrong.raw_source_digest = nq_protocol::sha256_bytes(duplicate.as_bytes());
            assert!(
                qualify(duplicate.as_bytes(), &wrong)
                    .unwrap_err()
                    .contains("duplicate")
            );
            let policy = serde_json::to_string(&binding).unwrap();
            let duplicate_policy =
                policy.replace("\"purpose\":", "\"purpose\":\"execute\",\"purpose\":");
            assert!(
                nq_protocol::decode_json_document::<ContinuityBinding>(
                    duplicate_policy.as_bytes(),
                    16384
                )
                .is_err()
            );
            for (pointer, replacement) in [
                ("/source/schema_version", serde_json::json!("1")),
                ("/source/exporter", serde_json::json!({})),
                ("/source/exporter/version", serde_json::json!(3)),
                ("/lifecycle", serde_json::json!({})),
                ("/lifecycle/observe_event_id", serde_json::json!(3)),
                ("/times", serde_json::json!({})),
                ("/times/created_at", serde_json::json!("invalid")),
                ("/history/event_count", serde_json::json!(-1)),
                ("/effective_reliance", serde_json::json!("arbitrary")),
                ("/effective_reliance", serde_json::json!("actionable")),
                ("/authoring_tier", serde_json::json!("arbitrary")),
                ("/status", serde_json::json!("arbitrary")),
                ("/establishes", serde_json::json!([false])),
                ("/does_not_establish", serde_json::json!([])),
            ] {
                let mut malformed = source.clone();
                *malformed.pointer_mut(pointer).unwrap() = replacement;
                let bytes = serde_json::to_vec(&malformed).unwrap();
                wrong = binding.clone();
                wrong.raw_source_digest = nq_protocol::sha256_bytes(&bytes);
                assert!(
                    qualify(&bytes, &wrong).is_err(),
                    "accepted malformed {pointer}"
                );
            }
            for pointer in ["/source", "/times", "/lifecycle"] {
                let mut malformed = source.clone();
                let map = malformed
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
                let key = map.keys().next().unwrap().clone();
                map.remove(&key);
                let bytes = serde_json::to_vec(&malformed).unwrap();
                wrong = binding.clone();
                wrong.raw_source_digest = nq_protocol::sha256_bytes(&bytes);
                assert!(qualify(&bytes, &wrong).is_err());
            }
        }
    }
}
