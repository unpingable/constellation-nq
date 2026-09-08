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
    }
}
