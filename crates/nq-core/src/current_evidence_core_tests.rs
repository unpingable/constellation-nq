// Ordinary Engine callers use a distinct selected-support proof. Full proof
// tests remain separate and keep their complete-source refusal contract.

#[test]
fn ordinary_current_source_materialization_stays_at_one_as_history_grows() {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, watcher, _) = live_fixture(root.path(), false);
    let mut collected = 0;
    for retained in [1, 4, 12] {
        while collected < retained {
            assert!(engine.collect(&watcher).unwrap().is_success());
            collected += 1;
        }
        PREPARED_SOURCE_ROWS_MATERIALIZED.with(|count| count.set(0));
        PREPARED_SOURCE_BYTES_MATERIALIZED.with(|count| count.set(0));
        assert_eq!(engine.freshness_sweep(&watcher).unwrap(), 1);
        let rows = PREPARED_SOURCE_ROWS_MATERIALIZED.with(std::cell::Cell::get);
        let bytes = PREPARED_SOURCE_BYTES_MATERIALIZED.with(std::cell::Cell::get);
        let full = engine
            .store
            .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
            .unwrap();
        assert_eq!(full.reports.len(), retained);
        assert_eq!(
            rows, 1,
            "retained history must not enter current preparation"
        );
        assert_eq!(bytes, full.reports.last().unwrap().canonical_json.len());
        let memo = admitted_report_memo().lock().unwrap();
        let own = memo
            .entries
            .values()
            .filter(|entry| entry.row.instance_id == watcher.instance_id)
            .count();
        assert_eq!(
            own, 1,
            "a healthy sweep retains only its selected full head"
        );
        println!(
            "ordinary_current_scale retained={retained} selected_rows={rows} selected_bytes={bytes} memo_entries={own}"
        );
    }
}

#[test]
fn ordinary_current_lineage_matches_committed_finding_and_keeps_full_citation() {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, watcher, template) = live_fixture(root.path(), true);
    assert!(engine.collect(&watcher).unwrap().is_success());
    let profile = resolve(&watcher).unwrap();
    let sequence = engine.store.latest_evaluation_sequence().unwrap();
    let (_, envelope, _) = validate_single_evaluation(&engine.store, sequence).unwrap();
    assert_eq!(
        current_question_lineage(&watcher, profile).unwrap(),
        evaluation_finding_lineage(&envelope).unwrap()
    );
    let cited = engine.store.finding_snapshots().unwrap()[0]
        .evidence_json
        .clone();
    fs::write(
        template,
        canonical(&testimony(&watcher, profile, Utc::now(), false, true))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let failed = engine.collect(&watcher).unwrap();
    assert!(matches!(failed.result, CollectionResult::Admitted { .. }));
    let (source, history) =
        PreparedHistoricalReports::prepare_ordinary(&mut engine.store, &watcher, profile).unwrap();
    let PreparedHistoricalSource::Current(source) = source else {
        panic!("audited ordinary question must use scoped custody");
    };
    assert_eq!(
        source.snapshot().reports.len(),
        2,
        "failed head and earlier full citation"
    );
    assert_eq!(history.matching_indices.len(), 2);
    assert_eq!(history.reports.len(), 1);
    assert_eq!(
        history.reports[0].report_id,
        source.snapshot().reports.last().unwrap().report_id
    );
    assert_eq!(
        engine.store.finding_snapshots().unwrap()[0].evidence_json,
        cited
    );
}

#[test]
fn ordinary_current_context_mismatch_falls_back_before_reconstruction_and_authority_refuses() {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, watcher, _) = live_fixture(root.path(), false);
    for _ in 0..2 {
        assert!(engine.collect(&watcher).unwrap().is_success());
    }
    let profile = resolve(&watcher).unwrap();
    let mut other = watcher.clone();
    other.subject.push_str(".different-context");
    let before = RECONSTRUCTIONS.with(std::cell::Cell::get);
    let (source, history) =
        PreparedHistoricalReports::prepare_ordinary(&mut engine.store, &other, profile).unwrap();
    let PreparedHistoricalSource::Full(source) = source else {
        panic!("mismatched head must use complete proof");
    };
    assert_eq!(source.snapshot().reports.len(), 2);
    assert!(history.matching_indices.is_empty());
    assert_eq!(RECONSTRUCTIONS.with(std::cell::Cell::get), before);
    PREPARED_SOURCE_ROWS_MATERIALIZED.with(|count| count.set(0));
    assert!(
        engine.freshness_sweep(&other).is_err(),
        "current admission never comes from a memo or source proof"
    );
    assert_eq!(
        PREPARED_SOURCE_ROWS_MATERIALIZED.with(std::cell::Cell::get),
        0,
        "the real caller refuses changed current authority before preparation"
    );
}

#[test]
fn ordinary_current_ignores_unreferenced_old_bytes_while_full_preparation_refuses() {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, watcher, _) = live_fixture(root.path(), false);
    for _ in 0..2 {
        assert!(engine.collect(&watcher).unwrap().is_success());
    }
    mutate_bypassing_triggers(
        &engine.config.database_path,
        "admitted_reports",
        "UPDATE admitted_reports SET canonical_json=CAST('{ }' AS BLOB) WHERE report_sequence=(SELECT MIN(report_sequence) FROM admitted_reports)",
    );
    assert_eq!(
        engine.freshness_sweep(&watcher).unwrap(),
        1,
        "unreferenced old raw integrity belongs to the complete audit, outside this current proof"
    );
    let profile = resolve(&watcher).unwrap();
    let error = PreparedHistoricalReports::prepare(&mut engine.store, &watcher, profile)
        .err()
        .expect("complete proof must still reopen the intentionally changed old bytes");
    assert!(error.to_string().contains("not canonical"), "{error}");
    mutate_bypassing_triggers(
        &engine.config.database_path,
        "admitted_reports",
        "UPDATE admitted_reports SET canonical_json=CAST('{ }' AS BLOB) WHERE report_sequence=(SELECT MAX(report_sequence) FROM admitted_reports)",
    );
    let error = engine.freshness_sweep(&watcher).unwrap_err();
    assert!(
        error.to_string().contains("not canonical"),
        "selected head bytes still refuse through the actual caller: {error}"
    );
}

#[test]
fn ordinary_current_compact_absolute_head_selects_full_fallback() {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, watcher, _) = live_fixture(root.path(), false);
    for _ in 0..2 {
        assert!(engine.collect(&watcher).unwrap().is_success());
    }
    // Deliberate compact-head branch fixture, as in Store's current-source
    // fallback test. This is not a valid expiry or a passing store verdict.
    mutate_bypassing_triggers(
        &engine.config.database_path,
        "admitted_reports",
        "UPDATE admitted_reports SET source_expired=1,canonical_json=CAST('{}' AS BLOB),validated_report_json=CAST('{}' AS BLOB),next_checkpoint_json=NULL WHERE report_sequence=(SELECT MAX(report_sequence) FROM admitted_reports)",
    );
    let profile = resolve(&watcher).unwrap();
    let (source, _) =
        PreparedHistoricalReports::prepare_ordinary(&mut engine.store, &watcher, profile).unwrap();
    let PreparedHistoricalSource::Full(source) = source else {
        panic!("compact absolute head must select the explicit full fallback");
    };
    assert_eq!(source.snapshot().reports.len(), 1);
    assert_eq!(source.snapshot().watermarks[0].max_report_sequence, 2);
}

#[test]
fn ordinary_current_unknown_recites_compact_older_finding_evidence() {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, watcher, template) = live_fixture(root.path(), true);
    let profile = resolve(&watcher).unwrap();
    assert!(engine.collect(&watcher).unwrap().is_success());
    fs::write(
        &template,
        canonical(&testimony(&watcher, profile, Utc::now(), false, false))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    for _ in 0..2 {
        assert!(engine.collect(&watcher).unwrap().is_success());
    }
    let before = engine.store.finding_snapshots().unwrap().remove(0);
    assert_eq!(before.condition_state, "explicitly_absent");
    let expired = expire_ordinary_history(
        &mut engine.store,
        &timestamp(Utc::now() + Duration::seconds(1)),
    )
    .unwrap();
    assert!(expired.boundary.generation > 0);
    let compact_evidence = engine
        .store
        .finding_snapshots()
        .unwrap()
        .remove(0)
        .evidence_json;
    let (source, _) =
        PreparedHistoricalReports::prepare_ordinary(&mut engine.store, &watcher, profile).unwrap();
    let PreparedHistoricalSource::Current(source) = source else {
        panic!("full head with a compact citation remains a scoped question");
    };
    assert_eq!(source.snapshot().reports.len(), 1);
    assert_eq!(
        source.snapshot().expired_citations.len(),
        1,
        "real expiry compacted the prior resolved evidence"
    );
    fs::write(
        template,
        canonical(&testimony(&watcher, profile, Utc::now(), false, true))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let failed = engine.collect(&watcher).unwrap();
    assert!(matches!(failed.result, CollectionResult::Admitted { .. }));
    let after = engine.store.finding_snapshots().unwrap().remove(0);
    assert_eq!(after.finding_id, before.finding_id);
    assert_eq!(after.condition_state, before.condition_state);
    assert_eq!(
        after.evidence_json, compact_evidence,
        "unknown retains exact compact citation identity"
    );
    validate_semantic_history(&engine.store).unwrap();
}

fn assert_question_index_exact(memo: &AdmittedReportMemo) {
    let members: usize = memo.by_question.values().map(|ids| ids.len()).sum();
    assert_eq!(members, memo.entries.len(), "no orphan membership nodes");
    for ((digest, id), entry) in &memo.entries {
        assert!(memo.by_question[&(digest.clone(), entry.row.instance_id.clone())].contains(id));
    }
    for ((digest, instance), ids) in &memo.by_question {
        assert!(!ids.is_empty());
        for id in ids {
            assert_eq!(
                &memo.entries[&(digest.clone(), id.clone())].row.instance_id,
                instance
            );
        }
    }
    assert_eq!(
        memo.bytes,
        memo.entries
            .values()
            .map(|entry| entry.weight)
            .sum::<usize>()
    );
}

#[test]
fn current_memo_pruning_visits_only_its_question_and_handles_replacement() {
    let fixture = SemanticLineageFixture::new();
    let mut memo = AdmittedReportMemo::default();
    let base = reconstruction_fixture_row(&fixture, "question-report");
    for index in 0..40 {
        let mut row = base.clone();
        row.instance_id = format!("unrelated-{index}");
        row.report_id = format!("unrelated-report-{index}");
        memo.remember(&row, &fixture.profile_digest, None, None, usize::MAX);
    }
    for index in 0..3 {
        let mut row = base.clone();
        row.report_id = format!("question-report-{index}");
        memo.remember(&row, &fixture.profile_digest, None, None, usize::MAX);
    }
    let before = MEMO_PRUNE_VISITED.with(std::cell::Cell::get);
    let keep = std::collections::BTreeSet::from(["question-report-2"]);
    memo.retain_question_sources(&fixture.profile_digest, &base.instance_id, &keep);
    assert_eq!(
        MEMO_PRUNE_VISITED.with(std::cell::Cell::get) - before,
        3,
        "forty unrelated questions are not traversed"
    );
    assert_eq!(memo.entries.len(), 41);
    assert_question_index_exact(&memo);
    let mut replacement = base;
    replacement.report_id = "question-report-2".into();
    let old_instance = replacement.instance_id.clone();
    replacement.instance_id = "replacement-instance".into();
    memo.remember(
        &replacement,
        &fixture.profile_digest,
        None,
        None,
        usize::MAX,
    );
    assert!(
        !memo
            .by_question
            .contains_key(&(fixture.profile_digest.clone(), old_instance))
    );
    assert_question_index_exact(&memo);
}

#[test]
fn current_memo_index_obeys_oversized_eviction_and_clear_budget() {
    let fixture = SemanticLineageFixture::new();
    let row = reconstruction_fixture_row(&fixture, "retained-index-row");
    let cap = AdmittedReportMemo::weight(&row, None);
    let mut memo = AdmittedReportMemo::default();
    memo.remember(&row, &fixture.profile_digest, None, None, cap);
    assert_eq!(memo.bytes, cap);
    let mut oversized = row.clone();
    oversized.canonical_json.resize(cap + 1, b'x');
    memo.remember(&oversized, &fixture.profile_digest, None, None, cap);
    assert!(
        memo.exact(&row, &fixture.profile_digest).is_some(),
        "oversized replacement preserves the original entry/index"
    );
    assert_question_index_exact(&memo);
    let mut next = row.clone();
    next.report_id = "replacement-index-row".into();
    let next_cap = AdmittedReportMemo::weight(&next, None);
    memo.remember(&next, &fixture.profile_digest, None, None, next_cap);
    assert!(memo.exact(&row, &fixture.profile_digest).is_none());
    assert_eq!(memo.entries.len(), 1);
    assert_question_index_exact(&memo);
    memo.clear();
    assert_eq!(
        (memo.entries.len(), memo.by_question.len(), memo.bytes),
        (0, 0, 0)
    );
}
