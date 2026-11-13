// Included inside engine::tests::current_report_preparation. Run each variant
// in a separate process, sequentially; setup and one warm preparation are excluded.
fn current_report_process_cpu_ticks() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").expect("Linux process CPU accounting");
    let tail = stat.rsplit_once(')').expect("process comm terminator").1;
    let fields: Vec<_> = tail.split_whitespace().collect();
    // Tail starts at field 3 (state); utime/stime are fields 14 and 15.
    let user: u64 = fields[11].parse().expect("utime ticks");
    let system: u64 = fields[12].parse().expect("stime ticks");
    user.checked_add(system).expect("process CPU tick sum")
}

#[test]
#[ignore = "bounded native A/B CPU observation; run variants sequentially"]
fn current_report_preparation_cpu_measurement() {
    const ROWS: usize = 64;
    const REPEATS: usize = 200;
    let temporary = tempfile::tempdir().unwrap();
    let root = std::env::var_os("NQ_CURRENT_REPORT_COST_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned());
    assert!(
        root.is_absolute(),
        "fixture path must be campaign-owned and absolute"
    );
    fs::create_dir_all(&root).unwrap();
    let config_path = root.join("fixture-config.toml");
    let (mut engine, watcher) = if root.join("nq.db").exists() {
        let config = NqConfig::from_toml(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(config.database_path, root.join("nq.db"));
        assert_eq!(config.watchers.len(), 1);
        let watcher = config.watchers[0].clone();
        let identity = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
            b"current-report-fixture",
        ));
        (
            CollectionEngine::open_with_evaluator_identity(&config, Ok(identity)).unwrap(),
            watcher,
        )
    } else {
        assert!(
            !config_path.exists(),
            "incomplete fixture requires explicit reconciliation"
        );
        let (mut engine, watcher, _) = live_fixture(&root, false);
        for _ in 0..ROWS {
            assert!(engine.collect(&watcher).unwrap().is_success());
        }
        fs::write(&config_path, toml::to_string(&engine.config).unwrap()).unwrap();
        (engine, watcher)
    };
    assert_eq!(watcher.profile.id, nq_profiles::host_io::PROFILE_ID);
    assert_eq!(
        watcher.profile.version,
        nq_profiles::host_io::PROFILE_VERSION
    );
    let profile = resolve(&watcher).unwrap();
    evict_own_reports(&watcher.instance_id);
    let (source, prepared) =
        PreparedHistoricalReports::prepare(&mut engine.store, &watcher, profile).unwrap();
    assert_eq!(source.snapshot().reports.len(), ROWS);
    assert_eq!(prepared.matching_indices.len(), ROWS);
    let latest = source.snapshot().reports.last().unwrap();
    let latest_id = latest.report_id.clone();
    let latest_sequence = u64::try_from(latest.report_sequence).unwrap();
    let raw_source_bytes: usize = source
        .snapshot()
        .reports
        .iter()
        .map(|row| row.canonical_json.len())
        .sum();
    assert_eq!(prepared.reports.last().unwrap().report_id, latest_id);
    drop(prepared);
    drop(source);

    let cpu_before = current_report_process_cpu_ticks();
    let started = std::time::Instant::now();
    let mut retained_detector_rows = 0;
    for _ in 0..REPEATS {
        let (source, prepared) =
            PreparedHistoricalReports::prepare(&mut engine.store, &watcher, profile).unwrap();
        assert_eq!(source.snapshot().reports.len(), ROWS);
        assert_eq!(prepared.matching_indices.len(), ROWS);
        let newest = prepared.reports.last().expect("newest detector report");
        assert_eq!(newest.report_id, latest_id);
        assert_eq!(newest.report_sequence, latest_sequence);
        retained_detector_rows = prepared.reports.len();
        // Normal iteration drop includes release of each preparation's results.
    }
    let elapsed_micros = started.elapsed().as_micros();
    let cpu_ticks = current_report_process_cpu_ticks()
        .checked_sub(cpu_before)
        .expect("monotonic process CPU accounting");
    println!(
        "current_report_cpu repeats={REPEATS} source_rows={ROWS} raw_source_bytes={raw_source_bytes} latest_sequence={latest_sequence} matching_rows={ROWS} retained_detector_rows={retained_detector_rows} cpu_ticks={cpu_ticks} elapsed_micros={elapsed_micros}"
    );
}
