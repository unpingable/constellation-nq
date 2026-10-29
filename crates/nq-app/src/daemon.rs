//! Resident scheduler, local API, and helper supervisor entry point.

mod collection_queue;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nq_core::config::{Carrier, NqConfig, WatcherConfig};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Resident nq-ng service.
#[derive(Debug, Parser)]
#[command(name = "nqd", version, about)]
pub struct Nqd {
    /// Human-edited configuration path.
    #[arg(long, env = "NQ_CONFIG", default_value = "/etc/nq/nq.toml")]
    pub config: PathBuf,
    /// Optional loopback console address (e.g. `127.0.0.1:8787`). Absent by
    /// default: no INET listener is created and the host-local HTTP console is
    /// off. The group-bounded Unix socket API is always enabled and remains the
    /// primary local surface.
    #[arg(long)]
    pub console_address: Option<String>,
    /// Collect every configured instance once, then exit. Intended for install
    /// drills and black-box tests, not normal service operation.
    #[arg(long)]
    pub once: bool,
}

/// Start the daemon and persist until shutdown.
///
/// # Errors
///
/// Returns when configuration/catalog/database validation fails or a daemon
/// service terminates unexpectedly.
#[allow(clippy::too_many_lines)]
pub async fn run(options: Nqd) -> Result<()> {
    initialize_tracing();
    let config = NqConfig::load(&options.config)
        .with_context(|| format!("cannot load {}", options.config.display()))?;
    let _database_ownership = crate::ownership::acquire(&config.database_path, "nqd")?;
    let mut store = open_configured_store(&config).context(
        "database is absent or has an incompatible schema; run `nq init` or `nq admin upgrade`",
    )?;
    // The open validated the store laws: beyond its certified watermark when
    // one applies, in full otherwise. Refuse typed provider-history
    // substitution before the daemon mutates status history or binds any
    // listener: this core pass additionally proves request/raw/native-outcome
    // semantic correspondence, beyond the same certification (in full
    // without one). `nq admin validate --full` remains the deep pass.
    let startup = nq_core::engine::validate_at_startup(&store)
        .context("provider-intake history failed typed startup verification")?;
    info!(validation = ?startup, "startup history validated");
    validate_catalog(&config)?;
    let horizon = chrono::TimeDelta::try_seconds(i64::try_from(config.retention.horizon_seconds)?)
        .context("retention horizon exceeds duration range")?;
    let cutoff = chrono::Utc::now()
        .checked_sub_signed(horizon)
        .context("retention cutoff exceeds timestamp range")?;
    // Expiry is maintenance: a refusal is reported and startup continues;
    // integrity and invariant failures still stop the daemon.
    match nq_core::classify_retention_attempt(nq_core::engine::expire_ordinary_history(
        &mut store,
        &cutoff.to_rfc3339(),
    ))? {
        nq_core::RetentionAttempt::Completed(expired) if expired.deleted_rows > 0 => {
            info!(
                deleted_rows = expired.deleted_rows,
                generation = expired.boundary.generation,
                "ordinary completed history expired"
            );
        }
        nq_core::RetentionAttempt::Completed(_)
        | nq_core::RetentionAttempt::Deferred { .. }
        | nq_core::RetentionAttempt::DeferredForReadyCollections => {}
        nq_core::RetentionAttempt::Refused { class, detail } => {
            warn!(class, %detail, "retention expiry refused at startup; continuing");
        }
    }
    nq_core::engine::record_component_status(
        &mut store,
        "daemon",
        "nqd",
        "unknown",
        "starting",
        &serde_json::json!({"pid": std::process::id()}),
    )?;
    nq_core::engine::record_component_status(
        &mut store,
        "scheduler",
        "independent",
        "unknown",
        "loading_instances",
        &serde_json::json!({"instance_count": config.watchers.len()}),
    )?;
    drop(store);

    if options.once {
        return collect_once(config).await;
    }

    let unix_listener = crate::api::bind_unix(&config.socket_path)?;
    // Fail closed on the host-local surface: bind an INET listener only when an
    // address is explicitly configured. Absent ⇒ Unix socket only.
    let loopback_listener = match options.console_address.as_deref() {
        Some(address) => {
            let parsed = crate::api::parse_loopback(address)?;
            Some(crate::api::bind_loopback(parsed).await?)
        }
        None => None,
    };
    let mut ready_store = open_configured_store(&config)?;
    nq_core::engine::record_component_status(
        &mut ready_store,
        "daemon",
        "nqd",
        "healthy",
        "listeners_ready",
        &serde_json::json!({"pid": std::process::id()}),
    )?;
    nq_core::engine::record_component_status(
        &mut ready_store,
        "scheduler",
        "independent",
        "healthy",
        "instances_loaded",
        &serde_json::json!({"instance_count": config.watchers.len()}),
    )?;
    drop(ready_store);
    let mut services = JoinSet::new();
    let database_path = config.database_path.clone();
    services
        .spawn(async move { crate::api::serve_unix_listener(unix_listener, database_path).await });
    if let Some(loopback_listener) = loopback_listener {
        info!("host-local loopback console enabled (opt-in)");
        let database_path = config.database_path.clone();
        services.spawn(async move {
            crate::api::serve_loopback_listener(loopback_listener, database_path).await
        });
    } else {
        info!("no loopback console; Unix socket API only");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // SQLite's operation guard is still authoritative across processes. Queue
    // this daemon's own full operations fairly instead of making its workers
    // repeatedly consume that guard's bounded contention wait against peers.
    let writer = Arc::new(Mutex::new(()));
    let shared = shared_stdio_engine(&config, writer.clone()).await?;
    for watcher in config.watchers.clone() {
        let config = config.clone();
        let shutdown = shutdown_rx.clone();
        let writer = writer.clone();
        let shared = shared.clone();
        services.spawn(async move {
            schedule_instance(config, watcher, shutdown, writer, shared).await
        });
    }
    for watcher in config.watchers.clone() {
        let config = config.clone();
        let shutdown = shutdown_rx.clone();
        let writer = writer.clone();
        let shared = shared.clone();
        services
            .spawn(async move { sweep_freshness(config, watcher, shutdown, writer, shared).await });
    }

    info!(instances = config.watchers.len(), "nqd started");
    // systemd stops the service with SIGTERM: stop as for SIGINT, so every
    // engine and store connection closes and the stopped status is recorded.
    // Closing never checkpoints (that would be an unbudgeted main-file
    // write); the stop runs one bounded checkpoint after the stopped record.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("cannot listen for SIGTERM")?;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("cannot listen for shutdown signal")?;
            info!("shutdown requested");
        }
        _ = terminate.recv() => {
            info!("termination requested");
        }
        result = services.join_next() => {
            match result {
                Some(Ok(Ok(()))) => anyhow::bail!("daemon service exited unexpectedly"),
                Some(Ok(Err(error))) => return Err(error).context("daemon service failed"),
                Some(Err(error)) => return Err(error).context("daemon task panicked"),
                None => return Ok(()),
            }
        }
    }
    let _ = shutdown_tx.send(true);
    let _drained_writer = drain_store_operations(&mut services, writer).await;
    drop(shared);
    let mut stopped_store = open_configured_store(&config)?;
    nq_core::engine::record_component_status(
        &mut stopped_store,
        "daemon",
        "nqd",
        "unknown",
        "stopped",
        &serde_json::json!({"pid": std::process::id()}),
    )?;
    // Fold the WAL so the main file alone holds every commit, through the
    // same guarded, envelope-checked TRUNCATE checkpoint as every write. A
    // refusal leaves the WAL (nq.db + nq.db-wal remain one consistent store).
    match stopped_store.checkpoint_wal() {
        Ok(()) => info!("write-ahead log checkpointed at stop"),
        Err(error) => warn!(
            %error,
            "bounded stop checkpoint refused; the write-ahead log keeps committed frames"
        ),
    }
    Ok(())
}

fn open_configured_store(config: &NqConfig) -> Result<nq_store::Store> {
    Ok(nq_store::Store::open_with_capacity(
        &config.database_path,
        config.retention.horizon_seconds,
        config.retention.byte_ceiling,
        config.retention.reserve_bytes,
        config.retention.auxiliary_bytes,
    )?)
}

async fn collect_once(config: NqConfig) -> Result<()> {
    let mut tasks = JoinSet::new();
    let writer = Arc::new(Mutex::new(()));
    let shared = shared_stdio_engine(&config, writer.clone()).await?;
    for watcher in config.watchers.clone() {
        let config = config.clone();
        let writer = writer.clone();
        let shared = shared.clone();
        tasks.spawn(async move { collect_one(config, watcher, writer, shared).await });
    }
    let mut failures = 0;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(outcome)) if outcome.is_success() => {
                let governed_result = canonical_result_document(&outcome)?;
                info!(
                    instance = %outcome.instance_id(),
                    governed_result = %governed_result,
                    "collection admitted"
                );
            }
            Ok(Ok(outcome)) => {
                failures += 1;
                let governed_result = canonical_result_document(&outcome)?;
                warn!(
                    instance = %outcome.instance_id(),
                    governed_result = %governed_result,
                    "collection did not admit a report"
                );
            }
            Ok(Err(error)) => {
                failures += 1;
                error!(%error, "collection failed before a run record could be returned");
            }
            Err(error) => return Err(error.into()),
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        anyhow::bail!("{failures} instance collection(s) did not admit a report")
    }
}

type SharedEngine = Arc<SharedStdioEngine>;

struct SharedStdioEngine {
    engine: Mutex<nq_core::CollectionEngine>,
    queue: collection_queue::CollectionQueue,
}

impl SharedStdioEngine {
    fn blocking_lock(&self) -> tokio::sync::MutexGuard<'_, nq_core::CollectionEngine> {
        self.engine.blocking_lock()
    }

    #[cfg(test)]
    async fn lock(&self) -> tokio::sync::MutexGuard<'_, nq_core::CollectionEngine> {
        self.engine.lock().await
    }

    // Called only inside store_operation, after acquiring the daemon writer.
    // The ticket stays in the blocking closure even if its async observer is
    // cancelled, and retires before store_operation releases that writer.
    fn collect_under_writer(
        &self,
        ticket: collection_queue::CollectionTicket,
        watcher: &WatcherConfig,
    ) -> (
        Result<nq_core::CollectionOutcome, nq_core::engine::EngineError>,
        Option<nq_core::RetentionAttempt>,
    ) {
        let defer = ticket.should_defer_pending_expiry();
        let mut engine = self.blocking_lock();
        let outcome = if defer {
            engine.collect_before_pending_expiry(watcher)
        } else {
            engine.collect(watcher)
        };
        let retention = engine.last_retention_attempt().cloned();
        drop(engine);
        if !defer {
            ticket.finish_opportunity();
        }
        drop(ticket);
        (outcome, retention)
    }
}

/// A stdio-only daemon has no persistent helper to quiesce while another
/// watcher collects. Share its store-wide replay and expiry state rather than
/// repeatedly invalidating peer engines at each retention generation. Mixed
/// configurations keep independent resident engines and Unix binding watches.
async fn shared_stdio_engine(
    config: &NqConfig,
    writer: Arc<Mutex<()>>,
) -> Result<Option<SharedEngine>> {
    let config = config.clone();
    store_operation(writer, move || open_shared_stdio_engine(&config)).await?
}

fn open_shared_stdio_engine(config: &NqConfig) -> Result<Option<SharedEngine>> {
    if config.watchers.is_empty() || config.watchers.iter().any(|w| w.carrier != Carrier::Stdio) {
        return Ok(None);
    }
    Ok(Some(Arc::new(SharedStdioEngine {
        engine: Mutex::new(nq_core::CollectionEngine::open(config)?),
        queue: collection_queue::CollectionQueue::default(),
    })))
}

/// Aborting async waiters does not abort a running blocking operation. Its
/// writer permit is the completion boundary before closing resident stores.
async fn drain_store_operations(
    services: &mut JoinSet<Result<()>>,
    writer: Arc<Mutex<()>>,
) -> tokio::sync::OwnedMutexGuard<()> {
    services.abort_all();
    while services.join_next().await.is_some() {}
    writer.lock_owned().await
}

async fn schedule_instance(
    config: NqConfig,
    watcher: WatcherConfig,
    mut shutdown: watch::Receiver<bool>,
    writer: Arc<Mutex<()>>,
    shared: Option<SharedEngine>,
) -> Result<()> {
    let jitter_cap = watcher.schedule.jitter_seconds;
    let jitter = if jitter_cap == 0 {
        0
    } else {
        rand::random::<u64>() % (jitter_cap + 1)
    };
    if jitter != 0 {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(jitter)) => {}
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
    }

    let mut engine = if shared.is_some() {
        None
    } else {
        Some(
            store_operation(writer.clone(), move || {
                nq_core::CollectionEngine::open(&config)
            })
            .await??,
        )
    };
    let mut backoff = watcher.schedule.retry_backoff_seconds;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let collection_watcher = watcher.clone();
        let shared = shared.clone();
        let ticket = shared.as_ref().map(|shared| shared.queue.register());
        let (returned_engine, outcome, retention) = store_operation(writer.clone(), move || {
            if let Some(shared) = shared {
                let (outcome, retention) = shared.collect_under_writer(
                    ticket.expect("shared collection registered before writer wait"),
                    &collection_watcher,
                );
                (None, outcome, retention)
            } else {
                let mut engine = engine.expect("independent resident engine");
                let outcome = engine.collect(&collection_watcher);
                let retention = engine.last_retention_attempt().cloned();
                (Some(engine), outcome, retention)
            }
        })
        .await?;
        engine = returned_engine;
        if let Some(nq_core::RetentionAttempt::Refused { class, detail }) = retention {
            warn!(
                instance = %watcher.instance_id,
                class,
                %detail,
                "retention expiry refused; collection continued"
            );
        }
        let delay = match outcome {
            Ok(outcome) if outcome.is_success() => {
                backoff = watcher.schedule.retry_backoff_seconds;
                let governed_result = canonical_result_document(&outcome)?;
                info!(
                    instance = %watcher.instance_id,
                    governed_result = %governed_result,
                    "collection admitted and evaluated"
                );
                watcher.schedule.interval_seconds
            }
            Ok(outcome) => {
                let governed_result = canonical_result_document(&outcome)?;
                warn!(
                    instance = %watcher.instance_id,
                    governed_result = %governed_result,
                    "collection retained without admitted report"
                );
                let delay = backoff.max(1);
                backoff = backoff
                    .saturating_mul(2)
                    .min(watcher.schedule.max_retry_backoff_seconds.max(1));
                delay
            }
            Err(nq_core::engine::EngineError::Store(ref refused)) if refused.is_refusal() => {
                warn!(instance = %watcher.instance_id, error = %refused, "collection refused");
                let delay = backoff.max(1);
                backoff = backoff
                    .saturating_mul(2)
                    .min(watcher.schedule.max_retry_backoff_seconds.max(1));
                delay
            }
            Err(error) => {
                error!(instance = %watcher.instance_id, %error, "collection engine error");
                let delay = backoff.max(1);
                backoff = backoff
                    .saturating_mul(2)
                    .min(watcher.schedule.max_retry_backoff_seconds.max(1));
                delay
            }
        };
        if let Some(resident) = engine {
            let (returned_engine, shutdown_requested) = wait_with_binding_watch(
                resident,
                &watcher,
                Duration::from_secs(delay),
                &mut shutdown,
            )
            .await?;
            engine = Some(returned_engine);
            if shutdown_requested {
                return Ok(());
            }
        } else {
            // Stdio helpers end with their request: no idle helper exists to
            // quiesce, and waiting must not acquire the shared engine lock.
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(delay)) => {}
                changed = shutdown.changed() => {
                    changed?;
                    return Ok(());
                }
            }
        }
    }
}

/// Render the exact versioned result document for structured daemon logs.
///
/// Debug formatting is a Rust implementation detail and is neither stable nor
/// independently reopenable. Log the same canonical serialization consumed by
/// the store and public surfaces so dependent testimony is never replaced by a
/// presentation-only projection.
fn canonical_result_document(value: &nq_core::CollectionOutcome) -> Result<String> {
    let frame = crate::transport::CollectionOutcomeFrame::encode(value)
        .context("cannot encode and reopen governed collection result for daemon log")?;
    let body = frame
        .wire()
        .strip_suffix(b"\n")
        .context("checked collection-result frame lacks its terminal newline")?;
    String::from_utf8(body.to_vec()).context("canonical governed result is not UTF-8")
}

async fn wait_with_binding_watch(
    mut engine: nq_core::CollectionEngine,
    watcher: &WatcherConfig,
    delay: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(nq_core::CollectionEngine, bool)> {
    let end = tokio::time::Instant::now() + delay;
    loop {
        let now = tokio::time::Instant::now();
        if now >= end {
            return Ok((engine, false));
        }
        let slice = (end - now).min(Duration::from_millis(250));
        tokio::select! {
            () = tokio::time::sleep(slice) => {}
            changed = shutdown.changed() => {
                changed?;
                return Ok((engine, true));
            }
        }
        let check_watcher = watcher.clone();
        let (returned_engine, quiesced) = tokio::task::spawn_blocking(move || {
            let result = engine.quiesce_if_binding_changed(&check_watcher);
            (engine, result)
        })
        .await?;
        engine = returned_engine;
        if quiesced? {
            warn!(
                instance = %watcher.instance_id,
                "persistent helper quiesced after admission binding changed"
            );
        }
    }
}

async fn collect_one(
    config: NqConfig,
    watcher: WatcherConfig,
    writer: Arc<Mutex<()>>,
    shared: Option<SharedEngine>,
) -> Result<nq_core::CollectionOutcome> {
    let ticket = shared.as_ref().map(|shared| shared.queue.register());
    Ok(store_operation(writer, move || {
        if let Some(shared) = shared {
            shared
                .collect_under_writer(
                    ticket.expect("shared collection registered before writer wait"),
                    &watcher,
                )
                .0
        } else {
            let mut engine = nq_core::CollectionEngine::open(&config)?;
            engine.collect(&watcher)
        }
    })
    .await??)
}

async fn sweep_freshness(
    config: NqConfig,
    watcher: WatcherConfig,
    mut shutdown: watch::Receiver<bool>,
    writer: Arc<Mutex<()>>,
    shared: Option<SharedEngine>,
) -> Result<()> {
    let profile = nq_profiles::resolve_profile(&watcher.profile.id, watcher.profile.version)
        .context("freshness sweep profile is not compiled")?;
    let reliance = profile.descriptor().freshness.reliance_seconds;
    let interval = (reliance / 2).clamp(1, 60);
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(interval)) => {}
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
        let sweep_config = config.clone();
        let sweep_watcher = watcher.clone();
        let shared = shared.clone();
        let result = store_operation(writer.clone(), move || {
            if let Some(shared) = shared {
                shared.blocking_lock().freshness_sweep(&sweep_watcher)
            } else {
                let mut engine = nq_core::CollectionEngine::open(&sweep_config)?;
                engine.freshness_sweep(&sweep_watcher)
            }
        })
        .await?;
        match result {
            Ok(count) => tracing::debug!(
                instance = %watcher.instance_id,
                evaluations = count,
                "freshness sweep committed"
            ),
            Err(error) => warn!(instance = %watcher.instance_id, %error, "freshness sweep failed"),
        }
    }
}

/// Keep the permit inside the blocking operation: cancelling its async waiter
/// must not admit a second writer while the first operation is still running.
async fn store_operation<T: Send + 'static>(
    writer: Arc<Mutex<()>>,
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    let queue_timing = nq_store::operation_timing::PhaseTiming::start("daemon.writer_queue");
    let permit = writer.lock_owned().await;
    drop(queue_timing);
    let pool_timing = nq_store::operation_timing::PhaseTiming::start("daemon.blocking_pool_queue");
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        drop(pool_timing);
        let _timing = nq_store::operation_timing::PhaseTiming::start("daemon.store_operation");
        operation()
    })
    .await
}

fn validate_catalog(config: &NqConfig) -> Result<()> {
    Ok(nq_core::engine::validate_compiled_config(config)?)
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use nq_core::engine::{CollectionOutcome, GovernedRefusal};
    use nq_protocol::{InstanceId, Refusal, RefusalBoundary, RefusalCode};
    use serde_json::json;

    use super::*;

    fn stdio_fixture(root: &std::path::Path) -> NqConfig {
        let mut config: NqConfig =
            toml::from_str(include_str!("../../../examples/nq-host.toml")).unwrap();
        config.database_path = root.join("store.db");
        config.socket_path = root.join("socket");
        config.admissions_dir = root.join("admissions");
        config.helper_runtime_dir = root.join("helpers");
        config.retention.horizon_seconds = 1;
        config.retention.reserve_bytes = Some(0);
        config.retention.auxiliary_bytes = Some(0);
        let watcher = &mut config.watchers[0];
        watcher.command.executable = PathBuf::from("/usr/bin/false");
        watcher.command.execution_account = nix::unistd::geteuid().as_raw().to_string();
        watcher.command.allow_same_identity_in_debug = true;
        watcher.command.working_directory = root.to_path_buf();
        let mut second = watcher.clone();
        second.instance_id = "host-second".into();
        config.watchers.push(second);
        let mut store = nq_store::Store::initialize_with_capacity(
            &config.database_path,
            config.retention.horizon_seconds,
            config.retention.byte_ceiling,
            Some(0),
            Some(0),
        )
        .unwrap();
        nq_core::engine::append_genesis(&mut store, None).unwrap();
        nq_core::engine::append_profile_descriptor(
            &mut store,
            nq_profiles::resolve_profile("nq.host", 1).unwrap(),
        )
        .unwrap();
        config
    }

    #[tokio::test]
    async fn stdio_watchers_share_retention_cadence_even_when_admission_refuses() {
        let root = tempfile::tempdir().unwrap();
        let config = stdio_fixture(root.path());
        let writer = Arc::new(Mutex::new(()));
        let shared = shared_stdio_engine(&config, writer.clone())
            .await
            .unwrap()
            .unwrap();
        for (index, watcher) in config.watchers.into_iter().enumerate() {
            let shared = shared.clone();
            let (outcome, attempt) = store_operation(writer.clone(), move || {
                let mut engine = shared.blocking_lock();
                let outcome = engine.collect(&watcher).unwrap();
                (outcome, engine.last_retention_attempt().cloned())
            })
            .await
            .unwrap();
            assert!(
                !outcome.is_success(),
                "unadmitted helper must remain refused"
            );
            if index == 0 {
                assert!(matches!(
                    attempt,
                    Some(nq_core::RetentionAttempt::Completed(_))
                ));
            } else {
                assert!(
                    matches!(attempt, Some(nq_core::RetentionAttempt::Deferred { .. })),
                    "the next watcher must reuse the store-wide retention cadence: {attempt:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn shared_stdio_owner_collects_and_sweeps_after_expiry() {
        let root = tempfile::tempdir().unwrap();
        let mut config = stdio_fixture(root.path());
        let script = root.path().join("helper.py");
        let load = root.path().join("load");
        std::fs::write(&script, include_str!("../tests/fixtures/host_load.py")).unwrap();
        std::fs::write(&load, "1.0\n").unwrap();
        std::fs::create_dir(&config.admissions_dir).unwrap();
        for watcher in &mut config.watchers {
            watcher.command.executable = PathBuf::from("/usr/bin/python3");
            watcher.command.args = vec![script.to_string_lossy().into_owned()];
            watcher.command.env.insert(
                "NQ_TEST_LOAD_FILE".into(),
                load.to_string_lossy().into_owned(),
            );
        }
        let seed_config = config.clone();
        store_operation(Arc::new(Mutex::new(())), move || {
            let mut engine = nq_core::CollectionEngine::open(&seed_config).unwrap();
            for watcher in &seed_config.watchers {
                engine
                    .watcher_action(watcher, "admit")
                    .expect("fixture helper must execute, not skip");
            }
            for index in 0..8 {
                assert!(
                    engine
                        .collect(&seed_config.watchers[index % 2])
                        .unwrap()
                        .is_success()
                );
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let writer = Arc::new(Mutex::new(()));
        // Install SQL accounting on the resident handle when it opens. Later
        // operations can count on whichever blocking worker executes them.
        let count_config = config.clone();
        let shared = store_operation(writer.clone(), move || {
            nq_store::start_sql_work_count();
            let shared = open_shared_stdio_engine(&count_config).unwrap().unwrap();
            nq_store::stop_sql_work_count();
            shared
        })
        .await
        .unwrap();
        // Register both real admitted acquisitions while the writer is held.
        // One gets an ordinary opportunity; the captured peer gets its turn.
        let permit = writer.clone().lock_owned().await;
        let mut acquisitions = JoinSet::new();
        for watcher in &config.watchers {
            let config = config.clone();
            let watcher = watcher.clone();
            let writer = writer.clone();
            let shared = shared.clone();
            acquisitions
                .spawn(async move { collect_one(config, watcher, writer, Some(shared)).await });
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while shared.queue.ready_count() != config.watchers.len() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both acquisitions must register before writer admission");
        drop(permit);
        while let Some(outcome) = acquisitions.join_next().await {
            assert!(outcome.unwrap().unwrap().is_success());
        }
        assert_eq!(shared.queue.ready_count(), 0);
        assert_eq!(
            shared.queue.opportunities(),
            1,
            "the captured ready cohort runs before another continuation opportunity"
        );
        assert!(
            shared.lock().await.last_retention_attempt().is_some(),
            "the collection path must use the supplied resident owner"
        );
        let mut work = Vec::new();
        for index in 0..24 {
            let engine = shared.clone();
            let watcher = config.watchers[index % 2].clone();
            let ticks = store_operation(writer.clone(), move || {
                nq_store::start_sql_work_count();
                let mut engine = engine.blocking_lock();
                let outcome = engine.collect(&watcher).unwrap();
                assert!(outcome.is_success());
                engine.freshness_sweep(&watcher).unwrap();
                let ticks = nq_store::stop_sql_work_count().unwrap();
                assert!(
                    !matches!(
                        engine.last_retention_attempt(),
                        Some(nq_core::RetentionAttempt::Refused { .. })
                    ),
                    "the shared owner must not contend with a peer or lose its certification"
                );
                ticks
            })
            .await
            .unwrap();
            work.push(ticks);
            if index % 8 == 7 {
                eprintln!(
                    "shared owner completed {} admitted collections and sweeps",
                    index + 1
                );
            }
        }
        let early: u64 = work[4..8].iter().sum();
        let late: u64 = work[20..24].iter().sum();
        eprintln!("shared stdio SQL work, early4={early}, late4={late}");
        assert!(
            late < early * 2,
            "settled work must not replay growing retained history"
        );
        drop(shared);
        let validation_config = config.clone();
        store_operation(writer, move || {
            let store =
                nq_store::Store::open_validating_fully(&validation_config.database_path).unwrap();
            assert!(
                store.retention_generation().unwrap() > 0,
                "fixture must actually expire history"
            );
            nq_core::engine::validate_fully_and_record(&store).unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn collection_tickets_follow_writer_cancellation_and_unwind() {
        let queue = collection_queue::CollectionQueue::default();
        let writer = Arc::new(Mutex::new(()));
        let permit = writer.clone().lock_owned().await;
        let ticket = queue.register();
        let waiting_writer = writer.clone();
        let waiting =
            tokio::spawn(
                async move { store_operation(waiting_writer, move || drop(ticket)).await },
            );
        tokio::task::yield_now().await;
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert_eq!(
            queue.ready_count(),
            0,
            "cancelled writer waiter retires its ticket"
        );
        drop(permit);

        let ticket = queue.register();
        let running_writer = writer.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let running = tokio::spawn(async move {
            store_operation(running_writer, move || {
                let _ticket = ticket;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await
        });
        started_rx.await.unwrap();
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert_eq!(
            queue.ready_count(),
            1,
            "a cancelled async observer cannot retire a running acquisition"
        );
        assert!(writer.try_lock().is_err());
        release_tx.send(()).unwrap();
        let permit = writer.clone().lock_owned().await;
        assert_eq!(
            queue.ready_count(),
            0,
            "ticket retires before writer release"
        );
        drop(permit);

        let ticket = queue.register();
        let result = store_operation(writer.clone(), move || {
            let _ticket = ticket;
            panic!("bounded blocking acquisition failure fixture");
        })
        .await;
        assert!(result.unwrap_err().is_panic());
        let _permit = writer.lock().await;
        assert_eq!(
            queue.ready_count(),
            0,
            "unwinding cannot pin a cohort forever"
        );
    }

    #[test]
    fn collection_ticket_survives_cancelled_observer_in_blocking_pool_queue() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let queue = collection_queue::CollectionQueue::default();
            let writer = Arc::new(Mutex::new(()));
            let (occupied_tx, occupied_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                occupied_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            occupied_rx.await.unwrap();
            let ticket = queue.register();
            let operation_writer = writer.clone();
            let queued = tokio::spawn(async move {
                store_operation(operation_writer, move || drop(ticket)).await
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if writer.try_lock().is_err() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            queued.abort();
            assert!(queued.await.unwrap_err().is_cancelled());
            assert_eq!(
                queue.ready_count(),
                1,
                "spawned blocking work owns the ticket"
            );
            release_tx.send(()).unwrap();
            blocker.await.unwrap();
            let _permit = writer.lock().await;
            assert_eq!(queue.ready_count(), 0);
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_drains_a_cancelled_waiters_blocking_operation() {
        let writer = Arc::new(Mutex::new(()));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut services = JoinSet::new();
        let operation_writer = writer.clone();
        services.spawn(async move {
            store_operation(operation_writer, move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await?;
            Ok(())
        });
        started_rx.await.unwrap();
        let (closed_tx, mut closed_rx) = tokio::sync::oneshot::channel();
        let drain = tokio::spawn(async move {
            let _permit = drain_store_operations(&mut services, writer).await;
            closed_tx.send(()).unwrap();
        });
        let waiting = tokio::time::timeout(Duration::from_millis(50), &mut closed_rx)
            .await
            .is_err();
        release_tx.send(()).unwrap();
        assert!(
            waiting,
            "shutdown must not claim closed while blocking collection still runs"
        );
        drain.await.unwrap();
    }

    #[tokio::test]
    async fn mixed_and_empty_configurations_do_not_share_a_resident_engine() {
        let root = tempfile::tempdir().unwrap();
        let mut config = stdio_fixture(root.path());
        config.watchers[1].carrier = nq_core::config::Carrier::Unix;
        let writer = Arc::new(Mutex::new(()));
        assert!(
            shared_stdio_engine(&config, writer.clone())
                .await
                .unwrap()
                .is_none()
        );
        config.watchers.clear();
        assert!(
            shared_stdio_engine(&config, writer)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_keeps_running_store_operation_serialized() {
        let writer = Arc::new(Mutex::new(()));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            store_operation(first_writer, move || {
                started_tx.send(()).expect("announce first operation");
                release_rx.recv().expect("release first operation");
            })
            .await
        });
        started_rx.await.expect("first operation started");
        first.abort();
        let _ = first.await;

        let (queued_tx, queued_rx) = tokio::sync::oneshot::channel();
        let (second_tx, mut second_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            queued_tx.send(()).expect("announce queued operation");
            store_operation(writer, move || {
                second_tx.send(()).expect("announce second operation");
                42
            })
            .await
        });
        queued_rx.await.expect("second operation queued");
        let still_waiting = tokio::time::timeout(Duration::from_millis(50), &mut second_rx)
            .await
            .is_err();
        // Release before asserting, including when the negative control fails.
        release_tx
            .send(())
            .expect("release original blocking operation");
        assert!(
            still_waiting,
            "cancelling a waiter released a running writer"
        );
        assert_eq!(
            second
                .await
                .expect("second task")
                .expect("second operation"),
            42
        );
    }

    #[tokio::test]
    async fn refused_operation_releases_queue_for_the_next_operation() {
        let writer = Arc::new(Mutex::new(()));
        assert_eq!(
            store_operation(writer.clone(), || Err::<(), _>("refused"))
                .await
                .unwrap(),
            Err("refused")
        );
        assert_eq!(store_operation(writer, || 7).await.unwrap(), 7);
    }

    #[test]
    fn daemon_cli_is_well_formed() {
        Nqd::command().debug_assert();
    }

    #[test]
    fn console_address_is_absent_by_default() {
        let parsed =
            Nqd::try_parse_from(["nqd", "--config=/etc/nq/nq.toml"]).expect("minimal args parse");
        assert!(
            parsed.console_address.is_none(),
            "the loopback console must be off unless explicitly configured"
        );
    }

    #[test]
    fn daemon_result_document_preserves_same_code_refusal_payloads() {
        let outcome = |run_id: &str, refusal_id: &str, retriable, details| {
            CollectionOutcome::rejected(
                "daemon-transport".to_owned(),
                run_id.to_owned(),
                GovernedRefusal::helper(
                    refusal_id.to_owned(),
                    Refusal {
                        responsible_instance_id: InstanceId::new("daemon-transport")
                            .expect("instance token"),
                        boundary: RefusalBoundary::Collection,
                        code: RefusalCode::CollectionFailed,
                        message: "backend collection failed".to_owned(),
                        retriable,
                        details,
                    },
                ),
            )
        };
        let transient = outcome(
            "run-transient",
            "refusal-transient",
            true,
            json!({"attempt": 1, "errno": "EAGAIN"}),
        );
        let permanent = outcome(
            "run-permanent",
            "refusal-permanent",
            false,
            json!({"device": "nvme0", "errno": "ENODEV"}),
        );
        let transient_value = serde_json::to_value(&transient).expect("transient serializes");
        let permanent_value = serde_json::to_value(&permanent).expect("permanent serializes");
        assert_ne!(
            transient_value["result"]["refusal"]["refusal_id"],
            permanent_value["result"]["refusal"]["refusal_id"]
        );

        let transient_log = canonical_result_document(&transient).expect("canonical log document");
        let permanent_log = canonical_result_document(&permanent).expect("canonical log document");
        assert_eq!(
            transient_log.into_bytes(),
            nq_protocol::canonical_json_bytes(&transient).expect("canonical transient")
        );
        assert_eq!(
            permanent_log.into_bytes(),
            nq_protocol::canonical_json_bytes(&permanent).expect("canonical permanent")
        );
        assert_ne!(
            nq_protocol::canonical_json_bytes(&transient).expect("canonical transient"),
            nq_protocol::canonical_json_bytes(&permanent).expect("canonical permanent")
        );
    }

    /// A startup refusal exits 1; the packaged unit must bound restarts so a
    /// refusing store cannot restart-loop forever (NQ #27 audit G1).
    #[test]
    fn packaged_unit_bounds_restart_attempts() {
        const UNIT: &str = include_str!("../../../packaging/systemd/nqd.service");
        let unit_section = UNIT
            .split("[Service]")
            .next()
            .expect("unit section precedes service section");
        assert!(
            unit_section
                .lines()
                .any(|line| line == "StartLimitIntervalSec=300")
        );
        assert!(unit_section.lines().any(|line| line == "StartLimitBurst=5"));
        assert!(UNIT.lines().any(|line| line == "Restart=on-failure"));
    }

    /// Default packaged startup must expose no host-local INET listener: the
    /// shipped unit carries no console address, and parsing its exact nqd
    /// invocation yields none.
    #[test]
    fn packaged_unit_exposes_no_loopback_listener_by_default() {
        const UNIT: &str = include_str!("../../../packaging/systemd/nqd.service");
        let exec = UNIT
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .expect("packaged unit has an ExecStart line");
        assert!(
            !exec.contains("--console-address"),
            "packaged ExecStart must not enable the loopback console: {exec}"
        );
        let args = std::iter::once("nqd").chain(exec.split_whitespace().skip(1));
        let parsed = Nqd::try_parse_from(args).expect("packaged nqd args parse");
        assert!(
            parsed.console_address.is_none(),
            "packaged startup must not configure a loopback console"
        );
    }

    /// The helper runtime root must be exactly `0711`: the supervisor refuses
    /// to prepare a private helper directory under any other mode.
    ///
    /// `RuntimeDirectoryMode=` applies to every `RuntimeDirectory=` entry, and
    /// systemd re-applies that setup before each `Exec` command. Listing the
    /// helper root there therefore overwrites the mode set by `ExecStartPre`,
    /// and the overwrite is silent until a collection actually fails.
    ///
    /// Regression: the 2026-07-19 sealed VM run refused at
    /// `explicit-service-lifecycle` because `/run/nq/helpers` was observed at
    /// `0o0751` when the supervisor required exactly `0o0711`.
    #[test]
    fn packaged_unit_does_not_let_systemd_govern_the_helper_runtime_root() {
        const UNIT: &str = include_str!("../../../packaging/systemd/nqd.service");
        const HELPER_ROOT: &str = "/run/nq/helpers";

        let managed: Vec<&str> = UNIT
            .lines()
            .filter_map(|line| line.strip_prefix("RuntimeDirectory="))
            .flat_map(str::split_whitespace)
            .collect();
        assert!(
            !managed.contains(&"nq/helpers"),
            "systemd must not manage the helper runtime root; \
             RuntimeDirectoryMode would overwrite its required 0711: {managed:?}"
        );
        assert!(
            managed.contains(&"nq"),
            "the daemon runtime directory must still be declared: {managed:?}"
        );

        // The helper root must instead be provisioned explicitly, at exactly
        // 0711, by a privileged pre-start step.
        let provisioning = UNIT
            .lines()
            .filter_map(|line| line.strip_prefix("ExecStartPre="))
            .find(|line| line.contains(HELPER_ROOT))
            .expect("packaged unit must provision the helper runtime root");
        assert!(
            provisioning.starts_with('+'),
            "helper-root provisioning must run privileged: {provisioning}"
        );
        assert!(
            provisioning.contains("-m 0711"),
            "helper runtime root must be provisioned at exactly 0711: {provisioning}"
        );
    }
}
