//! Resident scheduler, local API, and helper supervisor entry point.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nq_core::config::{NqConfig, WatcherConfig};
use tokio::sync::watch;
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
    let mut store = nq_store::Store::open(&config.database_path).context(
        "database is absent or has an incompatible schema; run `nq init` or `nq admin upgrade`",
    )?;
    store.validate()?;
    // Refuse typed provider-history substitution before the daemon mutates
    // status history or binds any listener. Store validation authenticates
    // canonical bytes and relational links; this core pass additionally
    // proves request/raw/native-outcome semantic correspondence.
    nq_core::engine::validate_provider_intake_history(&store)
        .context("provider-intake history failed typed startup verification")?;
    validate_catalog(&config)?;
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
    let mut ready_store = nq_store::Store::open(&config.database_path)?;
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
    for watcher in config.watchers.clone() {
        let config = config.clone();
        let shutdown = shutdown_rx.clone();
        services.spawn(async move { schedule_instance(config, watcher, shutdown).await });
    }
    for watcher in config.watchers.clone() {
        let config = config.clone();
        let shutdown = shutdown_rx.clone();
        services.spawn(async move { sweep_freshness(config, watcher, shutdown).await });
    }

    info!(instances = config.watchers.len(), "nqd started");
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("cannot listen for shutdown signal")?;
            info!("shutdown requested");
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
    services.abort_all();
    while services.join_next().await.is_some() {}
    let mut stopped_store = nq_store::Store::open(&config.database_path)?;
    nq_core::engine::record_component_status(
        &mut stopped_store,
        "daemon",
        "nqd",
        "unknown",
        "stopped",
        &serde_json::json!({"pid": std::process::id()}),
    )?;
    Ok(())
}

async fn collect_once(config: NqConfig) -> Result<()> {
    let mut tasks = JoinSet::new();
    for watcher in config.watchers.clone() {
        let config = config.clone();
        tasks.spawn(async move { collect_one(config, watcher).await });
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

async fn schedule_instance(
    config: NqConfig,
    watcher: WatcherConfig,
    mut shutdown: watch::Receiver<bool>,
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

    let mut engine =
        tokio::task::spawn_blocking(move || nq_core::CollectionEngine::open(&config)).await??;
    let mut backoff = watcher.schedule.retry_backoff_seconds;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let collection_watcher = watcher.clone();
        let (returned_engine, outcome) = tokio::task::spawn_blocking(move || {
            let outcome = engine.collect(&collection_watcher);
            (engine, outcome)
        })
        .await?;
        engine = returned_engine;
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
            Err(error) => {
                error!(instance = %watcher.instance_id, %error, "collection engine error");
                let delay = backoff.max(1);
                backoff = backoff
                    .saturating_mul(2)
                    .min(watcher.schedule.max_retry_backoff_seconds.max(1));
                delay
            }
        };
        let (returned_engine, shutdown_requested) =
            wait_with_binding_watch(engine, &watcher, Duration::from_secs(delay), &mut shutdown)
                .await?;
        engine = returned_engine;
        if shutdown_requested {
            return Ok(());
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
) -> Result<nq_core::CollectionOutcome> {
    Ok(tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.collect(&watcher)
    })
    .await??)
}

async fn sweep_freshness(
    config: NqConfig,
    watcher: WatcherConfig,
    mut shutdown: watch::Receiver<bool>,
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
        let result = tokio::task::spawn_blocking(move || {
            let mut engine = nq_core::CollectionEngine::open(&sweep_config)?;
            engine.freshness_sweep(&sweep_watcher)
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
