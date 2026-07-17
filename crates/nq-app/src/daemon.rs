//! Resident scheduler, local API, and helper supervisor entry point.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nq_core::config::{NqConfig, WitnessConfig};
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
    /// Optional loopback console address. The Unix API is always enabled.
    #[arg(long, default_value = "127.0.0.1:8787")]
    pub console_address: String,
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
pub async fn run(options: Nqd) -> Result<()> {
    initialize_tracing();
    let config = NqConfig::load(&options.config)
        .with_context(|| format!("cannot load {}", options.config.display()))?;
    let _database_ownership = crate::ownership::acquire(&config.database_path, "nqd")?;
    let mut store = nq_store::Store::open(&config.database_path).context(
        "database is absent or has an incompatible schema; run `nq init` or `nq admin upgrade`",
    )?;
    store.validate()?;
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
        &serde_json::json!({"instance_count": config.witnesses.len()}),
    )?;
    drop(store);

    if options.once {
        return collect_once(config).await;
    }

    let console_address = crate::api::parse_loopback(&options.console_address)?;
    let unix_listener = crate::api::bind_unix(&config.socket_path)?;
    let loopback_listener = crate::api::bind_loopback(console_address).await?;
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
        &serde_json::json!({"instance_count": config.witnesses.len()}),
    )?;
    drop(ready_store);
    let mut services = JoinSet::new();
    let database_path = config.database_path.clone();
    services
        .spawn(async move { crate::api::serve_unix_listener(unix_listener, database_path).await });
    let database_path = config.database_path.clone();
    services.spawn(async move {
        crate::api::serve_loopback_listener(loopback_listener, database_path).await
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    for witness in config.witnesses.clone() {
        let config = config.clone();
        let shutdown = shutdown_rx.clone();
        services.spawn(async move { schedule_instance(config, witness, shutdown).await });
    }
    for witness in config.witnesses.clone() {
        let config = config.clone();
        let shutdown = shutdown_rx.clone();
        services.spawn(async move { sweep_freshness(config, witness, shutdown).await });
    }

    info!(instances = config.witnesses.len(), "nqd started");
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
    for witness in config.witnesses.clone() {
        let config = config.clone();
        tasks.spawn(async move { collect_one(config, witness).await });
    }
    let mut failures = 0;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(outcome)) if outcome.is_success() => {
                info!(instance = %outcome.instance_id(), "collection admitted");
            }
            Ok(Ok(outcome)) => {
                failures += 1;
                warn!(instance = %outcome.instance_id(), ?outcome, "collection did not admit a report");
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
    witness: WitnessConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let jitter_cap = witness.schedule.jitter_seconds;
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
    let mut backoff = witness.schedule.retry_backoff_seconds;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let collection_witness = witness.clone();
        let (returned_engine, outcome) = tokio::task::spawn_blocking(move || {
            let outcome = engine.collect(&collection_witness);
            (engine, outcome)
        })
        .await?;
        engine = returned_engine;
        let delay = match outcome {
            Ok(outcome) if outcome.is_success() => {
                backoff = witness.schedule.retry_backoff_seconds;
                info!(instance = %witness.instance_id, "collection admitted and evaluated");
                witness.schedule.interval_seconds
            }
            Ok(outcome) => {
                warn!(instance = %witness.instance_id, ?outcome, "collection retained without admitted report");
                let delay = backoff.max(1);
                backoff = backoff
                    .saturating_mul(2)
                    .min(witness.schedule.max_retry_backoff_seconds.max(1));
                delay
            }
            Err(error) => {
                error!(instance = %witness.instance_id, %error, "collection engine error");
                let delay = backoff.max(1);
                backoff = backoff
                    .saturating_mul(2)
                    .min(witness.schedule.max_retry_backoff_seconds.max(1));
                delay
            }
        };
        let (returned_engine, shutdown_requested) =
            wait_with_binding_watch(engine, &witness, Duration::from_secs(delay), &mut shutdown)
                .await?;
        engine = returned_engine;
        if shutdown_requested {
            return Ok(());
        }
    }
}

async fn wait_with_binding_watch(
    mut engine: nq_core::CollectionEngine,
    witness: &WitnessConfig,
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
        let check_witness = witness.clone();
        let (returned_engine, quiesced) = tokio::task::spawn_blocking(move || {
            let result = engine.quiesce_if_binding_changed(&check_witness);
            (engine, result)
        })
        .await?;
        engine = returned_engine;
        if quiesced? {
            warn!(
                instance = %witness.instance_id,
                "persistent helper quiesced after admission binding changed"
            );
        }
    }
}

async fn collect_one(
    config: NqConfig,
    witness: WitnessConfig,
) -> Result<nq_core::CollectionOutcome> {
    Ok(tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.collect(&witness)
    })
    .await??)
}

async fn sweep_freshness(
    config: NqConfig,
    witness: WitnessConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let profile = nq_profiles::resolve_profile(&witness.profile.id, witness.profile.version)
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
        let sweep_witness = witness.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut engine = nq_core::CollectionEngine::open(&sweep_config)?;
            engine.freshness_sweep(&sweep_witness)
        })
        .await?;
        match result {
            Ok(count) => tracing::debug!(
                instance = %witness.instance_id,
                evaluations = count,
                "freshness sweep committed"
            ),
            Err(error) => warn!(instance = %witness.instance_id, %error, "freshness sweep failed"),
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

    use super::*;

    #[test]
    fn daemon_cli_is_well_formed() {
        Nqd::command().debug_assert();
    }
}
