//! Resident read surface and explicitly bounded one-shot entry point.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use nq_core::config::{NqConfig, WatcherConfig};
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

    info!(
        instances = config.watchers.len(),
        "nqd started without recurrence; bounded diagnostics require an explicit request"
    );
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
            Ok(Ok(outcome)) if outcome.has_admitted_usable_report() => {
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
    fn resident_and_read_surfaces_cannot_create_recurrent_provider_work() {
        fn production(source: &'static str) -> &'static str {
            source.split("#[cfg(test)]").next().unwrap_or(source)
        }

        let daemon = production(include_str!("daemon.rs"));
        for (left, right) in [
            ("schedule_", "instance"),
            ("sweep_", "freshness"),
            ("tokio::time::", "sleep"),
            ("retry_backoff_", "seconds"),
            ("interval_", "seconds"),
            ("jitter_", "seconds"),
        ] {
            let forbidden = format!("{left}{right}");
            assert!(
                !daemon.contains(&forbidden),
                "resident NQ must not own Nightshift recurrence token {forbidden}"
            );
        }
        assert!(
            daemon.contains("if options.once {")
                && daemon.contains("return collect_once(config).await;"),
            "the only daemon collection path must remain explicitly gated by --once"
        );
        assert_eq!(
            daemon.matches("collect_one(config, watcher)").count(),
            1,
            "daemon startup or restart must not add another provider invocation path"
        );

        let api = production(include_str!("api.rs"));
        for forbidden in ["CollectionEngine", "diagnostic_execute", "collect_one"] {
            assert!(
                !api.contains(forbidden),
                "the resident read API must not invoke diagnostics through {forbidden}"
            );
        }

        let config = production(include_str!("../../nq-core/src/config.rs"));
        for (left, right) in [
            ("Schedule", "Config"),
            ("interval_", "seconds"),
            ("jitter_", "seconds"),
            ("retry_backoff_", "seconds"),
            ("max_retry_backoff_", "seconds"),
        ] {
            let forbidden = format!("{left}{right}");
            assert!(
                !config.contains(&forbidden),
                "current NQ configuration must not accept recurrence field {forbidden}"
            );
        }

        let intake = production(include_str!("../../nq-core/src/provider_intake.rs"));
        for (left, right) in [
            ("Command::", "new"),
            (".sp", "awn("),
            ("run_", "capture("),
            (".col", "lect("),
        ] {
            let forbidden = format!("{left}{right}");
            assert!(
                !intake.contains(&forbidden),
                "provider intake testimony must not launch or recur through {forbidden}"
            );
        }

        for source in [
            daemon,
            api,
            production(include_str!("cli.rs")),
            production(include_str!("archive.rs")),
        ] {
            for (left, right) in [("\"sched", "uler\""), ("\"notific", "ation\"")] {
                let forbidden = format!("{left}{right}");
                assert!(
                    !source.contains(&forbidden),
                    "current NQ application code must not emit legacy {forbidden} status"
                );
            }
        }
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
