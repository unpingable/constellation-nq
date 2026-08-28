//! Closed passive host-load sampler and immutable-sample provider entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "nq-passive-load-helper")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the bounded long-lived sampler until its finite store is exhausted.
    Observe { config: PathBuf },
    /// Produce exactly one signed sample, primarily for bounded qualification.
    SampleOnce { config: PathBuf },
    /// Serve one NQ request over stdin/stdout using only pre-existing samples.
    ServeStdio { config: PathBuf },
    /// Reconstruct derived selection metadata from canonical retained samples.
    ReconstructSelectionIndex { config: PathBuf },
    /// Inspect the exact local `available_parallelism()` context without sampling.
    InspectCapacityContext,
    /// Create one raw Ed25519 signing key with mode 0600.
    Keygen {
        private_key: PathBuf,
        issuer: String,
        key_id: String,
    },
    /// Materialize one immutable finite observer generation.
    PrepareGeneration {
        policy: PathBuf,
        spec: PathBuf,
        output: PathBuf,
        #[arg(long)]
        previous_generation: Option<PathBuf>,
    },
    /// Run one bounded long-lived observer generation.
    ObserveGeneration {
        policy: PathBuf,
        generation: PathBuf,
    },
    /// Evaluate one sampling slot without starting a loop.
    SampleOnceGeneration {
        policy: PathBuf,
        generation: PathBuf,
    },
    /// Project immutable observer-generation state without sampling.
    GenerationStatus {
        policy: PathBuf,
        generation: PathBuf,
    },
    /// Check existing generation-store custody without sampling or traversal.
    GenerationStoreReadiness { generation: PathBuf },
    /// Retire one generation without deleting its samples.
    RetireGeneration {
        generation: PathBuf,
        operation_id: String,
        reason: String,
    },
    /// Revoke one generation's signing key for future sampling only.
    RevokeGenerationKey {
        generation: PathBuf,
        operation_id: String,
        reason: String,
    },
}

fn main() -> ExitCode {
    match nq_build_info::write_if_requested("nq-passive-load-helper", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return ExitCode::SUCCESS,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nq-passive-load-helper: cannot write build information: {error}");
            return ExitCode::FAILURE;
        }
    }
    let result = match Cli::parse().command {
        Command::Observe { config } => nq_passive_load_helper::observe(&config),
        Command::SampleOnce { config } => nq_passive_load_helper::sample_once(&config).map(|_| ()),
        Command::ServeStdio { config } => nq_passive_load_helper::serve_stdio(&config),
        Command::ReconstructSelectionIndex { config } => {
            nq_passive_load_helper::reconstruct_selection_index(&config)
        }
        Command::InspectCapacityContext => nq_passive_load_helper::inspect_capacity_context(),
        Command::Keygen {
            private_key,
            issuer,
            key_id,
        } => nq_passive_load_helper::keygen(&private_key, &issuer, &key_id),
        Command::PrepareGeneration {
            policy,
            spec,
            output,
            previous_generation,
        } => nq_passive_load_helper::materialize_generation(
            &policy,
            &spec,
            previous_generation.as_deref(),
            &output,
        )
        .map(|generation| {
            let bytes = std::fs::read(&output).expect("materialized generation must reopen");
            println!(
                "{}",
                serde_json::json!({
                    "schema": "nq.passive_load_observer_generation_materialization.v1",
                    "generation_id": nq_protocol::sha256_bytes(&bytes),
                    "generation": generation,
                })
            );
        }),
        Command::ObserveGeneration { policy, generation } => {
            nq_passive_load_helper::observe_generation(&policy, &generation)
        }
        Command::SampleOnceGeneration { policy, generation } => {
            nq_passive_load_helper::sample_once_generation(&policy, &generation).map(|action| {
                println!(
                    "{}",
                    serde_json::to_string(&action).expect("sampling action must serialize")
                );
            })
        }
        Command::GenerationStatus { policy, generation } => {
            nq_passive_load_helper::generation_status(&policy, &generation).map(|status| {
                println!(
                    "{}",
                    serde_json::to_string(&status).expect("generation status must serialize")
                );
            })
        }
        Command::GenerationStoreReadiness { generation } => {
            nq_passive_load_helper::generation_store_readiness(&generation).map(|readiness| {
                println!(
                    "{}",
                    serde_json::to_string(&readiness)
                        .expect("generation-store readiness must serialize")
                );
            })
        }
        Command::RetireGeneration {
            generation,
            operation_id,
            reason,
        } => nq_passive_load_helper::retire_generation(&generation, &operation_id, &reason)
            .map(|event_id| println!("{{\"event_id\":\"{event_id}\",\"state\":\"retired\"}}")),
        Command::RevokeGenerationKey {
            generation,
            operation_id,
            reason,
        } => nq_passive_load_helper::revoke_generation_key(&generation, &operation_id, &reason)
            .map(|event_id| {
                println!("{{\"event_id\":\"{event_id}\",\"state\":\"key_revoked\"}}");
            }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nq-passive-load-helper: {error}");
            ExitCode::from(2)
        }
    }
}
