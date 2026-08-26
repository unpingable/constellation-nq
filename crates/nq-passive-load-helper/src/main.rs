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
    /// Inspect the exact local `available_parallelism()` context without sampling.
    InspectCapacityContext,
    /// Create one raw Ed25519 signing key with mode 0600.
    Keygen {
        private_key: PathBuf,
        issuer: String,
        key_id: String,
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
        Command::InspectCapacityContext => nq_passive_load_helper::inspect_capacity_context(),
        Command::Keygen {
            private_key,
            issuer,
            key_id,
        } => nq_passive_load_helper::keygen(&private_key, &issuer, &key_id),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nq-passive-load-helper: {error}");
            ExitCode::from(2)
        }
    }
}
