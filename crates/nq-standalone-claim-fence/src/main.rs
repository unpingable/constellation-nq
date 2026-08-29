//! Standalone NQ claim/fence CLI.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nq_protocol::canonical_json_bytes;
use nq_standalone_claim_fence::{ClaimFence, ClaimRequestV1, TransitionRequestV1};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, Parser)]
#[command(name = "nq-claim-fence")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create or exactly reopen one immutable occurrence claim.
    Claim { state: PathBuf, request: PathBuf },
    /// Advance one exact fence/release/outcome transition.
    Transition { state: PathBuf, request: PathBuf },
}

fn read_exact<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let value: T = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if canonical_json_bytes(&value).map_err(|error| error.to_string())? != bytes {
        return Err("request is not exact RFC 8785 JSON".into());
    }
    Ok(value)
}

fn print_receipt<T: Serialize>(value: &T) -> Result<(), String> {
    let mut bytes = canonical_json_bytes(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    io::stdout()
        .write_all(&bytes)
        .map_err(|error| error.to_string())
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Claim { state, request } => {
            let request: ClaimRequestV1 = read_exact(&request)?;
            let mut interface = ClaimFence::open(&state).map_err(|error| error.to_string())?;
            let receipt = interface
                .claim(&request)
                .map_err(|error| error.to_string())?;
            print_receipt(&receipt)
        }
        Command::Transition { state, request } => {
            let request: TransitionRequestV1 = read_exact(&request)?;
            let mut interface = ClaimFence::open(&state).map_err(|error| error.to_string())?;
            let receipt = interface
                .transition(&request)
                .map_err(|error| error.to_string())?;
            print_receipt(&receipt)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nq-claim-fence: {error}");
            ExitCode::FAILURE
        }
    }
}
