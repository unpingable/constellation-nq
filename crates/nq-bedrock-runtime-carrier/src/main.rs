//! BEDROCK inert runtime carrier entry point.

use clap::Parser;
use nq_bedrock_runtime_carrier::{
    ProcessRunner, ReleaseDecision, hold_until_release, reconcile_unknown,
};
use nq_protocol::Sha256Digest;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "nq-bedrock-runtime-carrier")]
struct Cli {
    #[arg(long, default_value = "/run/nq/binding.json")]
    binding: PathBuf,
    #[arg(long, default_value = "/run/nq/release.json")]
    release: PathBuf,
    #[arg(long, default_value = "/var/lib/nq/carrier/state.sqlite3")]
    state: PathBuf,
    #[arg(long, default_value = "/usr/bin/nq")]
    executable: PathBuf,
    /// Bounded fixture mode only; production hold has no timeout.
    #[arg(long)]
    max_wait_ms: Option<u64>,
    /// Exact claimed release to reconcile without re-invocation.
    #[arg(long, requires = "outcome_evidence_digest")]
    reconcile_release_id: Option<String>,
    /// Exact retained evidence supporting explicit outcome resolution.
    #[arg(long, requires = "reconcile_release_id")]
    outcome_evidence_digest: Option<String>,
    /// Known exit code for explicit outcome resolution; omission retains none.
    #[arg(long)]
    exit_code: Option<i32>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let (Some(release), Some(evidence)) =
        (&cli.reconcile_release_id, &cli.outcome_evidence_digest)
    {
        let Ok(release) = Sha256Digest::parse(release.clone()) else {
            eprintln!("nq-bedrock-runtime-carrier: malformed release identity");
            return ExitCode::FAILURE;
        };
        let Ok(evidence) = Sha256Digest::parse(evidence.clone()) else {
            eprintln!("nq-bedrock-runtime-carrier: malformed outcome evidence identity");
            return ExitCode::FAILURE;
        };
        return match reconcile_unknown(&cli.state, &release, cli.exit_code, &evidence) {
            Ok(ReleaseDecision::AlreadyComplete { .. }) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("nq-bedrock-runtime-carrier: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let mut runner = ProcessRunner;
    match hold_until_release(
        &cli.binding,
        &cli.release,
        &cli.state,
        &cli.executable,
        cli.max_wait_ms.map(Duration::from_millis),
        &mut runner,
    ) {
        Ok(Some(ReleaseDecision::Invoked {
            exit_code: Some(0), ..
        })) => ExitCode::SUCCESS,
        Ok(Some(ReleaseDecision::AlreadyComplete { .. })) => {
            eprintln!("release already complete; no invocation");
            ExitCode::SUCCESS
        }
        Ok(Some(ReleaseDecision::InFlight { .. })) => {
            eprintln!("release invocation is still in flight; no reconciliation allowed");
            ExitCode::from(77)
        }
        Ok(Some(ReleaseDecision::OutcomeUnknown { .. })) => {
            eprintln!("release outcome unknown; explicit reconciliation required");
            ExitCode::from(76)
        }
        Ok(None) => {
            eprintln!("inert timeout; no release and no invocation");
            ExitCode::from(75)
        }
        Ok(Some(ReleaseDecision::Invoked { exit_code, .. })) => {
            eprintln!("exact invocation did not succeed: {exit_code:?}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("nq-bedrock-runtime-carrier: {error}");
            ExitCode::FAILURE
        }
    }
}
