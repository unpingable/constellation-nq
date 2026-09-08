//! Read-only transport for compiled stage predicates; does not dispatch effects.
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use nq_core::{stage_qualification as q, stage_realization as r};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Subcommand)]
pub enum StageCommand {
    /// Evaluate exact factual testimony, never caller-authored verdicts.
    Evaluate(Evaluate),
    /// Reproduce an exact historical receipt without renewing its time.
    Replay(Replay),
}

#[derive(Debug, Args)]
pub struct Evaluate {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    evidence: PathBuf,
    #[arg(long)]
    evaluated_at_unix_ms: u64,
    #[arg(long, default_value = "-")]
    output: String,
}

#[derive(Debug, Args)]
pub struct Replay {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    evidence: PathBuf,
    #[arg(long)]
    receipt: PathBuf,
    #[arg(long, default_value = "-")]
    output: String,
}

pub fn run(command: StageCommand, realization: bool) -> Result<()> {
    let evaluator = identity(realization)?;
    match command {
        StageCommand::Evaluate(args) => {
            if realization {
                write(
                    &args.output,
                    &r::evaluate_campaign_stage_realization(
                        &read(&args.profile)?,
                        &read(&args.evidence)?,
                        &evaluator,
                        args.evaluated_at_unix_ms,
                    ),
                )
            } else {
                write(
                    &args.output,
                    &q::evaluate_campaign_stage_qualification(
                        &read(&args.profile)?,
                        &read(&args.evidence)?,
                        &evaluator,
                        args.evaluated_at_unix_ms,
                    ),
                )
            }
        }
        StageCommand::Replay(args) => {
            let matches = if realization {
                let receipt: r::CampaignStageRealizationReceiptV2 = read(&args.receipt)?;
                check_identity(
                    &evaluator,
                    &receipt.evaluator_id,
                    &receipt.evaluator_version,
                    &receipt.evaluator_executable_sha256,
                )?;
                let replay = r::replay_campaign_stage_realization(
                    &read(&args.profile)?,
                    &read(&args.evidence)?,
                    &receipt,
                );
                write(&args.output, &replay)?;
                replay.matches
            } else {
                let receipt: q::CampaignStageQualificationReceiptV1 = read(&args.receipt)?;
                check_identity(
                    &evaluator,
                    &receipt.evaluator_id,
                    &receipt.evaluator_version,
                    &receipt.evaluator_executable_sha256,
                )?;
                let replay = q::replay_campaign_stage_qualification(
                    &read(&args.profile)?,
                    &read(&args.evidence)?,
                    &receipt,
                );
                write(&args.output, &replay)?;
                replay.matches
            };
            if !matches {
                bail!("stage replay did not reproduce the exact receipt");
            }
            Ok(())
        }
    }
}

fn identity(realization: bool) -> Result<q::QualificationEvaluatorIdentityV1> {
    // On Linux this reads the executing inode, including after pathname replacement.
    #[cfg(target_os = "linux")]
    let path = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let path = std::env::current_exe()?;
    Ok(q::QualificationEvaluatorIdentityV1 {
        evaluator_id: if realization {
            r::EVALUATOR_ID
        } else {
            q::EVALUATOR_ID
        }
        .into(),
        evaluator_version: env!("CARGO_PKG_VERSION").into(),
        executable_sha256: nq_protocol::sha256_bytes(&std::fs::read(path)?).into_string(),
    })
}

fn check_identity(
    e: &q::QualificationEvaluatorIdentityV1,
    id: &str,
    version: &str,
    digest: &str,
) -> Result<()> {
    if e.evaluator_id != id || e.evaluator_version != version || e.executable_sha256 != digest {
        bail!("receipt evaluator does not match the executing NQ-ng build");
    }
    Ok(())
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    const LIMIT: u64 = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("stage document exceeds 4 MiB bound");
    }
    nq_protocol::decode_json_document(&bytes, 2 * 1024 * 1024)
        .with_context(|| format!("parsing {}", path.display()))
}

fn write<T: Serialize>(path: &str, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if path == "-" {
        std::io::stdout().write_all(&bytes)?;
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(&bytes)?;
    }
    Ok(())
}
