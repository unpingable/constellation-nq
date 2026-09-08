//! Offline compiled predicate admission and exact replay.
use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use nq_core::fixed_queue;
use serde_json::{Value, json};
use std::{fs, io::Read, path::PathBuf};

#[derive(Debug, Subcommand)]
pub enum QueueCommand {
    Admit(Inputs),
    Replay(Inputs),
    SupportEvaluate(Inputs),
}

#[derive(Debug, Args)]
pub struct Inputs {
    #[arg(long)]
    inventory: PathBuf,
    #[arg(long)]
    profiles: PathBuf,
    #[arg(long)]
    receipt: Option<PathBuf>,
    #[arg(long)]
    facts: Option<PathBuf>,
    #[arg(long)]
    catalog_digest: Option<String>,
    #[arg(long)]
    concern: Option<String>,
    #[arg(long)]
    evaluated_at: Option<String>,
    #[arg(long)]
    output: PathBuf,
}

fn read(path: &PathBuf) -> Result<Value> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        bail!("artifact exceeds 2 MiB");
    }
    Ok(nq_protocol::decode_json_document(&bytes, 2 * 1024 * 1024)?)
}

pub fn run(command: QueueCommand) -> Result<()> {
    let (mode, a) = match command {
        QueueCommand::Admit(a) => (0, a),
        QueueCommand::Replay(a) => (1, a),
        QueueCommand::SupportEvaluate(a) => (2, a),
    };
    let inventory = read(&a.inventory)?;
    let catalog = read(&a.profiles)?;
    let value = if mode == 0 {
        fixed_queue::admit(
            &inventory,
            &catalog,
            a.catalog_digest
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--catalog-digest required"))?,
            a.concern
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--concern required"))?,
            a.evaluated_at
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--evaluated-at required"))?,
        )
        .map_err(anyhow::Error::msg)?
    } else {
        let receipt = read(
            a.receipt
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--receipt required"))?,
        )?;
        if mode == 1 {
            let matches =
                fixed_queue::replay(&receipt, &inventory, &catalog).map_err(anyhow::Error::msg)?;
            json!({"schema":"nq.bounded-predicate-replay/v1","matches":matches,"expected_receipt_digest":receipt["receipt_digest"]})
        } else {
            fixed_queue::support(
                &receipt,
                &inventory,
                &catalog,
                &read(
                    a.facts
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("--facts required"))?,
                )?,
            )
            .map_err(anyhow::Error::msg)?
        }
    };
    let bytes = nq_protocol::canonical_json_bytes(&value)?;
    if a.output.as_os_str() == "-" {
        println!("{}", String::from_utf8(bytes)?);
    } else {
        fs::write(a.output, bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read;
    #[test]
    fn duplicate_profile_keys_are_refused_before_canonicalization() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("catalog.json");
        std::fs::write(&path, br#"{"profiles":[{"id":"first","id":"second"}]}"#).unwrap();
        assert!(read(&path).unwrap_err().to_string().contains("duplicate"));
        std::fs::write(&path, br#"{"profiles":[{"id":"only"}]}"#).unwrap();
        assert!(read(&path).is_ok());
    }
}
