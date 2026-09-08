//! Read-only local-store purpose support; no imported artifact fallback.
use anyhow::Result;
use std::{io::Read, path::Path};

pub fn run(config_path: &Path, request_path: &Path) -> Result<()> {
    let config = nq_core::config::NqConfig::load(config_path)?;
    let mut bytes = Vec::new();
    std::fs::File::open(request_path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "request exceeds 64KiB");
    let request: nq_core::purpose_support::PurposeRequest = serde_json::from_slice(&bytes)?;
    let store = nq_store::Store::open_read_only(&config.database_path)?;
    let result = nq_core::purpose_support::qualify(&store, &request).map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        String::from_utf8(nq_protocol::canonical_json_bytes(&result)?)?
    );
    Ok(())
}
