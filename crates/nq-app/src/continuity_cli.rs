//! Bounded factual projection of exact externally acquired Continuity bytes.
use anyhow::Result;
use std::{io::Read, path::Path};
pub fn run(record: &Path, binding: &Path) -> Result<()> {
    let mut raw = Vec::new();
    std::fs::File::open(record)?
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    let mut policy = Vec::new();
    std::fs::File::open(binding)?
        .take(16385)
        .read_to_end(&mut policy)?;
    anyhow::ensure!(policy.len() <= 16384, "binding exceeds16KiB");
    let binding = nq_protocol::decode_json_document(&policy, 16384)?;
    let receipt =
        nq_core::continuity_support::qualify(&raw, &binding).map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        String::from_utf8(nq_protocol::canonical_json_bytes(&receipt)?)?
    );
    Ok(())
}
