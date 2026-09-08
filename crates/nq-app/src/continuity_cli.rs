//! Bounded factual projection of exact externally acquired Continuity bytes.
use anyhow::Result;
use std::path::Path;
pub fn run(record: &Path, binding: &Path, history: &Path) -> Result<()> {
    let raw = crate::bounded_input::read(record, 2 * 1024 * 1024)?;
    let policy = crate::bounded_input::read(binding, 16384)?;
    let binding = nq_protocol::decode_json_document(&policy, 16384)?;
    let receipt = nq_core::continuity_support::qualify_with_history(&raw, &binding, history)
        .map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        String::from_utf8(nq_protocol::canonical_json_bytes(&receipt)?)?
    );
    Ok(())
}
