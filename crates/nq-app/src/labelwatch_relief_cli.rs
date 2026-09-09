//! Read-only closed qualification of independently acquired Labelwatch facts.
use anyhow::Result;
use std::path::Path;
pub fn run(source: &Path, request: &Path) -> Result<()> {
    let raw = crate::bounded_input::read(source, 2 * 1024 * 1024)?;
    let request_raw = crate::bounded_input::read(request, 2 * 1024 * 1024)?;
    let value = nq_protocol::decode_json_document(&request_raw, 2 * 1024 * 1024)?;
    let request = serde_json::from_value(value)?;
    let receipt =
        nq_core::labelwatch_relief::qualify(&raw, &request).map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        String::from_utf8(nq_protocol::canonical_json_bytes(&receipt)?)?
    );
    Ok(())
}
