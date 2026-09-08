//! Read-only local-store purpose support; no imported artifact fallback.
use anyhow::Result;
use std::path::Path;

pub fn run(config_path: &Path, request_path: &Path) -> Result<()> {
    let config = nq_core::config::NqConfig::load(config_path)?;
    let bytes = crate::bounded_input::read(request_path, 65536)?;
    let request: nq_core::purpose_support::PurposeRequest =
        nq_protocol::decode_json_document(&bytes, 65536)?;
    let store = nq_store::Store::open_read_only(&config.database_path)?;
    let result = nq_core::purpose_support::qualify(&store, &request).map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        String::from_utf8(nq_protocol::canonical_json_bytes(&result)?)?
    );
    Ok(())
}
