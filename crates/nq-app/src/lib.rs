//! Shared application wiring for the `nq` and `nqd` binaries.

pub mod api;
pub mod archive;
pub mod bounded_input;
pub mod cli;
pub mod continuity_cli;
pub mod daemon;
pub mod docket_cli;
pub mod labelwatch_cleanup_cli;
pub mod labelwatch_relief_cli;
pub mod notification;
mod ownership;
pub mod purpose_cli;
pub mod queue_cli;
pub mod repository_cli;
pub mod saved_check;
pub mod stage_cli;
mod transport;
