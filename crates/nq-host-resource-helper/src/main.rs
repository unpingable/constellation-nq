//! `nq.host_filesystem_*` one-shot stdio helper entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    match nq_build_info::write_if_requested("nq-host-resource-helper", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return ExitCode::SUCCESS,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nq-host-resource-helper: cannot write build information: {error}");
            return ExitCode::FAILURE;
        }
    }
    match nq_host_resource_helper::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nq-host-resource-helper: {error}");
            ExitCode::from(2)
        }
    }
}
