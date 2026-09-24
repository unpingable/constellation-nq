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
    if std::env::args().nth(1).as_deref() == Some("--failure-codes") {
        return match nq_host_resource_helper::write_failure_codes(std::io::stdout().lock()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("nq-host-resource-helper: cannot write failure codes: {error}");
                ExitCode::FAILURE
            }
        };
    }
    match nq_host_resource_helper::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nq-host-resource-helper: {error}");
            ExitCode::from(2)
        }
    }
}
