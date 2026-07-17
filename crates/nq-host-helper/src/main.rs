//! `nq.host/v1` one-shot stdio helper entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    match nq_build_info::write_if_requested("nq-host-helper", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return ExitCode::SUCCESS,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nq-host-helper: cannot write build information: {error}");
            return ExitCode::FAILURE;
        }
    }
    match nq_host_helper::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Request parsing failures cannot be echoed safely. Keep stderr
            // bounded and leave stdout empty so the runner records a protocol
            // failure rather than mistaking it for helper testimony.
            eprintln!("nq-host-helper: {error}");
            ExitCode::from(2)
        }
    }
}
