//! One-shot operator-beta observation helper entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    match nq_build_info::write_if_requested("nq-operator-beta-helper", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return ExitCode::SUCCESS,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nq-operator-beta-helper: cannot write build information: {error}");
            return ExitCode::FAILURE;
        }
    }
    match nq_operator_beta_helper::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Before a valid echoable request exists, or when its negotiated
            // response bound is unrepresentable, stdout must remain empty.
            eprintln!("nq-operator-beta-helper: {error}");
            ExitCode::from(2)
        }
    }
}
