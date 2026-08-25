//! Closed production helper for `linode_instance_metadata_v1`.

use std::process::ExitCode;

fn main() -> ExitCode {
    match nq_build_info::write_if_requested("nq-linode-origin-helper", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return ExitCode::SUCCESS,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nq-linode-origin-helper: cannot write build information: {error}");
            return ExitCode::FAILURE;
        }
    }
    match nq_linode_origin_helper::run_command() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nq-linode-origin-helper: {error}");
            ExitCode::from(2)
        }
    }
}
