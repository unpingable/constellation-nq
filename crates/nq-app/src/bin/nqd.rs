//! `nqd` resident service entry point.
//!
//! `nqd` is not itself an evaluator. After answering `--build-info`, it
//! replaces its process image with the sibling `nq` executable running
//! `nq daemon`, so the running evaluator (`/proc/self/exe`) is the same
//! artifact that admits watchers through the `nq` CLI, and an admission's
//! bound evaluator identity holds for daemon collection.

use std::os::unix::process::CommandExt as _;
use std::process::Command;

fn main() {
    match nq_build_info::write_if_requested("nqd", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nqd: cannot write build information: {error}");
            std::process::exit(1);
        }
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| {
        eprintln!("nqd: cannot resolve its own executable: {error}");
        std::process::exit(1);
    });
    let Some(directory) = executable.parent() else {
        eprintln!(
            "nqd: cannot locate the nq executable beside {}",
            executable.display()
        );
        std::process::exit(1);
    };
    let nq = directory.join("nq");
    let error = Command::new(&nq)
        .arg0("nq")
        .arg("daemon")
        .args(std::env::args_os().skip(1))
        .exec();
    eprintln!("nqd: cannot exec {} daemon: {error}", nq.display());
    std::process::exit(1);
}
