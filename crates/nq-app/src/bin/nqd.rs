//! `nqd` resident service entry point.
//!
//! `nqd` is not itself an evaluator. After answering `--build-info`, it
//! replaces its process image with the sibling `nq` executable running
//! `nq daemon`, so the running evaluator (`/proc/self/exe`) is the same
//! artifact that admits watchers through the `nq` CLI, and an admission's
//! bound evaluator identity holds for daemon collection.
//!
//! `nqd --version` is also answered here, in the same form as `nq --version`,
//! because `nq daemon` does not accept a version flag.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

fn is_only_argument(flag: &str) -> bool {
    let mut arguments = std::env::args_os().skip(1);
    arguments.next().as_deref() == Some(OsStr::new(flag)) && arguments.next().is_none()
}

fn main() {
    match nq_build_info::write_if_requested("nqd", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nqd: cannot write build information: {error}");
            std::process::exit(1);
        }
    }
    if is_only_argument("--version") || is_only_argument("-V") {
        println!("nqd {}", nq_build_info::VERSION_STRING);
        return;
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
