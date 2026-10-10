//! `nq` operator CLI entry point.

use clap::Parser;

#[tokio::main]
async fn main() {
    // Catch rather than ignore SIGXFSZ: the failed write still returns EFBIG,
    // while exec of a watcher helper restores the default signal disposition.
    // Install this before any CLI, ownership-lock, or SQLite write. Capacity
    // admission remains responsible for avoiding the limit in normal operation.
    let _file_size_signal = match tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::from_raw(nix::libc::SIGXFSZ),
    ) {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("nq: cannot establish file-size-limit error handling: {error}");
            std::process::exit(1);
        }
    };
    match nq_build_info::write_if_requested("nq", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nq: cannot write build information: {error}");
            std::process::exit(1);
        }
    }
    let options = nq_app::cli::Nq::parse();
    if let Err(error) = nq_app::cli::run(options).await {
        eprintln!("nq: {error:#}");
        std::process::exit(1);
    }
}
