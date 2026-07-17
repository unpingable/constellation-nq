//! `nq` operator CLI entry point.

use clap::Parser;

#[tokio::main]
async fn main() {
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
