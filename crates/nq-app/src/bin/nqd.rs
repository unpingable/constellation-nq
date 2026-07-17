//! `nqd` resident service entry point.

use clap::Parser;

#[tokio::main]
async fn main() {
    match nq_build_info::write_if_requested("nqd", env!("CARGO_PKG_VERSION")) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("nqd: cannot write build information: {error}");
            std::process::exit(1);
        }
    }
    let options = nq_app::daemon::Nqd::parse();
    if let Err(error) = nq_app::daemon::run(options).await {
        eprintln!("nqd: {error:#}");
        std::process::exit(1);
    }
}
