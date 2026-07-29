//! Black-box proof that shipped resident startup cannot invoke diagnostics.

use std::fs;
use std::process::Command;

#[test]
fn daemon_once_flag_is_refused_before_any_store_or_provider_work() {
    let nqd = env!("CARGO_BIN_EXE_nqd");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let config = directory.path().join("nq.toml");
    let database = directory.path().join("nq.db");
    fs::write(
        &config,
        format!(
            "schema = \"nq.config.v2\"\ndatabase_path = \"{}\"\nsocket_path = \"{}\"\n\
             admissions_dir = \"{}\"\nhelper_runtime_dir = \"{}\"\n",
            database.display(),
            directory.path().join("nqd.sock").display(),
            directory.path().join("admissions").display(),
            directory.path().join("helpers").display(),
        ),
    )
    .expect("write bounded config");

    let output = Command::new(nqd)
        .arg("--config")
        .arg(&config)
        .arg("--once")
        .output()
        .expect("shipped nqd binary executes");
    assert!(
        !output.status.success(),
        "removed invocation flag was accepted"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--once'"),
        "daemon did not refuse at its command boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !database.exists(),
        "refused daemon invocation mutated persistent state"
    );
}
