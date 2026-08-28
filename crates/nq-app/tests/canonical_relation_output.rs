//! Exact-byte qualification for watcher succession relation output.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn nq(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nq"))
        .args(arguments)
        .output()
        .expect("run nq")
}

#[test]
#[allow(clippy::too_many_lines)]
fn succession_builder_stdout_is_an_exact_canonical_file_and_lf_still_refuses() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let fixture = repository
        .join("audit/receipts/run-2026-08-27-passive-24h-charter-replacement/live-inputs");
    let temporary = tempfile::tempdir().expect("temporary relation fixture");
    let provider_g1 = temporary.path().join("provider-g1.toml");
    let provider_g2 = temporary.path().join("provider-g2.toml");
    fs::copy(fixture.join("provider-g1.toml"), &provider_g1).expect("copy G1 provider");
    fs::copy(fixture.join("provider-g2.toml"), &provider_g2).expect("copy G2 provider");

    let config_path = temporary.path().join("nq.toml");
    let execution_account = nix::unistd::geteuid().as_raw().to_string();
    let config = fs::read_to_string(fixture.join("nq-charter.toml"))
        .expect("read reviewed succession configuration")
        .replace(
            "/etc/nq/passive-load-24h-r2/provider-g1.toml",
            provider_g1.to_str().expect("UTF-8 G1 provider path"),
        )
        .replace(
            "/etc/nq/passive-load-24h-r2/provider-g2.toml",
            provider_g2.to_str().expect("UTF-8 G2 provider path"),
        )
        .replace("nq-passive-load-reader", &execution_account)
        .replace("env = {}", "env = {}\nallow_same_identity_in_debug = true")
        .replace(
            "/opt/nq-ng/passive-handoff-87a6ca3-musl/lib/nq/helpers/nq-passive-load-helper",
            "/bin/true",
        )
        .replace(
            "/opt/nq-ng/passive-handoff-87a6ca3-musl",
            temporary.path().to_str().expect("UTF-8 working directory"),
        );
    fs::write(&config_path, config).expect("write local relation configuration");

    let output = nq(&[
        "--config",
        config_path.to_str().expect("UTF-8 configuration path"),
        "--json",
        "operating",
        "build-watcher-succession",
        "labelwatch-host-passive-24h-r2-g1",
        "labelwatch-host-passive-24h-r2-g2",
        "--predecessor-provider-config",
        provider_g1.to_str().expect("UTF-8 G1 provider path"),
        "--successor-provider-config",
        provider_g2.to_str().expect("UTF-8 G2 provider path"),
        "--operator-occurrence-id",
        "glasshopper:exact-relation-file",
    ]);
    assert!(
        output.status.success(),
        "succession builder failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let relation: Value = serde_json::from_slice(&output.stdout).expect("relation JSON");
    let canonical = nq_protocol::canonical_json_bytes(&relation).expect("canonical relation");
    assert_eq!(output.stdout, canonical);
    assert_ne!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        nq_protocol::sha256_bytes(&output.stdout),
        nq_protocol::semantic_digest(&relation).expect("relation semantic digest")
    );

    let exact_path = temporary.path().join("relation-exact.json");
    fs::write(&exact_path, &output.stdout).expect("write exact relation file");
    let state_dir = temporary.path().join("operating-state");
    let unknown_grant = format!("sha256:{}", "0".repeat(64));
    let exact_issue = nq(&[
        "--config",
        config_path.to_str().expect("UTF-8 configuration path"),
        "--json",
        "operating",
        "issue-watcher-succession",
        &unknown_grant,
        exact_path.to_str().expect("UTF-8 exact relation path"),
        "--state-dir",
        state_dir.to_str().expect("UTF-8 operating state path"),
    ]);
    assert!(!exact_issue.status.success());
    assert!(
        !String::from_utf8_lossy(&exact_issue.stderr).contains("not exact canonical JSON"),
        "exact producer bytes must cross the strict file reader"
    );

    let mut with_lf = output.stdout;
    with_lf.push(b'\n');
    let lf_path = temporary.path().join("relation-with-lf.json");
    fs::write(&lf_path, with_lf).expect("write deterministic LF negative control");
    let lf_issue = nq(&[
        "--config",
        config_path.to_str().expect("UTF-8 configuration path"),
        "--json",
        "operating",
        "issue-watcher-succession",
        &unknown_grant,
        lf_path.to_str().expect("UTF-8 LF relation path"),
        "--state-dir",
        state_dir.to_str().expect("UTF-8 operating state path"),
    ]);
    assert!(!lf_issue.status.success());
    assert!(
        String::from_utf8_lossy(&lf_issue.stderr).contains("not exact canonical JSON"),
        "strict verifier must keep refusing LF-framed relation files"
    );
}
