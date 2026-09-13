//! The first-party helper participates in the executable release cohort.

use std::process::Command;

#[test]
fn helper_exposes_version_and_build_policy_without_reading_a_request() {
    let output = Command::new(env!("CARGO_BIN_EXE_nq-synthetic-cache-result-helper"))
        .arg("--build-info")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("execute helper build-info probe");
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("machine-readable build information");
    assert_eq!(value["schema"], "nq.build_info.v1");
    assert_eq!(value["component"], "nq-synthetic-cache-result-helper");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["debug_assertions"], cfg!(debug_assertions));
}
