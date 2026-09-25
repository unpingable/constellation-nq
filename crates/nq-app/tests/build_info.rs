//! Build-policy probes must execute without consulting operator configuration.

use std::process::Command;

fn assert_probe(binary: &str, component: &str) {
    let output = Command::new(binary)
        .arg("--build-info")
        .env("NQ_CONFIG", "/nonexistent/probe-must-not-load-config.toml")
        .output()
        .expect("execute build-info probe");
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let body = output
        .stdout
        .strip_suffix(b"\n")
        .expect("newline-terminated build information");
    assert!(!body.contains(&b'\n'));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("machine-readable build information");
    let object = value.as_object().expect("build information object");
    assert_eq!(object.len(), 6);
    assert_eq!(value["schema"], "nq.build_info.v2");
    assert_eq!(value["component"], component);
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["debug_assertions"], cfg!(debug_assertions));
    let expected_policy = if cfg!(debug_assertions) {
        "debug_same_identity_test_exception_available"
    } else {
        "production_separate_identity_required"
    };
    assert_eq!(value["helper_isolation_policy"], expected_policy);
    match nq_build_info::SOURCE_COMMIT {
        Some(commit) => {
            assert_eq!(value["source_commit"], commit);
            assert_eq!(
                nq_build_info::parse_source_commit(Some(commit)),
                Ok(Some(commit))
            );
        }
        None => assert!(value["source_commit"].is_null()),
    }
}

fn assert_version(binary: &str, component: &str) {
    let output = Command::new(binary)
        .arg("--version")
        .env("NQ_CONFIG", "/nonexistent/probe-must-not-load-config.toml")
        .output()
        .expect("execute version flag");
    assert!(
        output.status.success(),
        "version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let expected = match nq_build_info::SOURCE_COMMIT {
        Some(commit) => format!("{component} {} ({commit})\n", env!("CARGO_PKG_VERSION")),
        None => format!("{component} {}\n", env!("CARGO_PKG_VERSION")),
    };
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
}

#[test]
fn operator_and_daemon_probe_before_config_load() {
    assert_probe(env!("CARGO_BIN_EXE_nq"), "nq");
    assert_probe(env!("CARGO_BIN_EXE_nqd"), "nqd");
}

#[test]
fn operator_and_daemon_report_version_with_recorded_commit() {
    assert_version(env!("CARGO_BIN_EXE_nq"), "nq");
    assert_version(env!("CARGO_BIN_EXE_nqd"), "nqd");
}
