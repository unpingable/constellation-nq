//! Black-box checks for the one-shot operator-beta helper.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use nq_profiles::{ProfileModule, systemd_unit};
use nq_protocol::{
    Capability, CollectionBounds, HelperRequest, InstanceId, MonotonicClock, MonotonicDeadline,
    ProfileBinding, ProfileId, ProfileVersion, RequestId, ResponseOutcome, ScopeBinding, ScopeKind,
    Sha256Digest, SubjectBinding, SubjectId, VantageBinding, VantageKind, encode_ndjson,
    parse_response,
};
use serde_json::json;

const SUBJECT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UNIT_DIGEST: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn request() -> HelperRequest {
    let descriptor = systemd_unit::MODULE.descriptor();
    HelperRequest::builder(
        RequestId::new("request:blackbox").unwrap(),
        InstanceId::new("instance:blackbox").unwrap(),
        ProfileBinding {
            id: ProfileId::new(systemd_unit::PROFILE_ID).unwrap(),
            version: ProfileVersion::new(systemd_unit::PROFILE_VERSION.to_string()).unwrap(),
            digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str()).unwrap(),
        },
        SubjectBinding {
            subject: SubjectId::new(SUBJECT).unwrap(),
            scope: ScopeBinding {
                kind: ScopeKind::new("systemd_unit").unwrap(),
                value: json!({
                    "schema": "nq.operator_beta.systemd_unit_scope.v1",
                    "subject_identity": SUBJECT,
                    "target_machine_identity": "machine:fixture-001",
                    "unit_name": "constellation-beta-http-fixture.service",
                    "unit_file_sha256": UNIT_DIGEST,
                    "manager_interface": "org.freedesktop.systemd1",
                    "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
                }),
            },
            vantage: VantageBinding {
                kind: VantageKind::new("target_local").unwrap(),
                value: json!({}),
            },
        },
        MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: u64::MAX,
        },
    )
    .capability(Capability::new("read_systemd_unit").unwrap())
    .bounds(CollectionBounds {
        max_response_bytes: 32_768,
        max_observations: 1,
        max_payload_bytes: 16_383,
        max_coverage_entries: 1,
        max_report_errors: 1,
        max_checkpoint_bytes: 1,
    })
    .build()
    .unwrap()
}

fn invoke(frame: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nq-operator-beta-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(frame).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn binary_emits_typed_refusal_before_external_collection() {
    let request = request();
    let output = invoke(&encode_ndjson(&request).unwrap());
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response = parse_response(&request, &output.stdout).unwrap();
    assert!(matches!(response.outcome, ResponseOutcome::Refusal { .. }));
}

#[test]
fn binary_rejects_malformed_framing_without_testimony() {
    let output = invoke(b"{}\n{}\n");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid request"));
}

#[test]
fn binary_build_information_is_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_nq-operator-beta-helper"))
        .arg("--build-info")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["component"], "nq-operator-beta-helper");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}
