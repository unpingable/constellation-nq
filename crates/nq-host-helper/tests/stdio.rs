//! Black-box checks for the shipped one-shot stdio helper binary.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use nq_profiles::{ProfileModule, ReportInput, ValidationContext, host};
use nq_protocol::{
    Capability, HelperRequest, InstanceId, MonotonicClock, MonotonicDeadline, ProfileBinding,
    ProfileId, ProfileVersion, RequestId, ResponseOutcome, ScopeBinding, ScopeKind, Sha256Digest,
    SubjectBinding, SubjectId, VantageBinding, VantageKind, encode_ndjson, parse_response,
};
use serde_json::json;

fn request() -> HelperRequest {
    let descriptor = host::MODULE.descriptor();
    HelperRequest::builder(
        RequestId::new("request:blackbox").unwrap(),
        InstanceId::new("instance:blackbox").unwrap(),
        ProfileBinding {
            id: ProfileId::new(host::PROFILE_ID).unwrap(),
            version: ProfileVersion::new(host::PROFILE_VERSION.to_string()).unwrap(),
            digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str()).unwrap(),
        },
        SubjectBinding {
            subject: SubjectId::new("host:blackbox").unwrap(),
            scope: ScopeBinding {
                kind: ScopeKind::new("host").unwrap(),
                value: json!({"id": "blackbox"}),
            },
            vantage: VantageBinding {
                kind: VantageKind::new("local").unwrap(),
                value: json!({}),
            },
        },
        MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: u64::MAX,
        },
    )
    .capabilities(vec![
        Capability::new("read_procfs").unwrap(),
        Capability::new("read_system_info").unwrap(),
    ])
    .build()
    .unwrap()
}

fn invoke(frame: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nq-host-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(frame).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn shipped_binary_emits_one_admissible_local_host_report() {
    let request = request();
    let output = invoke(&encode_ndjson(&request).unwrap());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let body = output
        .stdout
        .strip_suffix(b"\n")
        .expect("one LF terminator");
    assert!(!body.contains(&b'\n'));

    let response = parse_response(&request, &output.stdout).unwrap();
    let ResponseOutcome::Report { report } = response.outcome else {
        panic!("expected a report from Linux host collection")
    };
    let input = ReportInput::from_protocol_with_digest(&report).unwrap();
    let context =
        ValidationContext::from_request(&request, chrono::Utc::now(), chrono::Duration::seconds(5));
    host::MODULE
        .validate(&context, &input)
        .expect("the compiled profile must admit first-party testimony");
}

#[test]
fn shipped_binary_rejects_malformed_framing_without_fake_testimony() {
    let output = invoke(b"{}\n{}\n");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid request"));
}
