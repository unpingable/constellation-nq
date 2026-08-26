//! Black-box checks for the shipped one-shot stdio helper binary.

use std::{
    io::Write,
    process::{Child, Command, Stdio},
    sync::{Arc, Barrier},
    thread,
};

use nq_profiles::{ProfileModule, ReportInput, ValidationContext, host};
use nq_protocol::{
    Capability, HelperRequest, InstanceId, MonotonicClock, MonotonicDeadline, ProfileBinding,
    ProfileId, ProfileVersion, RequestId, ResponseOutcome, ScopeBinding, ScopeKind, Sha256Digest,
    SubjectBinding, SubjectId, VantageBinding, VantageKind, encode_ndjson, parse_response,
};
use serde_json::json;

fn request(request_id: &str) -> HelperRequest {
    let descriptor = host::MODULE.descriptor();
    HelperRequest::builder(
        RequestId::new(request_id).unwrap(),
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

fn spawn_helper() -> Child {
    Command::new(env!("CARGO_BIN_EXE_nq-host-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn invoke(frame: &[u8]) -> std::process::Output {
    let mut child = spawn_helper();
    child.stdin.take().unwrap().write_all(frame).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn shipped_binary_emits_one_admissible_local_host_report() {
    let request = request("request:blackbox");
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
fn concurrent_one_shot_helpers_keep_request_and_stdio_custody_separate() {
    let barrier = Arc::new(Barrier::new(3));
    let children = [spawn_helper(), spawn_helper()];
    let handles = ["request:concurrent-one", "request:concurrent-two"]
        .into_iter()
        .zip(children)
        .map(|(request_id, mut child)| {
            let request = request(request_id);
            let frame = encode_ndjson(&request).unwrap();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                child.stdin.take().unwrap().write_all(&frame).unwrap();
                (request, child.wait_with_output().unwrap())
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();

    let mut outputs = handles
        .into_iter()
        .map(|handle| handle.join().expect("helper worker must join"));
    let (first_request, first) = outputs.next().unwrap();
    let (second_request, second) = outputs.next().unwrap();
    for (request, output) in [(&first_request, &first), (&second_request, &second)] {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        parse_response(request, &output.stdout)
            .expect("each response must echo and validate against only its own request");
    }
    assert_ne!(
        first.stdout, second.stdout,
        "distinct request identities must remain visible in separately captured frames"
    );
    assert!(parse_response(&first_request, &second.stdout).is_err());
    assert!(parse_response(&second_request, &first.stdout).is_err());
}

#[test]
fn shipped_binary_rejects_malformed_framing_without_fake_testimony() {
    let output = invoke(b"{}\n{}\n");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid request"));
}
