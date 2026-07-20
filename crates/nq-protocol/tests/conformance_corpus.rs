//! Black-box tests for the published protocol conformance corpus.

use std::{
    io::Write as _,
    path::PathBuf,
    process::{Command, Stdio},
};

use nq_protocol::{
    EvidenceReport, FramingError, HelperResponse, Refusal, RefusalBoundary, RefusalCode,
    ResponseOutcome, ValidationError, canonical_json_bytes, decode_ndjson, encode_ndjson,
    parse_request, parse_response, semantic_digest, validate_report,
};
use serde_json::{Value, json};

const REQUEST: &[u8] = include_bytes!("../../../protocol/fixtures/valid/request.ndjson");
const REPORT: &[u8] = include_bytes!("../../../protocol/fixtures/valid/evidence_report.ndjson");
const RESPONSE_REPORT: &[u8] =
    include_bytes!("../../../protocol/fixtures/valid/response_report.ndjson");
const RESPONSE_REFUSAL: &[u8] =
    include_bytes!("../../../protocol/fixtures/valid/response_refusal.ndjson");
const RESPONSE_FAILED: &[u8] =
    include_bytes!("../../../protocol/fixtures/valid/response_failed_report.ndjson");

#[test]
fn positive_corpus_exercises_all_result_planes() {
    let request = parse_request(REQUEST).expect("valid request fixture");

    let response = parse_response(&request, RESPONSE_REPORT).expect("valid report response");
    let ResponseOutcome::Report { report } = response.outcome else {
        panic!("expected report outcome");
    };
    assert_eq!(report.status, nq_protocol::ReportStatus::Complete);

    let response = parse_response(&request, RESPONSE_FAILED).expect("valid failed report response");
    let ResponseOutcome::Report { report } = response.outcome else {
        panic!("expected failed report outcome");
    };
    assert_eq!(report.status, nq_protocol::ReportStatus::Failed);

    let response =
        parse_response(&request, RESPONSE_REFUSAL).expect("valid typed refusal response");
    assert!(matches!(response.outcome, ResponseOutcome::Refusal { .. }));
}

#[test]
fn same_code_distinct_refusals_remain_distinct_on_wire() {
    let request = parse_request(REQUEST).expect("valid request fixture");
    let refusal = |retriable, details| Refusal {
        responsible_instance_id: request.instance_id.clone(),
        boundary: RefusalBoundary::Collection,
        code: RefusalCode::CollectionFailed,
        message: "backend collection failed".to_owned(),
        retriable,
        details,
    };
    let transient = HelperResponse::refusal(
        &request,
        refusal(true, json!({"errno": "EAGAIN", "attempt": 1})),
    );
    let permanent = HelperResponse::refusal(
        &request,
        refusal(false, json!({"errno": "ENODEV", "device": "nvme0"})),
    );

    let transient_wire = encode_ndjson(&transient).expect("transient refusal wire frame");
    let permanent_wire = encode_ndjson(&permanent).expect("permanent refusal wire frame");
    assert_ne!(transient_wire, permanent_wire);
    assert_eq!(
        parse_response(&request, &transient_wire).expect("parse transient refusal"),
        transient
    );
    assert_eq!(
        parse_response(&request, &permanent_wire).expect("parse permanent refusal"),
        permanent
    );
}

#[test]
fn standalone_evidence_report_contract_is_valid() {
    let report: EvidenceReport = decode_ndjson(REPORT, 1_048_576).expect("strict report decode");
    validate_report(&report).expect("common report laws");
}

#[test]
fn request_negative_corpus_is_rejected_at_the_named_plane() {
    let unknown = include_bytes!("../../../protocol/fixtures/invalid/request_unknown_field.ndjson");
    assert!(matches!(parse_request(unknown), Err(FramingError::Json(_))));

    let duplicate =
        include_bytes!("../../../protocol/fixtures/invalid/request_duplicate_key.ndjson");
    let error = parse_request(duplicate).expect_err("duplicate keys must fail");
    assert!(error.to_string().contains("duplicate object key"));

    let version = include_bytes!("../../../protocol/fixtures/invalid/request_wrong_version.ndjson");
    assert!(matches!(
        parse_request(version),
        Err(FramingError::Validation(
            ValidationError::InvalidProtocolVersion { .. }
        ))
    ));
}

#[test]
fn response_negative_corpus_is_rejected_at_the_named_plane() {
    let request = parse_request(REQUEST).unwrap();

    let wrong_echo =
        include_bytes!("../../../protocol/fixtures/invalid/response_wrong_echo.ndjson");
    assert!(matches!(
        parse_response(&request, wrong_echo),
        Err(FramingError::Validation(ValidationError::EchoMismatch {
            field: "echo.request_id"
        }))
    ));

    let escape =
        include_bytes!("../../../protocol/fixtures/invalid/response_capability_escape.ndjson");
    assert!(matches!(
        parse_response(&request, escape),
        Err(FramingError::Validation(ValidationError::CapabilityEscape(
            _
        )))
    ));

    let failed =
        include_bytes!("../../../protocol/fixtures/invalid/response_failed_without_error.ndjson");
    assert!(matches!(
        parse_response(&request, failed),
        Err(FramingError::Validation(ValidationError::InvalidField {
            field: "report.status",
            ..
        }))
    ));

    let extra = include_bytes!("../../../protocol/fixtures/invalid/extra_frame.ndjson");
    assert!(matches!(
        decode_ndjson::<Value>(extra, 1024),
        Err(FramingError::NotExactlyOneLine)
    ));
}

#[test]
fn encoding_is_canonical_and_round_trips_as_one_frame() {
    let request = parse_request(REQUEST).unwrap();
    let encoded = encode_ndjson(&request).unwrap();
    assert_eq!(encoded.last(), Some(&b'\n'));
    assert!(!encoded[..encoded.len() - 1].contains(&b'\n'));
    let decoded = parse_request(&encoded).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn semantic_digest_ignores_object_insertion_order_but_raw_digest_need_not() {
    let left = json!({"profile": {"version": "1", "id": "nq.conformance"}, "x": 1});
    let right = json!({"x": 1, "profile": {"id": "nq.conformance", "version": "1"}});
    assert_eq!(
        canonical_json_bytes(&left).unwrap(),
        canonical_json_bytes(&right).unwrap()
    );
    assert_eq!(
        semantic_digest(&left).unwrap(),
        semantic_digest(&right).unwrap()
    );
}

#[test]
fn helpers_cannot_smuggle_authority_fields() {
    let mut response: Value = serde_json::from_slice(&RESPONSE_REPORT[..RESPONSE_REPORT.len() - 1])
        .expect("fixture JSON");
    response["outcome"]["report"]["authoritative_for"] = json!(["host"]);
    let bytes = encode_ndjson(&response).unwrap();
    let request = parse_request(REQUEST).unwrap();
    assert!(matches!(
        parse_response(&request, &bytes),
        Err(FramingError::Json(_))
    ));
}

#[test]
fn python_reference_helper_is_wire_compatible() {
    let mut request = parse_request(REQUEST).unwrap();
    request.deadline.expires_at_ns = u64::MAX;
    let frame = encode_ndjson(&request).unwrap();
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../helpers/python-conformance/nq_conformance_helper.py");
    let mut child = Command::new("python3")
        .arg(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Python reference helper");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&frame)
        .expect("write exactly one request");
    let output = child.wait_with_output().expect("collect helper response");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let response = parse_response(&request, &output.stdout).expect("Rust accepts Python response");
    assert!(matches!(response.outcome, ResponseOutcome::Report { .. }));
}
