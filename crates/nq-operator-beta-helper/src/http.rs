use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    str::FromStr,
};

use nq_protocol::{HelperRequest, Sha256Digest};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{CollectionFailure, DeadlineClock, evidence_basis, remaining};

const MAX_HEADER_BYTES: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpScope {
    schema: String,
    subject_identity: String,
    controller_vantage_identity: String,
    endpoint: String,
    method: String,
    redirect_policy: String,
    max_response_bytes: u32,
}

pub(super) fn acquire(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<Value, CollectionFailure> {
    let scope: HttpScope =
        serde_json::from_value(request.binding.scope.value.clone()).map_err(|_| {
            CollectionFailure::new("http_scope_invalid", "HTTP scope was not reopenable", false)
        })?;
    let _ = (&scope.schema, &scope.subject_identity);
    let (address, authority) = parse_endpoint(&scope.endpoint)?;
    let mut stream =
        TcpStream::connect_timeout(&address, remaining(request, clock)?).map_err(|_| {
            CollectionFailure::new("http_connect_failed", "bounded TCP connection failed", true)
        })?;
    configure_timeout(&stream, request, clock)?;
    let request_bytes =
        format!("GET /healthz HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request_bytes.as_bytes()).map_err(|_| {
        CollectionFailure::new(
            "http_write_failed",
            "bounded HTTP request write failed",
            true,
        )
    })?;
    configure_timeout(&stream, request, clock)?;
    let response = read_response(
        &mut stream,
        usize::try_from(scope.max_response_bytes).unwrap_or(usize::MAX),
        request,
        clock,
    )?;
    let _ = remaining(request, clock)?;
    let body_digest = format!("sha256:{:x}", Sha256::digest(&response.body));
    let body_sha256 = Sha256Digest::parse(body_digest).map_err(|_| {
        CollectionFailure::new(
            "http_body_digest",
            "HTTP body digest could not be represented",
            false,
        )
    })?;
    let body_bytes = u32::try_from(response.body.len()).map_err(|_| {
        CollectionFailure::new("http_body_bound", "HTTP body length exceeded u32", false)
    })?;
    Ok(json!({
        "evidence_basis": evidence_basis(request, "http_tcp", "http_response"),
        "controller_vantage_identity": scope.controller_vantage_identity,
        "endpoint": scope.endpoint,
        "method": scope.method,
        "redirect_policy": scope.redirect_policy,
        "status": response.status,
        "body_sha256": body_sha256,
        "body_bytes": body_bytes,
    }))
}

fn parse_endpoint(endpoint: &str) -> Result<(SocketAddr, String), CollectionFailure> {
    let remainder = endpoint
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix("/healthz"))
        .ok_or_else(|| {
            CollectionFailure::new(
                "http_endpoint_invalid",
                "endpoint must be exact plain HTTP /healthz",
                false,
            )
        })?;
    if remainder.is_empty() || remainder.contains(['@', '/', '?', '#']) {
        return Err(CollectionFailure::new(
            "http_endpoint_invalid",
            "endpoint authority contains a disallowed component",
            false,
        ));
    }
    let address = SocketAddr::from_str(remainder).map_err(|_| {
        CollectionFailure::new(
            "http_endpoint_not_numeric",
            "endpoint must contain one numeric socket address",
            false,
        )
    })?;
    if address.port() != 18_080 {
        return Err(CollectionFailure::new(
            "http_endpoint_port",
            "operator-beta endpoint port must be 18080",
            false,
        ));
    }
    Ok((address, remainder.to_owned()))
}

fn configure_timeout(
    stream: &TcpStream,
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<(), CollectionFailure> {
    let duration = remaining(request, clock)?;
    stream
        .set_read_timeout(Some(duration))
        .and_then(|()| stream.set_write_timeout(Some(duration)))
        .map_err(|_| {
            CollectionFailure::new(
                "http_timeout_configuration",
                "TCP timeout could not be configured",
                true,
            )
        })
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn read_response(
    stream: &mut TcpStream,
    maximum_body: usize,
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<HttpResponse, CollectionFailure> {
    let mut received = Vec::with_capacity(MAX_HEADER_BYTES.min(4_096));
    let header_end = loop {
        if let Some(position) = find_header_end(&received) {
            let end = position + 4;
            if end > MAX_HEADER_BYTES {
                return Err(CollectionFailure::new(
                    "http_header_bound",
                    "HTTP headers exceed 16384 bytes",
                    false,
                ));
            }
            break end;
        }
        if received.len() >= MAX_HEADER_BYTES {
            return Err(CollectionFailure::new(
                "http_header_bound",
                "HTTP headers exceed 16384 bytes",
                false,
            ));
        }
        configure_timeout(stream, request, clock)?;
        let mut chunk = [0_u8; 4_096];
        let count = stream.read(&mut chunk).map_err(|_| {
            CollectionFailure::new("http_read_failed", "HTTP header read failed", true)
        })?;
        if count == 0 {
            return Err(CollectionFailure::new(
                "http_header_incomplete",
                "HTTP headers ended before the terminator",
                true,
            ));
        }
        received.extend_from_slice(&chunk[..count]);
    };

    let (status, content_length) = parse_headers(&received[..header_end])?;
    if content_length > maximum_body {
        return Err(CollectionFailure::new(
            "http_body_bound",
            "declared HTTP body exceeds the exact scope bound",
            false,
        ));
    }
    let mut body = received[header_end..].to_vec();
    if body.len() > content_length {
        return Err(CollectionFailure::new(
            "http_body_length",
            "HTTP response carried bytes beyond Content-Length",
            false,
        ));
    }
    body.reserve(content_length.saturating_sub(body.len()));
    while body.len() < content_length {
        configure_timeout(stream, request, clock)?;
        let remaining_body = content_length - body.len();
        let mut chunk = [0_u8; 4_096];
        let read_bound = remaining_body.min(chunk.len());
        let count = stream.read(&mut chunk[..read_bound]).map_err(|_| {
            CollectionFailure::new("http_read_failed", "HTTP body read failed", true)
        })?;
        if count == 0 {
            return Err(CollectionFailure::new(
                "http_body_incomplete",
                "HTTP body ended before Content-Length",
                true,
            ));
        }
        body.extend_from_slice(&chunk[..count]);
    }
    configure_timeout(stream, request, clock)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            return Err(CollectionFailure::new(
                "http_body_length",
                "HTTP response carried bytes beyond Content-Length",
                false,
            ));
        }
        Err(_) => {
            return Err(CollectionFailure::new(
                "http_completion_unconfirmed",
                "HTTP connection did not close after the exact Content-Length body",
                true,
            ));
        }
    }
    Ok(HttpResponse { status, body })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn valid_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn validate_header_syntax(name: &str, value: &str) -> Result<(), CollectionFailure> {
    if name.is_empty() || !name.bytes().all(valid_header_name_byte) {
        return Err(CollectionFailure::new(
            "http_header_name",
            "HTTP header name is outside the bounded token syntax",
            false,
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(CollectionFailure::new(
            "http_header_value",
            "HTTP header value contains a disallowed byte",
            false,
        ));
    }
    Ok(())
}

fn parse_headers(bytes: &[u8]) -> Result<(u16, usize), CollectionFailure> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        CollectionFailure::new("http_header_encoding", "HTTP headers are not UTF-8", false)
    })?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| {
            CollectionFailure::new(
                "http_header_framing",
                "HTTP header terminator is missing",
                false,
            )
        })?
        .split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        CollectionFailure::new("http_status_missing", "HTTP status line is missing", false)
    })?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let status_text = status_parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status_text.len() != 3
        || !status_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CollectionFailure::new(
            "http_status_invalid",
            "HTTP status line is outside the beta framing",
            false,
        ));
    }
    let status = status_text.parse::<u16>().map_err(|_| {
        CollectionFailure::new("http_status_invalid", "HTTP status is not a u16", false)
    })?;
    if !(200..=999).contains(&status) {
        return Err(CollectionFailure::new(
            "http_interim_or_invalid",
            "interim and non-final HTTP status values are refused",
            false,
        ));
    }

    let mut content_length = None;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(CollectionFailure::new(
                "http_header_folding",
                "folded HTTP headers are refused",
                false,
            ));
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            CollectionFailure::new("http_header_invalid", "HTTP header lacks a colon", false)
        })?;
        validate_header_syntax(name, value)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(CollectionFailure::new(
                "http_transfer_encoding",
                "every Transfer-Encoding is refused",
                false,
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(CollectionFailure::new(
                    "http_content_length_duplicate",
                    "duplicate Content-Length is refused",
                    false,
                ));
            }
            let value = value.trim_matches([' ', '\t']);
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(CollectionFailure::new(
                    "http_content_length_invalid",
                    "Content-Length is not canonical decimal",
                    false,
                ));
            }
            content_length = Some(value.parse::<usize>().map_err(|_| {
                CollectionFailure::new(
                    "http_content_length_invalid",
                    "Content-Length exceeds usize",
                    false,
                )
            })?);
        }
    }
    let content_length = content_length.ok_or_else(|| {
        CollectionFailure::new(
            "http_content_length_missing",
            "one Content-Length is required",
            false,
        )
    })?;
    Ok((status, content_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_header_matrix() {
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap(),
            (200, 3)
        );
        for bytes in [
            &b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nBad Header: value\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nX-Test: good\x01bad\r\nContent-Length: 0\r\n\r\n"[..],
        ] {
            assert!(parse_headers(bytes).is_err());
        }
    }

    #[test]
    fn exact_numeric_endpoint() {
        assert!(parse_endpoint("http://127.0.0.1:18080/healthz").is_ok());
        assert!(parse_endpoint("http://[::1]:18080/healthz").is_ok());
        assert!(parse_endpoint("http://fixture:18080/healthz").is_err());
        assert!(parse_endpoint("http://127.0.0.1:80/healthz").is_err());
    }

    fn response_stream(bytes: Vec<u8>) -> (TcpStream, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&bytes).unwrap();
        });
        (TcpStream::connect(address).unwrap(), writer)
    }

    fn split_response_stream(
        first: Vec<u8>,
        trailing: Vec<u8>,
    ) -> (TcpStream, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&first).unwrap();
            stream.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(25));
            stream.write_all(&trailing).unwrap();
        });
        (TcpStream::connect(address).unwrap(), writer)
    }

    fn framing_request() -> HelperRequest {
        use nq_protocol::{
            InstanceId, MonotonicClock, MonotonicDeadline, ProfileBinding, ProfileId,
            ProfileVersion, RequestId, ScopeBinding, ScopeKind, SubjectBinding, SubjectId,
            VantageBinding, VantageKind,
        };
        HelperRequest::builder(
            RequestId::new("request:http-framing").unwrap(),
            InstanceId::new("instance:http-framing").unwrap(),
            ProfileBinding {
                id: ProfileId::new("fixture").unwrap(),
                version: ProfileVersion::new("1").unwrap(),
                digest: Sha256Digest::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            },
            SubjectBinding {
                subject: SubjectId::new("subject:fixture").unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").unwrap(),
                    value: json!({}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("fixture").unwrap(),
                    value: json!({}),
                },
            },
            MonotonicDeadline {
                clock: MonotonicClock::LinuxBoottime,
                expires_at_ns: 1_000_000_001,
            },
        )
        .build()
        .unwrap()
    }

    struct FixedClock;

    impl DeadlineClock for FixedClock {
        fn now_ns(&self) -> Result<u64, String> {
            Ok(1)
        }
    }

    #[test]
    fn response_reader_requires_exact_declared_body() {
        let request = framing_request();
        let (mut valid, writer) =
            response_stream(b"HTTP/1.1 302 Found\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        let response = read_response(&mut valid, 3, &request, &FixedClock).unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(response.body, b"abc");
        writer.join().unwrap();

        let (mut short, writer) =
            response_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab".to_vec());
        assert!(read_response(&mut short, 3, &request, &FixedClock).is_err());
        writer.join().unwrap();

        let (mut long, writer) =
            response_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc".to_vec());
        assert!(read_response(&mut long, 3, &request, &FixedClock).is_err());
        writer.join().unwrap();

        let (mut split, writer) = split_response_stream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab".to_vec(),
            b"c".to_vec(),
        );
        assert!(read_response(&mut split, 3, &request, &FixedClock).is_err());
        writer.join().unwrap();
    }

    #[test]
    fn response_reader_enforces_header_and_scope_bounds() {
        let request = framing_request();
        let oversized_header = format!(
            "HTTP/1.1 200 OK\r\nX-Fill: {}\r\nContent-Length: 0\r\n\r\n",
            "x".repeat(MAX_HEADER_BYTES)
        )
        .into_bytes();
        let (mut stream, writer) = response_stream(oversized_header);
        assert!(read_response(&mut stream, 1, &request, &FixedClock).is_err());
        writer.join().unwrap();

        let (mut stream, writer) =
            response_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab".to_vec());
        assert!(read_response(&mut stream, 1, &request, &FixedClock).is_err());
        writer.join().unwrap();
    }
}
