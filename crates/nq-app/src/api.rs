//! Versioned local read API and server-rendered console.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nq_store::Store;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const MAX_HTTP_REQUEST_BYTES: usize = 8 * 1024;
const MAX_CONNECTIONS: usize = 64;
const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_FINDINGS_PER_RESPONSE: u32 = nq_store::MAX_PUBLIC_QUERY_ROWS;
const MAX_REJECTED_CUSTODY_PER_RESPONSE: u32 = nq_store::MAX_PUBLIC_QUERY_ROWS;
const MAX_EVALUATIONS_PER_RESPONSE: u32 = nq_store::MAX_PUBLIC_QUERY_ROWS;
const V1_STATUS_UNREPRESENTABLE: &[u8] =
    br#"{"error":"governed_status_requires_v3","required_endpoint":"/v3/status"}"#;
const V2_STATUS_UNREPRESENTABLE: &[u8] =
    br#"{"error":"typed_evaluations_require_v3","required_endpoint":"/v3/status"}"#;
const V2_FINDINGS_UNREPRESENTABLE: &[u8] =
    br#"{"error":"governed_findings_require_v3","required_endpoint":"/v3/findings"}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RejectedCustodyQuery {
    limit: u32,
    after_submission_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingsQuery {
    limit: u32,
    after_finding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvaluationHistoryQuery {
    limit: u32,
    after_sequence: Option<u64>,
    through_sequence: Option<u64>,
}

/// Serve the versioned API on a permission-restricted Unix socket.
///
/// # Errors
///
/// Returns when the socket cannot be prepared or listener I/O fails.
pub async fn serve_unix(socket_path: PathBuf, database_path: PathBuf) -> Result<()> {
    let listener = bind_unix(&socket_path)?;
    serve_unix_listener(listener, database_path).await
}

/// Prepare and bind the daemon's permission-restricted Unix listener before
/// service health is announced.
pub(crate) fn bind_unix(socket_path: &Path) -> Result<UnixListener> {
    prepare_socket(socket_path)?;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("cannot bind {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Serve a listener that was already successfully bound.
pub(crate) async fn serve_unix_listener(
    listener: UnixListener,
    database_path: PathBuf,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = std::sync::Arc::clone(&semaphore).acquire_owned().await?;
        let (stream, _) = listener.accept().await?;
        let database_path = database_path.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, database_path).await {
                tracing::debug!(%error, "local API request failed");
            }
        });
        while tasks.try_join_next().is_some() {}
    }
}

/// Serve the same read model as a loopback-only console/API endpoint.
///
/// # Errors
///
/// Returns when the address is not loopback or listener I/O fails.
pub async fn serve_loopback(address: SocketAddr, database_path: PathBuf) -> Result<()> {
    let listener = bind_loopback(address).await?;
    serve_loopback_listener(listener, database_path).await
}

/// Bind a literal loopback address before service health is announced.
pub(crate) async fn bind_loopback(address: SocketAddr) -> Result<TcpListener> {
    if !address.ip().is_loopback() {
        bail!("console address must be loopback, got {}", address.ip());
    }
    let listener = TcpListener::bind(address).await?;
    Ok(listener)
}

/// Serve a loopback listener that was already successfully bound.
pub(crate) async fn serve_loopback_listener(
    listener: TcpListener,
    database_path: PathBuf,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = std::sync::Arc::clone(&semaphore).acquire_owned().await?;
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!(%peer, "rejected non-loopback console connection");
            continue;
        }
        let database_path = database_path.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, database_path).await {
                tracing::debug!(%error, "loopback API request failed");
            }
        });
        while tasks.try_join_next().is_some() {}
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_connection<S>(mut stream: S, database_path: PathBuf) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = tokio::time::timeout(REQUEST_READ_TIMEOUT, read_request(&mut stream))
        .await
        .context("timed out reading HTTP request")??;
    let first_line = request.split("\r\n").next().context("empty HTTP request")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "GET" || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return write_response(
            &mut stream,
            405,
            "application/json",
            br#"{"error":"read-only GET API"}"#,
        )
        .await;
    }

    let (route, query) = match path.split_once('?') {
        Some((route, query)) => (route, Some(query)),
        None => (path, None),
    };
    match route {
        "/v1/status" => {
            if query.is_some() {
                return write_response(
                    &mut stream,
                    400,
                    "application/json",
                    br#"{"error":"status_query_not_supported"}"#,
                )
                .await;
            }
            // Compatibility surface: its schema and representation remain v1.
            match read_status_v1(database_path).await {
                Ok(body) => write_response(&mut stream, 200, "application/json", &body).await,
                Err(error) if is_v1_status_representation_error(&error) => {
                    write_response(
                        &mut stream,
                        409,
                        "application/json",
                        V1_STATUS_UNREPRESENTABLE,
                    )
                    .await
                }
                Err(error) => Err(error),
            }
        }
        "/v2/status" => {
            if query.is_some() {
                return write_response(
                    &mut stream,
                    400,
                    "application/json",
                    br#"{"error":"status_query_not_supported"}"#,
                )
                .await;
            }
            match read_status_v2(database_path).await {
                Ok(body) => write_response(&mut stream, 200, "application/json", &body).await,
                Err(error) if is_v2_status_representation_error(&error) => {
                    write_response(
                        &mut stream,
                        409,
                        "application/json",
                        V2_STATUS_UNREPRESENTABLE,
                    )
                    .await
                }
                Err(error) => Err(error),
            }
        }
        "/v3/status" => {
            if query.is_some() {
                return write_response(
                    &mut stream,
                    400,
                    "application/json",
                    br#"{"error":"status_query_not_supported"}"#,
                )
                .await;
            }
            let body = read_status_v3(database_path).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        "/v2/findings" => {
            write_response(
                &mut stream,
                409,
                "application/json",
                V2_FINDINGS_UNREPRESENTABLE,
            )
            .await
        }
        "/v3/findings" => {
            let query = match parse_findings_query(query) {
                Ok(query) => query,
                Err(detail) => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "error": "invalid_findings_query",
                        "detail": detail,
                    }))?;
                    return write_response(&mut stream, 400, "application/json", &body).await;
                }
            };
            let body = read_findings(database_path, query.limit, query.after_finding_id).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        "/v1/rejected-custody" => {
            let query = match parse_rejected_custody_query(query) {
                Ok(query) => query,
                Err(detail) => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "error": "invalid_rejected_custody_query",
                        "detail": detail,
                    }))?;
                    return write_response(&mut stream, 400, "application/json", &body).await;
                }
            };
            let body = read_rejected_custody(database_path, query.limit, query.after_submission_id)
                .await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        "/v1/evaluations" => {
            let query = match parse_evaluation_history_query(query) {
                Ok(query) => query,
                Err(detail) => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "error": "invalid_evaluations_query",
                        "detail": detail,
                    }))?;
                    return write_response(&mut stream, 400, "application/json", &body).await;
                }
            };
            let body = match read_evaluations(
                database_path,
                query.limit,
                query.after_sequence,
                query.through_sequence,
            )
            .await
            {
                Ok(body) => body,
                Err(error) if is_evaluation_query_bound_error(&error) => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "error": "invalid_evaluations_query",
                        "detail": error.to_string(),
                    }))?;
                    return write_response(&mut stream, 400, "application/json", &body).await;
                }
                Err(error) => return Err(error),
            };
            write_response(&mut stream, 200, "application/json", &body).await
        }
        "/console" | "/" => {
            let status = read_status_v3(database_path.clone()).await?;
            let findings = read_all_findings(database_path).await?;
            let body = render_console(&status, &findings);
            write_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                body.as_bytes(),
            )
            .await
        }
        _ => {
            write_response(
                &mut stream,
                404,
                "application/json",
                br#"{"error":"not found"}"#,
            )
            .await
        }
    }
}

async fn read_status_v1(database_path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let snapshot = nq_core::engine::status_snapshot(&store)?;
        serde_json::to_vec(&snapshot).map_err(anyhow::Error::from)
    })
    .await?
}

fn is_v1_status_representation_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<nq_core::engine::EngineError>(),
        Some(nq_core::engine::EngineError::Invariant(message))
            if message == "nq.status_snapshot.v1 cannot emit governed collection results; use v3"
                || message == "nq.status_snapshot.v1 cannot emit governed evaluation results; use v3"
    )
}

async fn read_status_v2(database_path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let snapshot = nq_core::engine::status_snapshot_v2(&store)?;
        serde_json::to_vec(&snapshot).map_err(anyhow::Error::from)
    })
    .await?
}

fn is_v2_status_representation_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<nq_core::engine::EngineError>(),
        Some(nq_core::engine::EngineError::Invariant(message))
            if message == "nq.status_snapshot.v2 cannot emit governed evaluation results; use v3"
    )
}

async fn read_status_v3(database_path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let snapshot = nq_core::engine::status_snapshot_v3(&store)?;
        serde_json::to_vec(&snapshot).map_err(anyhow::Error::from)
    })
    .await?
}

async fn read_evaluations(
    database_path: PathBuf,
    limit: u32,
    after_sequence: Option<u64>,
    through_sequence: Option<u64>,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let page = nq_core::engine::evaluation_history_bounded(
            &store,
            limit,
            after_sequence,
            through_sequence,
        )?;
        serde_json::to_vec(&page).map_err(anyhow::Error::from)
    })
    .await?
}

fn is_evaluation_query_bound_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<nq_core::engine::EngineError>(),
        Some(nq_core::engine::EngineError::Invariant(message))
            if message == "evaluation history cursor or frozen upper bound is not present"
                || message == "evaluation history continuation requires its frozen upper bound"
                || message == "evaluation history cursor overflowed"
                || message == "evaluation history bound overflowed"
    )
}

async fn read_findings(
    database_path: PathBuf,
    limit: u32,
    after_finding_id: Option<String>,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let findings =
            nq_core::engine::list_findings_bounded(&store, limit, after_finding_id.as_deref())?;
        serde_json::to_vec(&findings).map_err(anyhow::Error::from)
    })
    .await?
}

async fn read_all_findings(database_path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let findings = nq_core::engine::list_findings(&store)?;
        serde_json::to_vec(&findings).map_err(anyhow::Error::from)
    })
    .await?
}

async fn read_rejected_custody(
    database_path: PathBuf,
    limit: u32,
    after_submission_id: Option<String>,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open_read_only(database_path)?;
        let snapshot = nq_core::engine::rejected_custody_snapshot_bounded(
            &store,
            limit,
            after_submission_id.as_deref(),
        )?;
        serde_json::to_vec(&snapshot).map_err(anyhow::Error::from)
    })
    .await?
}

fn parse_rejected_custody_query(
    query: Option<&str>,
) -> std::result::Result<RejectedCustodyQuery, &'static str> {
    let Some(query) = query else {
        return Ok(RejectedCustodyQuery {
            limit: MAX_REJECTED_CUSTODY_PER_RESPONSE,
            after_submission_id: None,
        });
    };
    if query.is_empty() {
        return Err("query string must not be empty");
    }

    let mut limit = None;
    let mut after_submission_id = None;
    for parameter in query.split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err("every query parameter must have exactly one value");
        };
        if name.is_empty() || value.is_empty() || value.contains('=') {
            return Err("every query parameter must have exactly one non-empty value");
        }
        match name {
            "limit" => {
                if limit.is_some() {
                    return Err("limit must not be repeated");
                }
                if !is_canonical_decimal(value) {
                    return Err("limit must be a canonical positive decimal integer");
                }
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| "limit is outside the supported integer range")?;
                if !(1..=MAX_REJECTED_CUSTODY_PER_RESPONSE).contains(&parsed) {
                    return Err("limit must be between 1 and 1000");
                }
                limit = Some(parsed);
            }
            "after" => {
                if after_submission_id.is_some() {
                    return Err("after must not be repeated");
                }
                if !is_stable_cursor_token(value) {
                    return Err("after must be an unescaped stable submission-ID token");
                }
                after_submission_id = Some(value.to_owned());
            }
            _ => return Err("unknown query parameter"),
        }
    }

    Ok(RejectedCustodyQuery {
        limit: limit.unwrap_or(MAX_REJECTED_CUSTODY_PER_RESPONSE),
        after_submission_id,
    })
}

fn parse_findings_query(query: Option<&str>) -> std::result::Result<FindingsQuery, &'static str> {
    let Some(query) = query else {
        return Ok(FindingsQuery {
            limit: MAX_FINDINGS_PER_RESPONSE,
            after_finding_id: None,
        });
    };
    if query.is_empty() {
        return Err("query string must not be empty");
    }

    let mut limit = None;
    let mut after_finding_id = None;
    for parameter in query.split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err("every query parameter must have exactly one value");
        };
        if name.is_empty() || value.is_empty() || value.contains('=') {
            return Err("every query parameter must have exactly one non-empty value");
        }
        match name {
            "limit" => {
                if limit.is_some() {
                    return Err("limit must not be repeated");
                }
                if !is_canonical_decimal(value) {
                    return Err("limit must be a canonical positive decimal integer");
                }
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| "limit is outside the supported integer range")?;
                if !(1..=MAX_FINDINGS_PER_RESPONSE).contains(&parsed) {
                    return Err("limit must be between 1 and 1000");
                }
                limit = Some(parsed);
            }
            "after" => {
                if after_finding_id.is_some() {
                    return Err("after must not be repeated");
                }
                if !is_stable_cursor_token(value) {
                    return Err("after must be an unescaped stable finding-ID token");
                }
                after_finding_id = Some(value.to_owned());
            }
            _ => return Err("unknown query parameter"),
        }
    }

    Ok(FindingsQuery {
        limit: limit.unwrap_or(MAX_FINDINGS_PER_RESPONSE),
        after_finding_id,
    })
}

fn parse_evaluation_history_query(
    query: Option<&str>,
) -> std::result::Result<EvaluationHistoryQuery, &'static str> {
    let Some(query) = query else {
        return Ok(EvaluationHistoryQuery {
            limit: MAX_EVALUATIONS_PER_RESPONSE,
            after_sequence: None,
            through_sequence: None,
        });
    };
    if query.is_empty() {
        return Err("query string must not be empty");
    }

    let mut limit = None;
    let mut after_sequence = None;
    let mut through_sequence = None;
    for parameter in query.split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err("every query parameter must have exactly one value");
        };
        if name.is_empty() || value.is_empty() || value.contains('=') {
            return Err("every query parameter must have exactly one non-empty value");
        }
        match name {
            "limit" => {
                if limit.is_some() {
                    return Err("limit must not be repeated");
                }
                if !is_canonical_decimal(value) {
                    return Err("limit must be a canonical positive decimal integer");
                }
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| "limit is outside the supported integer range")?;
                if !(1..=MAX_EVALUATIONS_PER_RESPONSE).contains(&parsed) {
                    return Err("limit must be between 1 and 1000");
                }
                limit = Some(parsed);
            }
            "after" => {
                if after_sequence.is_some() {
                    return Err("after must not be repeated");
                }
                if !is_canonical_nonnegative_decimal(value) {
                    return Err("after must be a canonical nonnegative decimal integer");
                }
                after_sequence = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "after is outside the supported integer range")?,
                );
            }
            "through" => {
                if through_sequence.is_some() {
                    return Err("through must not be repeated");
                }
                if !is_canonical_nonnegative_decimal(value) {
                    return Err("through must be a canonical nonnegative decimal integer");
                }
                through_sequence = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "through is outside the supported integer range")?,
                );
            }
            _ => return Err("unknown query parameter"),
        }
    }

    if after_sequence.is_some() && through_sequence.is_none() {
        return Err("after requires the frozen through bound returned by the first page");
    }
    if after_sequence
        .zip(through_sequence)
        .is_some_and(|(after, through)| after > through)
    {
        return Err("after must not exceed through");
    }
    Ok(EvaluationHistoryQuery {
        limit: limit.unwrap_or(MAX_EVALUATIONS_PER_RESPONSE),
        after_sequence,
        through_sequence,
    })
}

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_canonical_nonnegative_decimal(value: &str) -> bool {
    value == "0" || is_canonical_decimal(value)
}

fn is_stable_cursor_token(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
        })
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("unexpected EOF reading request");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HTTP_REQUEST_BYTES {
            bail!("HTTP request exceeds {MAX_HTTP_REQUEST_BYTES} bytes");
        }
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(buffer).context("HTTP request is not UTF-8")
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        409 => "Conflict",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

fn prepare_socket(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => match StdUnixStream::connect(path) {
            Ok(_) => bail!("refusing to replace live Unix socket {}", path.display()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                std::fs::remove_file(path)?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot prove socket {} is stale", path.display()));
            }
        },
        Ok(_) => bail!("refusing to replace non-socket path {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn render_console(status: &[u8], findings: &[u8]) -> String {
    let status = html_escape(&String::from_utf8_lossy(status));
    let findings = html_escape(&String::from_utf8_lossy(findings));
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>NQ-ng console</title><style>\
         body{{font:15px system-ui,sans-serif;max-width:80rem;margin:2rem auto;padding:0 1rem;color:#18202a}}\
         h1,h2{{font-weight:600}}pre{{white-space:pre-wrap;background:#f4f6f8;padding:1rem;border-radius:.4rem;overflow:auto}}\
         .note{{color:#53606d}}</style></head><body><h1>NQ-ng</h1>\
         <p class=\"note\">Read-only local evidence console. Collection is scheduled independently of this page.</p>\
         <h2>Status</h2><pre>{status}</pre><h2>Findings</h2><pre>{findings}</pre></body></html>"
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Parse and reject non-loopback console addresses.
///
/// # Errors
///
/// Returns when parsing fails or the literal IP is not loopback.
pub fn parse_loopback(value: &str) -> Result<SocketAddr> {
    let address: SocketAddr = value.parse()?;
    match address.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => Ok(address),
        IpAddr::V6(ip) if ip.is_loopback() => Ok(address),
        _ => bail!("console address must resolve literally to loopback"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use chrono::{DateTime, Utc};
    use nq_core::config::{ScopeConfig, VantageConfig};
    use nq_core::engine::{
        AdmissionRefusal, AdmissionRefusalBoundary, AdmissionRefusalCode, AdmissionRefusalDetails,
        CollectionOutcome, CollectionResult, EvaluationContextV1, EvaluationDetectorIdentity,
        EvaluationEnvelopeSchema, EvaluationEnvelopeV2, EvaluationProfileIdentity,
        EvaluationResultSchema, EvaluationResultV1, EvaluationWatermarkV2, GovernedRefusal,
        GovernedRefusalOrigin, RunHardLimits, RunResourceOutcomeSchema, RunResourceOutcomeV1,
    };
    use nq_core::runner::{AcquisitionOutcome, ExchangeTimeoutPhase};
    use nq_profiles::{
        DetectorState, EvidenceWatermark, ProfileKey, ProfileRefusal, ProfileRefusalCode,
        RefusalBoundary as ProfileRefusalBoundary, profile_semantic_id,
    };
    use nq_protocol::{InstanceId, Refusal, RefusalBoundary, RefusalCode, Sha256Digest};
    use nq_store::{
        AdmissionIdentity, AdmissionInput, BindingEventInput, BindingMaterializationInput,
        CanonicalDocument, CollectionInput, EvaluationInput, EvaluationProfileBinding,
        EvaluationWatermark, FindingEventInput, ProfileDescriptorInput, ProviderIntakeInput,
        RefusalInput, RunInput, RunResultStatusInput, StatusEventInput, SubmissionDisposition,
        SubmissionInput,
    };
    use serde_json::{Value, json};

    const TEST_TIME: &str = "2026-07-20T12:00:00Z";

    fn document(value: &impl serde::Serialize) -> CanonicalDocument {
        CanonicalDocument::from_serializable(value).expect("fixture document canonicalizes")
    }

    fn helper_rejection(
        instance_id: &str,
        run_id: &str,
        refusal_id: &str,
        retriable: bool,
        details: Value,
    ) -> (CollectionOutcome, GovernedRefusal) {
        let refusal = GovernedRefusal::helper(
            refusal_id.to_owned(),
            Refusal {
                responsible_instance_id: InstanceId::new(instance_id).expect("instance token"),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "backend collection failed".to_owned(),
                retriable,
                details,
            },
        );
        (
            CollectionOutcome::rejected(instance_id.to_owned(), run_id.to_owned(), refusal.clone()),
            refusal,
        )
    }

    fn helper_admission_refusal(
        instance_id: &str,
        refusal_id: &str,
        retriable: bool,
        details: Value,
    ) -> (CollectionOutcome, GovernedRefusal) {
        let refusal = GovernedRefusal::helper(
            refusal_id.to_owned(),
            Refusal {
                responsible_instance_id: InstanceId::new(instance_id).expect("instance token"),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "helper refused before run admission".to_owned(),
                retriable,
                details,
            },
        );
        let admission = AdmissionRefusal {
            responsible_instance_id: instance_id.to_owned(),
            boundary: AdmissionRefusalBoundary::Protocol,
            code: AdmissionRefusalCode::UpstreamRefusal,
            details: AdmissionRefusalDetails::Governed {
                refusal: Box::new(refusal.clone()),
            },
        };
        (
            CollectionOutcome::admission_refused(instance_id.to_owned(), admission),
            refusal,
        )
    }

    fn profile_rejection(
        instance_id: &str,
        run_id: &str,
        refusal_id: &str,
        profile_id: &str,
        profile_version: u32,
        boundary: ProfileRefusalBoundary,
        details: BTreeMap<String, String>,
    ) -> (CollectionOutcome, GovernedRefusal) {
        let profile = nq_profiles::resolve_profile(profile_id, profile_version)
            .expect("profile refusal fixture uses a compiled profile");
        let refusal = GovernedRefusal::profile(
            refusal_id.to_owned(),
            profile_semantic_id(profile.descriptor()).expect("profile semantic identity"),
            ProfileRefusal {
                instance_id: instance_id.to_owned(),
                profile: ProfileKey::new(profile_id, profile_version),
                boundary,
                code: ProfileRefusalCode::InvalidPayload,
                message: "payload is invalid".to_owned(),
                details,
            },
        );
        (
            CollectionOutcome::rejected(instance_id.to_owned(), run_id.to_owned(), refusal.clone()),
            refusal,
        )
    }

    fn append_fixture_descriptor(store: &mut Store, profile_id: &str, version: u32) -> String {
        let descriptor = nq_profiles::resolve_profile(profile_id, version).map_or_else(
            || {
                document(&json!({
                    "profile": {"id": profile_id, "version": version},
                    "fixture": "semantic-transport",
                }))
            },
            |profile| document(profile.descriptor()),
        );
        let digest = descriptor.digest().to_owned();
        if store
            .profile_descriptor(profile_id, &version.to_string(), &digest)
            .expect("read fixture descriptor")
            .is_none()
        {
            store
                .append_profile_descriptor(&ProfileDescriptorInput {
                    profile_id: profile_id.to_owned(),
                    profile_version: version.to_string(),
                    descriptor,
                    recorded_at: TEST_TIME.to_owned(),
                })
                .expect("append fixture descriptor");
        }
        digest
    }

    fn resource_document(
        outcome: AcquisitionOutcome,
        stdout_bytes_retained: usize,
    ) -> CanonicalDocument {
        document(&RunResourceOutcomeV1 {
            schema: RunResourceOutcomeSchema::V1,
            duration_ms: 1,
            exit_code: Some(0),
            hard_limits: RunHardLimits {
                address_space_bytes_per_process: 1,
                cpu_seconds_per_process: 1,
                processes_per_execution_uid: 1,
                open_files_per_process: 1,
                file_bytes_per_regular_file: 1,
                core_bytes: 0,
            },
            stdout_bytes_retained,
            stderr_bytes_retained: 0,
            stderr_hex: String::new(),
            outcome,
        })
    }

    fn append_run_admission(
        store: &mut Store,
        _suffix: &str,
        instance_id: &str,
        profile_id: &str,
        profile_version: u32,
        profile_digest: &str,
    ) -> String {
        let profile = nq_profiles::resolve_profile(profile_id, profile_version)
            .expect("run admission uses a compiled profile");
        let semantic_id =
            profile_semantic_id(profile.descriptor()).expect("compiled profile semantic identity");
        let admission_id = uuid::Uuid::new_v4().to_string();
        let digest = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
        store
            .append_admission(&AdmissionInput {
                admission_id: admission_id.clone(),
                instance_id: instance_id.to_owned(),
                identity: AdmissionIdentity {
                    profile_semantic_id: Sha256Digest::parse(semantic_id.as_str())
                        .expect("semantic identity is a digest"),
                    detector_identity_digest: nq_store::detector_suite_identity_digest(
                        profile.detectors().iter().map(|detector| {
                            detector
                                .descriptor()
                                .digest()
                                .expect("compiled detector identity")
                        }),
                    )
                    .expect("compiled detector suite identity"),
                    evaluator_source_digest: Sha256Digest::parse(
                        nq_profiles::EVALUATOR_SOURCE_DIGEST.to_owned(),
                    )
                    .expect("compiled evaluator source identity"),
                    evaluator_artifact_digest: digest("evaluator"),
                    helper_artifact_digest: digest("helper"),
                    config_digest: digest("config"),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    target_triple: "fixture-target".to_owned(),
                    artifact_identity_method: "fixture".to_owned(),
                    platform_runtime_version: "fixture".to_owned(),
                },
                execution_chain: document(&json!({"fixture": true})),
                profile_id: profile_id.to_owned(),
                profile_version: profile_version.to_string(),
                profile_digest: profile_digest.to_owned(),
                capability_grant: document(&json!([])),
                conformance: document(&json!({"fixture": true})),
                lock: document(&json!({"fixture": true})),
                admitted_at: TEST_TIME.to_owned(),
                operator_identity: document(&json!({"fixture": true})),
            })
            .expect("append governing run admission");
        admission_id
    }

    /// Store-structural fixture for API projection tests. Its synthetic JSON
    /// is intentionally not cited as typed provider-intake reopen evidence.
    #[allow(clippy::too_many_lines)]
    fn fixture_provider_collection(
        store: &mut Store,
        mut run: RunInput,
        submission: Option<SubmissionInput>,
        interpretation_kind: &str,
        interpretation: CanonicalDocument,
    ) -> CollectionInput {
        let admission_id = run
            .admission_id
            .as_deref()
            .expect("provider fixture run has an admission")
            .to_owned();
        let admission = store
            .admission(&admission_id)
            .expect("read fixture provider admission")
            .expect("fixture provider admission exists");
        run.binding_digest = CanonicalDocument::from_canonical_bytes(admission.lock_json.clone())
            .expect("fixture source lock canonical")
            .digest()
            .to_owned();
        let event_id = uuid::Uuid::new_v4().to_string();
        let operation_id = uuid::Uuid::new_v4().to_string();
        store
            .begin_binding_transition(
                &BindingEventInput {
                    binding_event_id: event_id.clone(),
                    instance_id: run.instance_id.clone(),
                    event_kind: "activate".to_owned(),
                    admission_id: Some(admission_id.clone()),
                    binding_digest: run.binding_digest.clone(),
                    occurred_at: TEST_TIME.to_owned(),
                    reason_code: Some("provider_intake_fixture".to_owned()),
                    detail: document(&json!({"fixture": true})),
                },
                &BindingMaterializationInput {
                    materialization_event_id: uuid::Uuid::new_v4().to_string(),
                    operation_id: operation_id.clone(),
                    instance_id: run.instance_id.clone(),
                    binding_event_id: event_id.clone(),
                    phase: "intent".to_owned(),
                    occurred_at: TEST_TIME.to_owned(),
                    detail: document(&json!({"fixture": true})),
                },
            )
            .expect("activate fixture provider admission");
        store
            .complete_binding_materialization(&BindingMaterializationInput {
                materialization_event_id: uuid::Uuid::new_v4().to_string(),
                operation_id,
                instance_id: run.instance_id.clone(),
                binding_event_id: event_id,
                phase: "completed".to_owned(),
                occurred_at: TEST_TIME.to_owned(),
                detail: document(&json!({"fixture": true})),
            })
            .expect("complete fixture provider binding");

        let provider = store
            .provider_admission_for_source(&admission_id)
            .expect("read derived provider admission")
            .expect("derived provider admission exists");
        let raw_bytes = submission
            .as_ref()
            .map_or_else(Vec::new, |submission| submission.raw_bytes.clone());
        let received_at = submission.as_ref().map_or_else(
            || run.finished_at.clone(),
            |submission| submission.received_at.clone(),
        );
        let attempt_id = format!("attempt-{}", run.run_id);
        let idempotency_key =
            nq_store::provider_idempotency_key(&provider.provider_admission_id, &attempt_id)
                .expect("provider idempotency identity");
        let intake = ProviderIntakeInput {
            intake_id: format!("intake-{}", run.run_id),
            idempotency_key,
            attempt_id,
            request_id: run.request_id.clone(),
            provider_admission_id: provider.provider_admission_id,
            source_admission_id: admission_id,
            provider_sequence: None,
            origin_carrier: run.carrier.clone(),
            deadline_at: run.deadline_at.clone(),
            checkpoint_contract_digest: run.checkpoint_contract_digest.clone(),
            execution_identity_digest: Sha256Digest::parse(
                run.execution_identity.digest().to_owned(),
            )
            .expect("execution identity digest"),
            admission_context_digest: Sha256Digest::parse(admission.admission_context_digest)
                .expect("admission context digest"),
            provider_semantic_id: Sha256Digest::parse(provider.provider_semantic_id)
                .expect("provider semantic identity"),
            provider_artifact_digest: Sha256Digest::parse(provider.provider_artifact_digest)
                .expect("provider artifact digest"),
            provider_protocol_identity: provider.provider_protocol_identity,
            provider_config_digest: Sha256Digest::parse(provider.provider_config_digest)
                .expect("provider config digest"),
            binding_digest: run.binding_digest.clone(),
            instance_id: run.instance_id.clone(),
            profile_id: run.profile_id.clone(),
            profile_version: run.profile_version.clone(),
            profile_digest: run.profile_digest.clone(),
            profile_semantic_id: Sha256Digest::parse(admission.profile_semantic_id)
                .expect("profile semantic identity"),
            evaluator_artifact_digest: Sha256Digest::parse(admission.evaluator_artifact_digest)
                .expect("evaluator artifact digest"),
            context: document(&json!({
                "schema": "fixture.provider_intake_context.v1",
                "subject": run.instance_id.clone(),
                "scope": {"kind": "fixture"},
                "vantage": {"kind": "local"},
                "requested_capabilities": [],
            })),
            interpretation_kind: interpretation_kind.to_owned(),
            interpretation,
            native_outcome_kind: run.acquisition_outcome.clone(),
            native_outcome: run.resource_outcome.clone(),
            raw_bytes,
            started_at: run.started_at.clone(),
            finished_at: run.finished_at.clone(),
            received_at,
        };
        CollectionInput {
            intake,
            run,
            submission,
        }
    }

    struct EvaluationSurfaceFixture {
        finding_id: String,
        refusal: GovernedRefusal,
        latest_evaluation: EvaluationEnvelopeV2,
    }

    #[allow(clippy::too_many_lines)]
    fn seed_present_then_refused_evaluation(
        store: &mut Store,
        suffix: &str,
        details: BTreeMap<String, String>,
        with_prior_finding: bool,
    ) -> EvaluationSurfaceFixture {
        let module = nq_profiles::resolve_profile("nq.host", 1)
            .expect("evaluation fixture uses the compiled host profile");
        let profile = module.descriptor().profile.clone();
        let profile_digest = append_fixture_descriptor(store, &profile.id, profile.version);
        let semantic_id = profile_semantic_id(module.descriptor()).expect("profile semantic ID");
        let semantic_digest = Sha256Digest::parse(semantic_id.as_str())
            .expect("profile semantic identity is a digest");
        let evaluation_profile = EvaluationProfileIdentity {
            profile: profile.clone(),
            profile_digest: module.descriptor().digest().expect("profile digest"),
            profile_semantic_id: semantic_id.clone(),
        };
        let instance_id = format!("evaluation-{suffix}");
        let subject = format!("host:{suffix}");
        let scope = ScopeConfig {
            kind: "host".to_owned(),
            value: json!({"id": suffix}),
        };
        let vantage = VantageConfig {
            kind: "local".to_owned(),
            value: json!({}),
        };
        let detector = module.detectors()[0].descriptor();
        let detector_id = detector.id.clone();
        let detector_digest = detector.digest().expect("compiled detector digest").clone();
        let finding_id = format!("finding-evaluation-{suffix}");
        let condition = detector.condition.clone();
        let evaluated_at: DateTime<Utc> = TEST_TIME.parse().expect("fixture timestamp");
        let evaluator_artifact_digest = nq_protocol::sha256_bytes(b"api-evaluator");
        let profile_binding = EvaluationProfileBinding {
            profile_id: profile.id.clone(),
            profile_version: profile.version.to_string(),
            profile_digest: profile_digest.clone(),
            profile_semantic_id: semantic_digest,
        };
        let watermarks = vec![EvaluationWatermark {
            instance_id: instance_id.clone(),
            max_report_sequence: 0,
            watermark_received_at: None,
        }];
        let present = EvaluationResultV1 {
            schema: EvaluationResultSchema::V1,
            profile: evaluation_profile.clone(),
            state: DetectorState::Present,
            condition: condition.clone(),
            summary: "condition is present".to_owned(),
            evidence: Vec::new(),
            limitations: Vec::new(),
            refusal: None,
            watermark: EvidenceWatermark(0),
        };
        let opened = FindingEventInput {
            event_id: format!("event-evaluation-{suffix}-opened"),
            finding_id: finding_id.clone(),
            event_kind: "opened".to_owned(),
            instance_id: instance_id.clone(),
            profile_id: profile.id.clone(),
            profile_version: profile.version.to_string(),
            profile_digest: profile_digest.clone(),
            subject: document(&subject),
            condition_name: condition.clone(),
            condition_state: "present".to_owned(),
            visibility_state: "sufficient".to_owned(),
            operator_work_state: "unreviewed".to_owned(),
            severity: "warning".to_owned(),
            summary: "condition is present".to_owned(),
            limitations: document(&Vec::<String>::new()),
            safe_next_checks: document(&vec![
                "Inspect the cited admitted evidence".to_owned(),
                "Run `nq watcher test` if collection remains unavailable".to_owned(),
            ]),
            freshness: document(&json!({"state": "current"})),
            basis: document(&json!({
                "profile_digest": profile_digest,
                "scope": scope,
                "vantage": vantage,
            })),
            refusal: None,
            origin_mode: "native".to_owned(),
            historical_refs: document(&Vec::<String>::new()),
            observed_at: None,
            received_at: None,
            created_at: TEST_TIME.to_owned(),
            evidence: Vec::new(),
        };
        let present_id = format!("evaluation-{suffix}-present");
        let present_envelope = EvaluationEnvelopeV2 {
            schema: EvaluationEnvelopeSchema::V2,
            evaluation_id: present_id.clone(),
            trigger_run_id: None,
            context: EvaluationContextV1 {
                instance_id: instance_id.clone(),
                subject: subject.clone(),
                scope: scope.clone(),
                vantage: vantage.clone(),
            },
            detector: EvaluationDetectorIdentity {
                id: detector_id.clone(),
                version: detector.version.to_string(),
                digest: detector_digest.clone(),
            },
            evaluator_artifact_digest: evaluator_artifact_digest.clone(),
            profile: evaluation_profile.clone(),
            started_at: evaluated_at,
            evaluated_at,
            watermark: EvaluationWatermarkV2 {
                instance_id: instance_id.clone(),
                max_report_sequence: 0,
                watermark_received_at: None,
            },
            result: present,
        };
        if with_prior_finding {
            store
                .commit_evaluation(
                    &EvaluationInput {
                        evaluation_id: present_id,
                        trigger_run_id: None,
                        detector_id: detector_id.clone(),
                        detector_version: detector.version.to_string(),
                        detector_digest: detector_digest.clone(),
                        evaluator_artifact_digest: evaluator_artifact_digest.to_string(),
                        started_at: TEST_TIME.to_owned(),
                        evaluated_at: TEST_TIME.to_owned(),
                        outcome: "condition_present".to_owned(),
                        detail: document(&present_envelope),
                        profile: profile_binding.clone(),
                        watermarks: watermarks.clone(),
                        refusal: None,
                    },
                    Some(&opened),
                )
                .expect("open a policy-valid present finding");
        }

        let source_refusal = ProfileRefusal {
            instance_id: instance_id.clone(),
            profile,
            boundary: ProfileRefusalBoundary::Detector,
            code: ProfileRefusalCode::CannotEvaluate,
            message: "insufficient current evidence".to_owned(),
            details,
        };
        let refusal = GovernedRefusal::profile(
            format!("refusal-evaluation-{suffix}"),
            semantic_id,
            source_refusal,
        );
        let refused = EvaluationResultV1 {
            schema: EvaluationResultSchema::V1,
            profile: evaluation_profile.clone(),
            state: DetectorState::CannotEvaluate,
            condition,
            summary: "insufficient current evidence".to_owned(),
            evidence: Vec::new(),
            limitations: vec!["evaluation refused at the typed profile boundary".to_owned()],
            refusal: Some(refusal.clone()),
            watermark: EvidenceWatermark(0),
        };
        let mut updated = opened;
        updated.event_id = format!("event-evaluation-{suffix}-refused");
        updated.event_kind = "updated".to_owned();
        // A refusal changes visibility, not the already-established condition.
        updated.visibility_state = "missing".to_owned();
        updated.limitations = document(&refused.limitations);
        updated.freshness = document(&json!({"state": "missing"}));
        updated.refusal = Some(document(&refusal));
        let refused_id = format!("evaluation-{suffix}-refused");
        let refused_envelope = EvaluationEnvelopeV2 {
            schema: EvaluationEnvelopeSchema::V2,
            evaluation_id: refused_id.clone(),
            trigger_run_id: None,
            context: EvaluationContextV1 {
                instance_id: instance_id.clone(),
                subject,
                scope,
                vantage,
            },
            detector: EvaluationDetectorIdentity {
                id: detector_id.clone(),
                version: detector.version.to_string(),
                digest: detector_digest.clone(),
            },
            evaluator_artifact_digest: evaluator_artifact_digest.clone(),
            profile: evaluation_profile,
            started_at: evaluated_at,
            evaluated_at,
            watermark: EvaluationWatermarkV2 {
                instance_id: instance_id.clone(),
                max_report_sequence: 0,
                watermark_received_at: None,
            },
            result: refused,
        };
        store
            .commit_evaluation(
                &EvaluationInput {
                    evaluation_id: refused_id,
                    trigger_run_id: None,
                    detector_id,
                    detector_version: detector.version.to_string(),
                    detector_digest,
                    evaluator_artifact_digest: evaluator_artifact_digest.to_string(),
                    started_at: TEST_TIME.to_owned(),
                    evaluated_at: TEST_TIME.to_owned(),
                    outcome: "cannot_evaluate".to_owned(),
                    detail: document(&refused_envelope),
                    profile: profile_binding,
                    watermarks,
                    refusal: Some(RefusalInput {
                        refusal_id: refusal.refusal_id.clone(),
                        source_kind: "profile".to_owned(),
                        responsible_instance_id: instance_id,
                        boundary: "detector".to_owned(),
                        code: "cannot_evaluate".to_owned(),
                        profile_semantic_id: Some(match &refusal.origin {
                            GovernedRefusalOrigin::Profile(profile) => {
                                profile.profile_semantic_id.as_str().to_owned()
                            }
                            _ => unreachable!("fixture refusal is profile-origin"),
                        }),
                        detail: document(&refusal),
                        created_at: TEST_TIME.to_owned(),
                    }),
                },
                with_prior_finding.then_some(&updated),
            )
            .expect("commit a typed evaluation refusal");

        EvaluationSurfaceFixture {
            finding_id,
            refusal,
            latest_evaluation: refused_envelope,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_rejected_result(
        store: &mut Store,
        profile_id: &str,
        profile_version: u32,
        profile_digest: &str,
        suffix: &str,
        outcome: &CollectionOutcome,
        refusal: &GovernedRefusal,
        state: &str,
        status_code: &str,
    ) {
        let instance_id = outcome.instance_id().to_owned();
        let run_id = outcome.run_id.as_deref().expect("rejection has run");
        let (source_kind, boundary, code, profile_semantic_id, protocol_outcome) =
            match &refusal.origin {
                GovernedRefusalOrigin::Helper(source) => (
                    "protocol",
                    serde_json::to_value(source.boundary).expect("boundary serializes"),
                    serde_json::to_value(source.code).expect("code serializes"),
                    None,
                    "valid_refusal",
                ),
                GovernedRefusalOrigin::Profile(source) => (
                    "profile",
                    serde_json::to_value(source.refusal.boundary).expect("boundary serializes"),
                    serde_json::to_value(source.refusal.code).expect("code serializes"),
                    Some(source.profile_semantic_id.as_str().to_owned()),
                    "valid_report",
                ),
                other => panic!("unsupported fixture refusal origin: {other:?}"),
            };
        let admission_id = append_run_admission(
            store,
            suffix,
            &instance_id,
            profile_id,
            profile_version,
            profile_digest,
        );
        let run = RunInput {
            run_id: run_id.to_owned(),
            request_id: format!("request-{suffix}"),
            instance_id: instance_id.clone(),
            admission_id: Some(admission_id),
            binding_digest: nq_protocol::sha256_bytes(b"binding").into_string(),
            checkpoint_contract_digest: nq_protocol::sha256_bytes(b"checkpoint").into_string(),
            profile_id: profile_id.to_owned(),
            profile_version: profile_version.to_string(),
            profile_digest: profile_digest.to_owned(),
            carrier: "stdio".to_owned(),
            started_at: TEST_TIME.to_owned(),
            deadline_at: TEST_TIME.to_owned(),
            finished_at: TEST_TIME.to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: document(&json!({"fixture": true})),
            resource_outcome: resource_document(
                AcquisitionOutcome::Response,
                format!("rejected-{suffix}").len(),
            ),
        };
        let submission = SubmissionInput {
            submission_id: format!("submission-{suffix}"),
            raw_bytes: format!("rejected-{suffix}").into_bytes(),
            received_at: TEST_TIME.to_owned(),
            protocol_outcome: protocol_outcome.to_owned(),
            disposition: SubmissionDisposition::Rejected {
                refusal: RefusalInput {
                    refusal_id: refusal.refusal_id.clone(),
                    source_kind: source_kind.to_owned(),
                    responsible_instance_id: instance_id.clone(),
                    boundary: boundary.as_str().expect("boundary is token").to_owned(),
                    code: code.as_str().expect("code is token").to_owned(),
                    profile_semantic_id,
                    detail: document(refusal),
                    created_at: TEST_TIME.to_owned(),
                },
            },
        };
        let interpretation_kind = if protocol_outcome == "valid_refusal" {
            "provider_refusal"
        } else {
            "candidate_report"
        };
        let collection = fixture_provider_collection(
            store,
            run,
            Some(submission),
            interpretation_kind,
            document(&json!({
                "schema": "fixture.provider_interpretation.v1",
                "native_outcome": protocol_outcome,
                "governed_refusal": refusal,
            })),
        );
        store
            .commit_non_success_collection(
                &collection,
                &RunResultStatusInput {
                    run_id: run_id.to_owned(),
                    status: StatusEventInput {
                        status_event_id: uuid::Uuid::new_v4().to_string(),
                        component_kind: "instance".to_owned(),
                        component_id: instance_id,
                        state: state.to_owned(),
                        code: status_code.to_owned(),
                        detail: document(outcome),
                        observed_at: TEST_TIME.to_owned(),
                    },
                },
            )
            .expect("atomically commit rejected custody and canonical status");
    }

    fn seed_acquisition_result(
        store: &mut Store,
        profile_digest: &str,
        suffix: &str,
        outcome: &CollectionOutcome,
    ) {
        let instance_id = outcome.instance_id().to_owned();
        let run_id = outcome.run_id.as_deref().expect("acquisition has run");
        let CollectionResult::AcquisitionFailed { failure } = &outcome.result else {
            panic!("acquisition fixture must carry acquisition failure");
        };
        let admission_id = append_run_admission(
            store,
            suffix,
            &instance_id,
            "nq.conformance",
            1,
            profile_digest,
        );
        let run = RunInput {
            run_id: run_id.to_owned(),
            request_id: format!("request-{suffix}"),
            instance_id: instance_id.clone(),
            admission_id: Some(admission_id),
            binding_digest: nq_protocol::sha256_bytes(b"binding").into_string(),
            checkpoint_contract_digest: nq_protocol::sha256_bytes(b"checkpoint").into_string(),
            profile_id: "nq.conformance".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.to_owned(),
            carrier: "unix".to_owned(),
            started_at: TEST_TIME.to_owned(),
            deadline_at: TEST_TIME.to_owned(),
            finished_at: TEST_TIME.to_owned(),
            acquisition_outcome: "timeout".to_owned(),
            execution_identity: document(&json!({"fixture": true})),
            resource_outcome: resource_document(failure.outcome.clone(), 0),
        };
        let collection =
            fixture_provider_collection(store, run, None, "unavailable", document(&Value::Null));
        store
            .commit_non_success_collection(
                &collection,
                &RunResultStatusInput {
                    run_id: run_id.to_owned(),
                    status: StatusEventInput {
                        status_event_id: uuid::Uuid::new_v4().to_string(),
                        component_kind: "instance".to_owned(),
                        component_id: instance_id,
                        state: "failed".to_owned(),
                        code: "collection_failed".to_owned(),
                        detail: document(outcome),
                        observed_at: TEST_TIME.to_owned(),
                    },
                },
            )
            .expect("atomically commit acquisition failure and canonical status");
    }

    fn seed_admission_refusal_status(store: &mut Store, outcome: &CollectionOutcome) {
        store
            .record_status(&StatusEventInput {
                status_event_id: uuid::Uuid::new_v4().to_string(),
                component_kind: "instance".to_owned(),
                component_id: outcome.instance_id().to_owned(),
                state: "failed".to_owned(),
                code: "admission_refused".to_owned(),
                detail: document(outcome),
                observed_at: TEST_TIME.to_owned(),
            })
            .expect("persist exact typed admission refusal status");
    }

    async fn get_response(path: &str, database_path: PathBuf) -> (u16, Value) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(handle_connection(server, database_path));
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: local\r\n\r\n").as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        task.await
            .expect("request task joins")
            .expect("request succeeds");
        let response = String::from_utf8(response).expect("HTTP response is UTF-8");
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .expect("HTTP response has body");
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse().ok())
            .expect("HTTP status code");
        (
            status,
            serde_json::from_str(body).expect("HTTP body is JSON"),
        )
    }

    async fn get_json(path: &str, database_path: PathBuf) -> Value {
        let (status, body) = get_response(path, database_path).await;
        assert_eq!(status, 200);
        body
    }

    #[test]
    fn console_binding_is_loopback_only() {
        assert!(parse_loopback("127.0.0.1:8787").is_ok());
        assert!(parse_loopback("[::1]:8787").is_ok());
        assert!(parse_loopback("0.0.0.0:8787").is_err());
    }

    #[test]
    fn console_escapes_embedded_json_strings() {
        let html = render_console(br#"{"x":"<script>"}"#, b"[]");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn rejected_custody_query_is_strict_and_unescaped() {
        assert_eq!(
            parse_rejected_custody_query(None).expect("default page"),
            RejectedCustodyQuery {
                limit: 1_000,
                after_submission_id: None,
            }
        );
        assert_eq!(
            parse_rejected_custody_query(Some("after=submission-a&limit=1"))
                .expect("explicit bounded page"),
            RejectedCustodyQuery {
                limit: 1,
                after_submission_id: Some("submission-a".to_owned()),
            }
        );
        for invalid in [
            "",
            "limit=0",
            "limit=01",
            "limit=1001",
            "limit=1&limit=2",
            "after=one&after=two",
            "after=submission%2Done",
            "after=submission+one",
            "unknown=value",
            "limit",
            "limit=1=2",
            "limit=1&&after=submission-one",
        ] {
            assert!(
                parse_rejected_custody_query(Some(invalid)).is_err(),
                "query must fail closed: {invalid}"
            );
        }
    }

    #[test]
    fn findings_query_is_strict_and_unescaped() {
        assert_eq!(
            parse_findings_query(None).expect("default page"),
            FindingsQuery {
                limit: 1_000,
                after_finding_id: None,
            }
        );
        assert_eq!(
            parse_findings_query(Some("limit=1&after=finding-a")).expect("explicit bounded page"),
            FindingsQuery {
                limit: 1,
                after_finding_id: Some("finding-a".to_owned()),
            }
        );
        for invalid in [
            "",
            "limit=0",
            "limit=01",
            "limit=1001",
            "limit=1&limit=2",
            "after=one&after=two",
            "after=finding%2Done",
            "after=finding+one",
            "unknown=value",
            "limit",
            "limit=1=2",
            "limit=1&&after=finding-one",
        ] {
            assert!(
                parse_findings_query(Some(invalid)).is_err(),
                "query must fail closed: {invalid}"
            );
        }
    }

    #[test]
    fn evaluation_history_query_has_exact_numeric_snapshot_bounds() {
        assert_eq!(
            parse_evaluation_history_query(None).expect("default evaluation page"),
            EvaluationHistoryQuery {
                limit: 1_000,
                after_sequence: None,
                through_sequence: None,
            }
        );
        assert_eq!(
            parse_evaluation_history_query(Some("limit=1&after=0&through=9"))
                .expect("explicit frozen page"),
            EvaluationHistoryQuery {
                limit: 1,
                after_sequence: Some(0),
                through_sequence: Some(9),
            }
        );
        for invalid in [
            "",
            "limit=0",
            "limit=01",
            "limit=1001",
            "limit=1&limit=2",
            "after=01",
            "after=2&after=3",
            "after=2",
            "through=01",
            "through=3&through=4",
            "after=4&through=3",
            "unknown=1",
            "after",
            "after=1=2",
        ] {
            assert!(
                parse_evaluation_history_query(Some(invalid)).is_err(),
                "evaluation query must fail closed: {invalid}"
            );
        }
    }

    #[tokio::test]
    async fn response_larger_than_one_stored_document_is_transported_exactly() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1_024);
        let canonical_body = vec![b'x'; nq_store::MAX_STORED_JSON_BYTES + 1];
        let writer = tokio::spawn(async move {
            write_response(&mut server, 200, "application/json", &canonical_body)
                .await
                .expect("canonical response writes without semantic substitution");
            canonical_body
        });
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read complete canonical response");
        let canonical_body = writer.await.expect("response writer joins");
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
            .expect("response has a complete HTTP header");
        let headers = std::str::from_utf8(&response[..header_end]).expect("headers are UTF-8");
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains(&format!("Content-Length: {}\r\n", canonical_body.len())));
        assert_eq!(&response[header_end..], canonical_body.as_slice());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn v3_findings_api_preserves_same_code_evaluation_refusals() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        let mut store = Store::initialize(&database).expect("initialize store");
        let fixtures = [
            seed_present_then_refused_evaluation(
                &mut store,
                "alpha",
                BTreeMap::from([
                    ("coverage".to_owned(), "reachability".to_owned()),
                    ("missing_basis".to_owned(), "active_probe".to_owned()),
                ]),
                true,
            ),
            seed_present_then_refused_evaluation(
                &mut store,
                "beta",
                BTreeMap::from([
                    ("age_seconds".to_owned(), "121".to_owned()),
                    ("reliance_seconds".to_owned(), "60".to_owned()),
                ]),
                true,
            ),
        ];
        let first_refusal = seed_present_then_refused_evaluation(
            &mut store,
            "first",
            BTreeMap::from([("reason".to_owned(), "missing_testimony".to_owned())]),
            false,
        );
        store.validate().expect("evaluation fixture validates");
        let direct_status = nq_core::engine::status_snapshot_v3(&store)
            .expect("direct V3 status reopens evaluations");
        assert_eq!(direct_status.evaluation_through_sequence, 5);
        let direct_first = direct_status
            .components
            .iter()
            .find(|component| component.id == first_refusal.latest_evaluation.evaluation_id)
            .expect("first-ever refusal has an evaluation status component");
        let nq_core::public::ComponentStatusDetailV3::Evaluation { result, .. } =
            &direct_first.detail
        else {
            panic!("first-ever refusal must remain a typed evaluation")
        };
        assert_eq!(result, &first_refusal.latest_evaluation);
        assert!(matches!(
            nq_core::engine::status_snapshot_v2(&store),
            Err(nq_core::engine::EngineError::Invariant(message))
                if message == "nq.status_snapshot.v2 cannot emit governed evaluation results; use v3"
        ));
        let direct_findings = nq_core::engine::list_findings(&store).expect("direct findings");
        assert_eq!(direct_findings.len(), 2);
        assert!(
            direct_findings
                .iter()
                .all(|finding| finding.finding_id != first_refusal.finding_id),
            "first-ever cannot-evaluate must not fabricate a finding"
        );
        drop(store);

        let status = get_json("/v3/status", database.clone()).await;
        assert_eq!(status["schema"], "nq.status_snapshot.v3");
        let first_status = status["components"]
            .as_array()
            .expect("status components")
            .iter()
            .find(|component| component["id"] == first_refusal.latest_evaluation.evaluation_id)
            .expect("HTTP V3 status exposes first-ever refusal");
        assert_eq!(
            first_status["detail"]["result"],
            serde_json::to_value(&first_refusal.latest_evaluation)
                .expect("first refusal envelope serializes")
        );
        let paired = fixtures
            .iter()
            .map(|fixture| {
                status["components"]
                    .as_array()
                    .expect("status components")
                    .iter()
                    .find(|component| component["id"] == fixture.latest_evaluation.evaluation_id)
                    .unwrap_or_else(|| {
                        panic!(
                            "missing evaluation status {}",
                            fixture.latest_evaluation.evaluation_id
                        )
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(paired[0]["code"], "cannot_evaluate");
        assert_eq!(paired[1]["code"], "cannot_evaluate");
        assert_eq!(
            paired[0]["detail"]["result"],
            serde_json::to_value(&fixtures[0].latest_evaluation)
                .expect("first pair envelope serializes")
        );
        assert_eq!(
            paired[1]["detail"]["result"],
            serde_json::to_value(&fixtures[1].latest_evaluation)
                .expect("second pair envelope serializes")
        );
        assert_ne!(paired[0]["detail"], paired[1]["detail"]);
        let (legacy_status, legacy_error) = get_response("/v2/status", database.clone()).await;
        assert_eq!(legacy_status, 409);
        assert_eq!(legacy_error["error"], "typed_evaluations_require_v3");
        assert_eq!(legacy_error["required_endpoint"], "/v3/status");

        let history = get_json("/v1/evaluations?limit=1000", database.clone()).await;
        assert_eq!(history["schema"], "nq.evaluation_history.v1");
        assert_eq!(history["through_sequence"], 5);
        assert_eq!(history["complete"], true);
        assert_eq!(
            history["records"]
                .as_array()
                .expect("history records")
                .len(),
            5
        );
        assert!(
            history["records"]
                .as_array()
                .expect("history records")
                .iter()
                .any(|record| record["result"]
                    == serde_json::to_value(&first_refusal.latest_evaluation)
                        .expect("first refusal envelope serializes"))
        );

        let first_history_page = get_json("/v1/evaluations?limit=1", database.clone()).await;
        assert_eq!(first_history_page["complete"], false);
        assert_eq!(first_history_page["next_after_sequence"], 1);
        let second_history_page = get_json(
            "/v1/evaluations?limit=1&after=1&through=5",
            database.clone(),
        )
        .await;
        assert_eq!(second_history_page["after_sequence"], 1);
        assert_eq!(second_history_page["through_sequence"], 5);
        assert_eq!(second_history_page["records"][0]["sequence"], 2);
        for invalid_path in [
            "/v1/evaluations?",
            "/v1/evaluations?limit=0",
            "/v1/evaluations?after=1",
            "/v1/evaluations?after=6&through=5",
            "/v1/evaluations?through=999",
            "/v1/evaluations?unknown=1",
        ] {
            let (status, body) = get_response(invalid_path, database.clone()).await;
            assert_eq!(status, 400, "request must fail closed: {invalid_path}");
            assert_eq!(body["error"], "invalid_evaluations_query");
        }
        let (status_query, status_query_error) =
            get_response("/v3/status?unknown=1", database.clone()).await;
        assert_eq!(status_query, 400);
        assert_eq!(status_query_error["error"], "status_query_not_supported");

        let first_page = get_json("/v3/findings?limit=1", database.clone()).await;
        let first = first_page
            .as_array()
            .expect("first findings page is an array");
        assert_eq!(first.len(), 1);
        let cursor = first[0]["finding_id"]
            .as_str()
            .expect("finding ID is a cursor");
        let second_page = get_json(
            &format!("/v3/findings?after={cursor}&limit=1"),
            database.clone(),
        )
        .await;
        let second = second_page
            .as_array()
            .expect("second findings page is an array");
        assert_eq!(second.len(), 1);
        let findings = [first[0].clone(), second[0].clone()];
        assert_eq!(findings.len(), fixtures.len());
        let mut reopened = Vec::new();
        for fixture in &fixtures {
            let finding = findings
                .iter()
                .find(|finding| finding["finding_id"] == fixture.finding_id)
                .unwrap_or_else(|| panic!("missing finding {}", fixture.finding_id));
            assert_eq!(finding["schema"], "nq.finding_snapshot.v3");
            assert_eq!(finding["condition"]["state"], "present");
            assert_eq!(finding["visibility"]["state"], "missing");

            // Finding v3 deliberately embeds the independently closed
            // nq.governed_refusal.v1 wire object; the nested schema is the
            // explicit version boundary for this refusal payload.
            let refusal = &finding["visibility"]["refusal"];
            assert_eq!(refusal["schema"], "nq.governed_refusal.v1");
            assert_eq!(
                refusal,
                &serde_json::to_value(&fixture.refusal).expect("expected refusal serializes")
            );
            let typed: GovernedRefusal = serde_json::from_value(refusal.clone())
                .expect("API refusal strictly typed-decodes");
            assert_eq!(typed, fixture.refusal);
            reopened.push(typed);
        }

        let profiles = reopened
            .iter()
            .map(|refusal| match &refusal.origin {
                GovernedRefusalOrigin::Profile(profile) => profile,
                other => panic!("evaluation refusal lost profile origin: {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(profiles[0].refusal.code, ProfileRefusalCode::CannotEvaluate);
        assert_eq!(profiles[0].refusal.code, profiles[1].refusal.code);
        assert_eq!(profiles[0].refusal.boundary, profiles[1].refusal.boundary);
        assert_ne!(reopened[0].refusal_id, reopened[1].refusal_id);
        assert_eq!(
            profiles[0].profile_semantic_id,
            profiles[1].profile_semantic_id
        );
        assert_eq!(profiles[0].refusal.profile, profiles[1].refusal.profile);
        assert_ne!(
            profiles[0].refusal.instance_id,
            profiles[1].refusal.instance_id
        );
        assert_ne!(profiles[0].refusal.details, profiles[1].refusal.details);
        assert_ne!(reopened[0], reopened[1]);

        for invalid_path in [
            "/v3/findings?",
            "/v3/findings?limit=0",
            "/v3/findings?limit=1001",
            "/v3/findings?limit=1&limit=2",
            "/v3/findings?after=one&after=two",
            "/v3/findings?after=finding%2Done",
            "/v3/findings?unknown=value",
        ] {
            let (status, body) = get_response(invalid_path, database.clone()).await;
            assert_eq!(status, 400, "request must fail closed: {invalid_path}");
            assert_eq!(body["error"], "invalid_findings_query");
            assert!(
                body["detail"]
                    .as_str()
                    .is_some_and(|detail| !detail.is_empty())
            );
        }

        let (v2_status, v2_error) = get_response("/v2/findings", database).await;
        assert_eq!(v2_status, 409);
        assert_eq!(v2_error["error"], "governed_findings_require_v3");
        assert_eq!(v2_error["required_endpoint"], "/v3/findings");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn v2_api_preserves_same_code_refusals_and_v1_route_stays_v1() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        let mut store = Store::initialize(&database).expect("initialize store");
        let profile_digest = append_fixture_descriptor(&mut store, "nq.conformance", 1);
        let conformance_digest = profile_digest.clone();
        let host_digest = append_fixture_descriptor(&mut store, "nq.host", 1);
        drop(store);

        // `/v1/status` remains the unchanged compatibility contract. A v1
        // reader does not reinterpret v2 collection documents.
        let v1 = get_json("/v1/status", database.clone()).await;
        assert_eq!(v1["schema"], "nq.status_snapshot.v1");
        let mut store = Store::open(&database).expect("reopen store");

        let (transient, transient_refusal) = helper_rejection(
            "transport-transient",
            "run-transient",
            "refusal-transient",
            true,
            json!({"attempt": 1, "errno": "EAGAIN"}),
        );
        let (permanent, permanent_refusal) = helper_rejection(
            "transport-permanent",
            "run-permanent",
            "refusal-permanent",
            false,
            json!({"device": "nvme0", "errno": "ENODEV"}),
        );
        seed_rejected_result(
            &mut store,
            "nq.conformance",
            1,
            &profile_digest,
            "transient",
            &transient,
            &transient_refusal,
            "degraded",
            "helper_refused",
        );
        seed_rejected_result(
            &mut store,
            "nq.conformance",
            1,
            &profile_digest,
            "permanent",
            &permanent,
            &permanent_refusal,
            "degraded",
            "helper_refused",
        );

        let timeout_write = CollectionOutcome::acquisition_failed(
            "timeout-write".to_owned(),
            "run-timeout-write".to_owned(),
            AcquisitionOutcome::ExchangeTimeout {
                phase: ExchangeTimeoutPhase::WriteRequest,
            },
        )
        .expect("write timeout carrier");
        let timeout_read = CollectionOutcome::acquisition_failed(
            "timeout-read".to_owned(),
            "run-timeout-read".to_owned(),
            AcquisitionOutcome::ExchangeTimeout {
                phase: ExchangeTimeoutPhase::ReadResponse,
            },
        )
        .expect("read timeout carrier");
        seed_acquisition_result(&mut store, &profile_digest, "timeout-write", &timeout_write);
        seed_acquisition_result(&mut store, &profile_digest, "timeout-read", &timeout_read);

        let (profile_report, report_refusal) = profile_rejection(
            "profile-report",
            "run-profile-report",
            "refusal-profile-report",
            "nq.conformance",
            1,
            ProfileRefusalBoundary::Report,
            BTreeMap::from([("field".to_owned(), "status".to_owned())]),
        );
        let (profile_observation, observation_refusal) = profile_rejection(
            "profile-observation",
            "run-profile-observation",
            "refusal-profile-observation",
            "nq.host",
            1,
            ProfileRefusalBoundary::Observation,
            BTreeMap::from([("ordinal".to_owned(), "4".to_owned())]),
        );
        seed_rejected_result(
            &mut store,
            "nq.conformance",
            1,
            &conformance_digest,
            "profile-report",
            &profile_report,
            &report_refusal,
            "failed",
            "report_rejected",
        );
        seed_rejected_result(
            &mut store,
            "nq.host",
            1,
            &host_digest,
            "profile-observation",
            &profile_observation,
            &observation_refusal,
            "failed",
            "report_rejected",
        );

        let (admission_transient, admission_transient_refusal) = helper_admission_refusal(
            "admission-transient",
            "refusal-admission-transient",
            true,
            json!({"attempt": 2, "errno": "EAGAIN"}),
        );
        let (admission_permanent, admission_permanent_refusal) = helper_admission_refusal(
            "admission-permanent",
            "refusal-admission-permanent",
            false,
            json!({"device": "nvme1", "errno": "ENODEV"}),
        );
        seed_admission_refusal_status(&mut store, &admission_transient);
        seed_admission_refusal_status(&mut store, &admission_permanent);

        // Exercise the direct typed status reader before the HTTP encoding
        // layer. Equal outward admission codes do not erase the nested helper
        // retryability, details, or refusal identities.
        let direct = nq_core::engine::status_snapshot_v2(&store).expect("direct typed status");
        let direct_result = |id: &str| {
            let component = direct
                .components
                .iter()
                .find(|component| component.id == id)
                .unwrap_or_else(|| panic!("missing direct admission status {id}"));
            let nq_core::public::ComponentStatusDetailV2::Collection { result } = &component.detail
            else {
                panic!("admission status must carry a typed collection result")
            };
            result
        };
        assert_eq!(direct_result("admission-transient"), &admission_transient);
        assert_eq!(direct_result("admission-permanent"), &admission_permanent);
        assert_ne!(
            direct_result("admission-transient"),
            direct_result("admission-permanent")
        );
        drop(store);

        let v2 = get_json("/v2/status", database.clone()).await;
        assert_eq!(v2["schema"], "nq.status_snapshot.v2");
        let component = |id: &str| {
            v2["components"]
                .as_array()
                .expect("status components")
                .iter()
                .find(|component| component["id"] == id)
                .unwrap_or_else(|| panic!("missing component {id}"))
        };
        let transient_component = component("transport-transient");
        let permanent_component = component("transport-permanent");
        assert_eq!(transient_component["code"], "helper_refused");
        assert_eq!(permanent_component["code"], "helper_refused");
        assert_eq!(
            transient_component["detail"]["result"],
            serde_json::to_value(&transient).expect("transient serializes")
        );
        assert_eq!(
            permanent_component["detail"]["result"],
            serde_json::to_value(&permanent).expect("permanent serializes")
        );
        assert_ne!(transient_component["detail"], permanent_component["detail"]);

        let timeout_write_component = component("timeout-write");
        let timeout_read_component = component("timeout-read");
        assert_eq!(timeout_write_component["code"], "collection_failed");
        assert_eq!(timeout_read_component["code"], "collection_failed");
        assert_eq!(
            timeout_write_component["detail"]["result"],
            serde_json::to_value(&timeout_write).expect("write timeout serializes")
        );
        assert_eq!(
            timeout_read_component["detail"]["result"],
            serde_json::to_value(&timeout_read).expect("read timeout serializes")
        );
        assert_eq!(
            timeout_write_component["detail"]["result"]["result"]["failure"]["class"],
            "timeout"
        );
        assert_eq!(
            timeout_read_component["detail"]["result"]["result"]["failure"]["class"],
            "timeout"
        );
        assert_eq!(
            timeout_write_component["detail"]["result"]["result"]["failure"]["outcome"]["phase"],
            "write_request"
        );
        assert_eq!(
            timeout_read_component["detail"]["result"]["result"]["failure"]["outcome"]["phase"],
            "read_response"
        );
        assert_ne!(
            timeout_write_component["detail"],
            timeout_read_component["detail"]
        );

        let report_component = component("profile-report");
        let observation_component = component("profile-observation");
        assert_eq!(report_component["code"], "report_rejected");
        assert_eq!(observation_component["code"], "report_rejected");
        assert_eq!(
            report_component["detail"]["result"],
            serde_json::to_value(&profile_report).expect("report refusal serializes")
        );
        assert_eq!(
            observation_component["detail"]["result"],
            serde_json::to_value(&profile_observation).expect("observation refusal serializes")
        );
        let report_status_refusal = &report_component["detail"]["result"]["result"]["refusal"];
        let observation_status_refusal =
            &observation_component["detail"]["result"]["result"]["refusal"];
        assert_eq!(
            report_status_refusal["origin"]["payload"]["refusal"]["profile"]["id"],
            "nq.conformance"
        );
        assert_eq!(
            report_status_refusal["origin"]["payload"]["refusal"]["boundary"],
            "report"
        );
        assert_eq!(
            observation_status_refusal["origin"]["payload"]["refusal"]["profile"]["id"],
            "nq.host"
        );
        assert_eq!(
            observation_status_refusal["origin"]["payload"]["refusal"]["boundary"],
            "observation"
        );
        assert_ne!(
            report_status_refusal["refusal_id"],
            observation_status_refusal["refusal_id"]
        );
        assert_ne!(report_status_refusal, observation_status_refusal);

        let admission_transient_component = component("admission-transient");
        let admission_permanent_component = component("admission-permanent");
        assert_eq!(admission_transient_component["code"], "admission_refused");
        assert_eq!(admission_permanent_component["code"], "admission_refused");
        assert_eq!(
            admission_transient_component["detail"]["result"],
            serde_json::to_value(&admission_transient).expect("transient admission serializes")
        );
        assert_eq!(
            admission_permanent_component["detail"]["result"],
            serde_json::to_value(&admission_permanent).expect("permanent admission serializes")
        );
        let transient_admission_refusal =
            &admission_transient_component["detail"]["result"]["result"]["refusal"];
        let permanent_admission_refusal =
            &admission_permanent_component["detail"]["result"]["result"]["refusal"];
        assert_eq!(transient_admission_refusal["code"], "upstream_refusal");
        assert_eq!(permanent_admission_refusal["code"], "upstream_refusal");
        assert_eq!(
            transient_admission_refusal["details"]["refusal"],
            serde_json::to_value(&admission_transient_refusal)
                .expect("nested transient helper refusal serializes")
        );
        assert_eq!(
            permanent_admission_refusal["details"]["refusal"],
            serde_json::to_value(&admission_permanent_refusal)
                .expect("nested permanent helper refusal serializes")
        );
        assert_eq!(
            transient_admission_refusal["details"]["refusal"]["origin"]["payload"]["retriable"],
            true
        );
        assert_eq!(
            permanent_admission_refusal["details"]["refusal"]["origin"]["payload"]["retriable"],
            false
        );
        assert_ne!(transient_admission_refusal, permanent_admission_refusal);

        let (v1_status, v1_error) = get_response("/v1/status", database.clone()).await;
        assert_eq!(v1_status, 409);
        assert_eq!(v1_error["error"], "governed_status_requires_v3");
        assert_eq!(v1_error["required_endpoint"], "/v3/status");

        let first_profile_page = get_json(
            "/v1/rejected-custody?limit=1&after=submission-permanent",
            database.clone(),
        )
        .await;
        let first_profile_records = first_profile_page["records"]
            .as_array()
            .expect("first profile page records");
        assert_eq!(first_profile_records.len(), 1);
        assert_eq!(
            first_profile_records[0]["submission_id"],
            "submission-profile-observation"
        );
        assert_eq!(
            first_profile_records[0]["refusal"],
            serde_json::to_value(&observation_refusal).expect("observation refusal serializes")
        );

        let second_profile_page = get_json(
            "/v1/rejected-custody?after=submission-profile-observation&limit=1",
            database.clone(),
        )
        .await;
        let second_profile_records = second_profile_page["records"]
            .as_array()
            .expect("second profile page records");
        assert_eq!(second_profile_records.len(), 1);
        assert_eq!(
            second_profile_records[0]["submission_id"],
            "submission-profile-report"
        );
        assert_eq!(
            second_profile_records[0]["refusal"],
            serde_json::to_value(&report_refusal).expect("report refusal serializes")
        );
        assert_eq!(
            first_profile_records[0]["refusal"]["origin"]["payload"]["code"],
            second_profile_records[0]["refusal"]["origin"]["payload"]["code"]
        );
        assert_ne!(
            first_profile_records[0]["refusal"],
            second_profile_records[0]["refusal"]
        );

        for invalid_path in [
            "/v1/rejected-custody?",
            "/v1/rejected-custody?limit=0",
            "/v1/rejected-custody?limit=1001",
            "/v1/rejected-custody?limit=1&limit=2",
            "/v1/rejected-custody?after=one&after=two",
            "/v1/rejected-custody?after=submission%2Dpermanent",
            "/v1/rejected-custody?unknown=value",
        ] {
            let (status, body) = get_response(invalid_path, database.clone()).await;
            assert_eq!(status, 400, "request must fail closed: {invalid_path}");
            assert_eq!(body["error"], "invalid_rejected_custody_query");
            assert!(
                body["detail"]
                    .as_str()
                    .is_some_and(|detail| !detail.is_empty())
            );
        }

        let custody = get_json("/v1/rejected-custody", database).await;
        assert_eq!(custody["schema"], "nq.rejected_custody.v1");
        let records = custody["records"].as_array().expect("custody records");
        assert_eq!(records.len(), 4);
        let custody_refusal = |id: &str| {
            &records
                .iter()
                .find(|record| record["refusal"]["refusal_id"] == id)
                .unwrap_or_else(|| panic!("missing custody refusal {id}"))["refusal"]
        };
        let transient_custody = custody_refusal("refusal-transient");
        let permanent_custody = custody_refusal("refusal-permanent");
        assert_eq!(transient_custody["origin"]["payload"]["retriable"], true);
        assert_eq!(permanent_custody["origin"]["payload"]["retriable"], false);
        assert_ne!(
            transient_custody["refusal_id"],
            permanent_custody["refusal_id"]
        );
        assert_ne!(transient_custody, permanent_custody);
        assert_eq!(
            custody_refusal("refusal-profile-report"),
            report_status_refusal
        );
        assert_eq!(
            custody_refusal("refusal-profile-observation"),
            observation_status_refusal
        );
    }
}
