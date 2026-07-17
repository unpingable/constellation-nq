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
const MAX_HTTP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_FINDINGS_PER_RESPONSE: u32 = 1_000;

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
            match tokio::time::timeout(CONNECTION_TIMEOUT, handle_connection(stream, database_path))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%error, "local API request failed"),
                Err(_) => tracing::debug!("local API request timed out"),
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
            match tokio::time::timeout(CONNECTION_TIMEOUT, handle_connection(stream, database_path))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%error, "loopback API request failed"),
                Err(_) => tracing::debug!("loopback API request timed out"),
            }
        });
        while tasks.try_join_next().is_some() {}
    }
}

async fn handle_connection<S>(mut stream: S, database_path: PathBuf) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request(&mut stream).await?;
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

    match path.split('?').next().unwrap_or(path) {
        "/v1/status" => {
            let body = read_status(database_path).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        "/v2/findings" => {
            let body = read_findings(database_path).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        "/console" | "/" => {
            let status = read_status(database_path.clone()).await?;
            let findings = read_findings(database_path).await?;
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

async fn read_status(database_path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open(database_path)?;
        let snapshot = nq_core::engine::status_snapshot(&store)?;
        serde_json::to_vec(&snapshot).map_err(anyhow::Error::from)
    })
    .await?
}

async fn read_findings(database_path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let store = Store::open(database_path)?;
        let findings =
            nq_core::engine::list_findings_bounded(&store, MAX_FINDINGS_PER_RESPONSE, None)?;
        serde_json::to_vec(&findings).map_err(anyhow::Error::from)
    })
    .await?
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
    if body.len() > MAX_HTTP_RESPONSE_BYTES {
        bail!("HTTP response exceeds {MAX_HTTP_RESPONSE_BYTES} bytes");
    }
    let reason = match status {
        200 => "OK",
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
    use super::*;

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
}
