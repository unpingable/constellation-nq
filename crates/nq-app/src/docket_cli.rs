//! Bounded direct acquisition from the supported, pinned Docket show interface.
//! Linux, trusted immutable executable contents/runtime libraries and same-UID
//! environment; descriptor binding closes pathname replacement, not in-place writes.
use anyhow::{Result, bail};
use nq_core::docket_support::{Acquisition, Request, qualify};
use nq_protocol::{Sha256Digest, decode_json_document, sha256_bytes};
use std::{
    fs::File,
    io::{Read, Seek},
    os::fd::AsRawFd,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn run(binary: &Path, expected: &str, state: &Path, request: &Path) -> Result<()> {
    let request_bytes = crate::bounded_input::read(request, 4 * 1024 * 1024)?;
    let mut r: Request = decode_json_document(&request_bytes, 4 * 1024 * 1024)?;
    let mut executable = File::open(binary)?;
    let mut bytes = Vec::new();
    (&mut executable)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if !executable.metadata()?.is_file()
        || bytes.len() > 256 * 1024 * 1024
        || sha256_bytes(&bytes) != Sha256Digest::parse(expected)?
    {
        bail!("Docket executable pin/size/type mismatch");
    }
    if !state.join("state.sqlite").is_file() {
        bail!("existing campaign-owned Docket state required");
    }
    let output = tempfile::tempfile()?;
    let mut reader = output.try_clone()?;
    let mut child = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .arg("show")
        .arg("--state")
        .arg(state)
        .arg("--attempt")
        .arg(&r.attempt)
        .arg("--json")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("Docket show refused/failed; no factual receipt");
            }
            break;
        }
        if start.elapsed() > Duration::from_secs(10) || reader.metadata()?.len() > 4 * 1024 * 1024 {
            child.kill()?;
            child.wait()?;
            bail!("Docket acquisition deadline/output bound");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.rewind()?;
    let mut raw = Vec::new();
    reader.take(4 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
    let observed_at = chrono::Utc::now();
    // The direct producer owns acquisition time; requests cannot backdate it.
    r.evaluated_at = observed_at;
    let acquisition = Acquisition {
        executable_digest: sha256_bytes(&bytes),
        state_locator: state.display().to_string(),
        attempt: r.attempt.clone(),
        observed_at,
        raw_digest: sha256_bytes(&raw),
    };
    let receipt = qualify(&raw, &r, Some(&acquisition)).map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        String::from_utf8(nq_protocol::canonical_json_bytes(&receipt)?)?
    );
    Ok(())
}
