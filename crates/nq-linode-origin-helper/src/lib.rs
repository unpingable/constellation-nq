//! Closed Linode instance-metadata origin helper.
//!
//! Normal execution accepts one exact NQ substrate-origin acquisition basis
//! on stdin, obtains metadata from the two fixed instance-local endpoints, and
//! emits one signed attestation. It exposes no URL, command, file, scheduling,
//! monitoring, or remediation parameter.

#![allow(missing_docs)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use nq_core::{
    ATTESTATION_SCHEMA_V1, LINODE_METADATA_NONCLAIMS_V1, LINODE_ORIGIN_HELPER_ISSUER_V1,
    LinodeInstanceMetadataEvidenceV1, SIGNED_ATTESTATION_SCHEMA_V1,
    SignedSubstrateOriginAttestationV1, SubstrateCoordinateKindV1,
    SubstrateOriginAcquisitionBasisV1, SubstrateOriginAttestationV1,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SIGNING_KEY_PATH: &str = "/var/lib/nq-origin-helper/signing-key.hex";
const METADATA_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(169, 254, 169, 254), 80);
const TOKEN_PATH: &str = "/v1/token";
const INSTANCE_PATH: &str = "/v1/instance";
const MAX_BASIS_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const MAX_HTTP_HEADERS: usize = 8 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum HelperError {
    #[error("unsupported arguments; only --public-key is accepted")]
    Arguments,
    #[error("cannot read bounded acquisition basis: {0}")]
    BasisIo(#[source] io::Error),
    #[error("acquisition basis is empty or oversized")]
    BasisSize,
    #[error("acquisition basis is malformed: {0}")]
    Basis(String),
    #[error("signing-key custody refused: {0}")]
    Key(String),
    #[error("metadata transport refused: {0}")]
    Transport(String),
    #[error("metadata response refused: {0}")]
    Metadata(String),
    #[error("cannot write bounded helper response: {0}")]
    Output(#[source] io::Error),
}

/// Run the closed command surface.
///
/// # Errors
///
/// Refuses unsupported arguments, invalid key custody, malformed input,
/// metadata transport/profile failures, and output failures.
pub fn run_command() -> Result<(), HelperError> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let signing_key = read_signing_key(Path::new(SIGNING_KEY_PATH))?;
    if arguments.as_slice() == ["--public-key"] {
        let mut stdout = io::stdout().lock();
        writeln!(
            stdout,
            "{}",
            hex::encode(signing_key.verifying_key().as_bytes())
        )
        .map_err(HelperError::Output)?;
        stdout.flush().map_err(HelperError::Output)?;
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err(HelperError::Arguments);
    }
    run(
        io::stdin().lock(),
        io::stdout().lock(),
        &signing_key,
        &mut fetch_metadata,
    )
}

/// Execute one bounded helper exchange against the supplied metadata source.
///
/// # Errors
///
/// Refuses malformed or oversized bases, metadata/profile disagreement,
/// signing failures, and output failures.
pub fn run(
    mut input: impl Read,
    mut output: impl Write,
    signing_key: &SigningKey,
    fetch: &mut impl FnMut() -> Result<Vec<u8>, HelperError>,
) -> Result<(), HelperError> {
    let mut bytes = Vec::with_capacity(4096);
    input
        .by_ref()
        .take((MAX_BASIS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(HelperError::BasisIo)?;
    if bytes.is_empty() || bytes.len() > MAX_BASIS_BYTES {
        return Err(HelperError::BasisSize);
    }
    let basis: SubstrateOriginAcquisitionBasisV1 =
        serde_json::from_slice(&bytes).map_err(|error| HelperError::Basis(error.to_string()))?;
    basis
        .validate()
        .map_err(|error| HelperError::Basis(error.to_string()))?;
    let evidence = LinodeInstanceMetadataEvidenceV1::from_response(&fetch()?)
        .map_err(|error| HelperError::Metadata(error.to_string()))?;
    let signed = sign_attestation(&basis, evidence, signing_key)?;
    let response = nq_protocol::canonical_json_bytes(&signed)
        .map_err(|error| HelperError::Metadata(error.to_string()))?;
    output.write_all(&response).map_err(HelperError::Output)?;
    output.flush().map_err(HelperError::Output)
}

fn sign_attestation(
    basis: &SubstrateOriginAcquisitionBasisV1,
    evidence: LinodeInstanceMetadataEvidenceV1,
    signing_key: &SigningKey,
) -> Result<SignedSubstrateOriginAttestationV1, HelperError> {
    if basis.expected_coordinate.kind != SubstrateCoordinateKindV1::LinodeInstance {
        return Err(HelperError::Metadata(
            "acquisition basis does not require the Linode metadata profile".into(),
        ));
    }
    let coordinate = evidence
        .coordinate()
        .map_err(|error| HelperError::Metadata(error.to_string()))?;
    if coordinate != basis.expected_coordinate {
        return Err(HelperError::Metadata(
            "Linode metadata does not match the expected coordinate".into(),
        ));
    }
    let payload = SubstrateOriginAttestationV1 {
        schema: ATTESTATION_SCHEMA_V1.into(),
        attestation_occurrence_ref: format!("attestation:{}", basis.acquisition_id),
        issuer_id: LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
        key_id: nq_core::linode_origin_helper_key_id(&signing_key.verifying_key()),
        acquisition_id: basis.acquisition_id.clone(),
        acquisition_basis_digest: basis
            .digest()
            .map_err(|error| HelperError::Basis(error.to_string()))?,
        coordinate,
        linode_metadata: Some(evidence),
        attested_at: Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
        replay_identity: format!("origin-replay:{}", basis.acquisition_id),
        nonclaims: LINODE_METADATA_NONCLAIMS_V1.map(str::to_owned).to_vec(),
    };
    let payload_bytes = nq_protocol::canonical_json_bytes(&payload)
        .map_err(|error| HelperError::Metadata(error.to_string()))?;
    let mut preimage =
        Vec::with_capacity(SIGNED_ATTESTATION_SCHEMA_V1.len() + 1 + payload_bytes.len());
    preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&payload_bytes);
    Ok(SignedSubstrateOriginAttestationV1 {
        schema: SIGNED_ATTESTATION_SCHEMA_V1.into(),
        payload_digest: format!("{:x}", Sha256::digest(&payload_bytes)),
        signature: hex::encode(signing_key.sign(&preimage).to_bytes()),
        payload,
    })
}

fn read_signing_key(path: &Path) -> Result<SigningKey, HelperError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| HelperError::Key(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| HelperError::Key(error.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 128
    {
        return Err(HelperError::Key(
            "key must be an owned regular 0600 file no larger than 128 bytes".into(),
        ));
    }
    decode_key(file)
}

fn decode_key(mut file: File) -> Result<SigningKey, HelperError> {
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| HelperError::Key(error.to_string()))?;
    let bytes: [u8; 32] = hex::decode(text.trim())
        .map_err(|_| HelperError::Key("key is not 32-byte lowercase/uppercase hex".into()))?
        .try_into()
        .map_err(|_| HelperError::Key("key is not exactly 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn fetch_metadata() -> Result<Vec<u8>, HelperError> {
    let token = http_request(
        "PUT",
        TOKEN_PATH,
        &["Metadata-Token-Expiry-Seconds: 60"],
        MAX_TOKEN_BYTES,
        None,
    )?;
    let token = std::str::from_utf8(&token)
        .map_err(|_| HelperError::Metadata("metadata token is not UTF-8".into()))?
        .trim();
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(HelperError::Metadata(
            "metadata token is empty, oversized, or malformed".into(),
        ));
    }
    let token_header = format!("Metadata-Token: {token}");
    http_request(
        "GET",
        INSTANCE_PATH,
        &["Accept: application/json", token_header.as_str()],
        MAX_METADATA_BYTES,
        Some("application/json"),
    )
}

fn http_request(
    method: &str,
    path: &str,
    headers: &[&str],
    max_body: usize,
    required_content_type: Option<&str>,
) -> Result<Vec<u8>, HelperError> {
    let mut stream = TcpStream::connect_timeout(&METADATA_ADDRESS.into(), HTTP_TIMEOUT)
        .map_err(|error| HelperError::Transport(error.to_string()))?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(HTTP_TIMEOUT)))
        .map_err(|error| HelperError::Transport(error.to_string()))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n"
    )
    .map_err(|error| HelperError::Transport(error.to_string()))?;
    for header in headers {
        write!(stream, "{header}\r\n")
            .map_err(|error| HelperError::Transport(error.to_string()))?;
    }
    stream
        .write_all(b"Content-Length: 0\r\n\r\n")
        .and_then(|()| stream.flush())
        .map_err(|error| HelperError::Transport(error.to_string()))?;
    let mut response = Vec::new();
    stream
        .take((MAX_HTTP_HEADERS + max_body + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| HelperError::Transport(error.to_string()))?;
    if response.len() > MAX_HTTP_HEADERS + max_body {
        return Err(HelperError::Metadata("HTTP response is oversized".into()));
    }
    parse_http_response(&response, max_body, required_content_type)
}

fn parse_http_response(
    response: &[u8],
    max_body: usize,
    required_content_type: Option<&str>,
) -> Result<Vec<u8>, HelperError> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| HelperError::Metadata("HTTP headers are incomplete".into()))?;
    if split > MAX_HTTP_HEADERS {
        return Err(HelperError::Metadata("HTTP headers are oversized".into()));
    }
    let header_bytes = &response[..split];
    let body = &response[split + 4..];
    if body.len() > max_body {
        return Err(HelperError::Metadata("HTTP body is oversized".into()));
    }
    let headers = std::str::from_utf8(header_bytes)
        .map_err(|_| HelperError::Metadata("HTTP headers are not UTF-8".into()))?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(HelperError::Metadata(
            "metadata HTTP status is not 200".into(),
        ));
    }
    let mut content_length = None;
    let mut content_type = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(HelperError::Metadata("malformed HTTP header".into()));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HelperError::Metadata(
                "transfer-encoded metadata is unsupported".into(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| HelperError::Metadata("invalid Content-Length".into()))?,
            );
        }
        if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim());
        }
    }
    if content_length != Some(body.len()) {
        return Err(HelperError::Metadata(
            "metadata Content-Length does not match exact body".into(),
        ));
    }
    if required_content_type.is_some_and(|required| content_type != Some(required)) {
        return Err(HelperError::Metadata(
            "metadata Content-Type does not match the closed profile".into(),
        ));
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_core::substrate_origin::ORIGIN_BASIS_SCHEMA_V1;
    use nq_core::{SubstrateCoordinateV1, SubstrateOriginVerifierV1};
    use nq_protocol::sha256_bytes;

    fn basis(id: u64) -> SubstrateOriginAcquisitionBasisV1 {
        SubstrateOriginAcquisitionBasisV1 {
            schema: ORIGIN_BASIS_SCHEMA_V1.into(),
            acquisition_id: "acquisition:test".into(),
            watcher_instance_id: "watcher:test".into(),
            watcher_config_digest: "ab".repeat(32),
            subject_ref: "labelwatch-host".into(),
            expected_coordinate: SubstrateCoordinateV1::for_linode_instance_digest(sha256_bytes(
                id.to_string().as_bytes(),
            ))
            .unwrap(),
            continuity: None,
        }
    }

    fn response(id: u64) -> Vec<u8> {
        format!(r#"{{"id":{id},"host_uuid":"host","region":"ca-central","type":"g6-dedicated-4","image":{{"id":"linode/ubuntu22.04"}}}}"#).into_bytes()
    }

    #[test]
    fn signs_exact_basis_and_refuses_wrong_instance() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let basis = basis(42);
        let mut output = Vec::new();
        run(
            serde_json::to_vec(&basis).unwrap().as_slice(),
            &mut output,
            &key,
            &mut || Ok(response(42)),
        )
        .unwrap();
        let signed = serde_json::from_slice(&output).unwrap();
        let key_id = nq_core::linode_origin_helper_key_id(&key.verifying_key());
        SubstrateOriginVerifierV1::for_linode_instance_metadata(
            nq_core::LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
            key_id,
            sha256_bytes(b"42"),
            key.verifying_key(),
        )
        .unwrap()
        .verify(&basis, &signed)
        .unwrap();

        let error = run(
            serde_json::to_vec(&basis).unwrap().as_slice(),
            Vec::new(),
            &key,
            &mut || Ok(response(43)),
        )
        .unwrap_err();
        assert!(error.to_string().contains("expected coordinate"));
    }

    #[test]
    fn http_parser_refuses_redirect_chunking_and_wrong_content_type() {
        assert!(
            parse_http_response(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", 1, None)
                .is_err()
        );
        assert!(
            parse_http_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                32,
                None
            )
            .is_err()
        );
        assert!(
            parse_http_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n{}",
                32,
                Some("application/json")
            )
            .is_err()
        );
    }
}
