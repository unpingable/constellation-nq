//! One closed passive observation boundary for `nq.host.load_pressure/v1`.
//!
//! The sampler is independent deployment infrastructure. It reads exactly the
//! first `/proc/loadavg` token and Rust `available_parallelism()`, then appends
//! an authenticated raw-fact sample. The provider path only selects and returns
//! a sample that existed before the NQ-owned cutoff; it never reads procfs,
//! computes the pressure verdict, schedules NQ, or falls back to the old helper.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use nix::fcntl::{Flock, FlockArg};
use nix::libc;
use nq_profiles::{ProfileModule, host};
use nq_protocol::{
    BackendIdentity, BackendProvenance, Capability, CoverageDeclaration, CoverageKind,
    CoverageState, ErrorCode, ErrorSeverity, EvidenceReport, HelperRequest, HelperResponse,
    ImplementationName, MAX_REQUEST_FRAME_BYTES, ObservationKind, PassiveHostLoadSamplePayloadV1,
    Refusal, RefusalBoundary, RefusalCode, ReportError, ReportStatus, Sha256Digest,
    SignedPassiveHostLoadSampleV1, SubjectBinding, encode_ndjson, parse_request, semantic_digest,
    sha256_bytes, validate_exchange,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

const OBSERVER_CONFIG_SCHEMA: &str = "nq.passive_load_observer_config.v1";
const PROVIDER_CONFIG_SCHEMA: &str = "nq.passive_load_provider_config.v1";
const OBSERVER_PROFILE: &str = "nq.host_load_passive_sampler.v1";
const SOURCE_BASIS: &str = "linux_proc_loadavg_plus_rust_available_parallelism_v1";
const READ_PROCFS: &str = "read_procfs";
const READ_SYSTEM_INFO: &str = "read_system_info";
const MAX_CONFIG_BYTES: usize = 65_536;
const MAX_SAMPLE_BYTES: usize = 65_536;
const MAX_PROC_BYTES: usize = 4_096;
const OBSERVER_LOCK_FILE: &str = ".observer.lock";

/// Process-lifetime serialization and fixed deployment identity for one
/// observer generation. Opening a second sampler over the same store refuses;
/// it cannot race sequence allocation or duplicate sampling delivery.
struct ObserverSession {
    config: ObserverConfigV1,
    key: SigningKey,
    observer_artifact_digest: Sha256Digest,
    observer_config_digest: Sha256Digest,
    observer_run_id: String,
    next_sequence: u64,
    sample_count: u64,
    bytes_used: u64,
    _lock: Flock<File>,
}

/// Closed observer deployment policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverConfigV1 {
    /// Must be `nq.passive_load_observer_config.v1`.
    pub schema: String,
    /// Dedicated finite append-only directory.
    pub sample_store: PathBuf,
    /// Exact governed subject/scope/vantage.
    pub binding: SubjectBinding,
    /// Fixed sample cadence, independent of NQ acquisition cadence.
    pub sample_interval_ms: u64,
    /// Finite number of samples this deployment generation may append.
    pub max_samples: u64,
    /// Hard byte ceiling; history is never deleted to satisfy it.
    pub max_store_bytes: u64,
    /// Exclusive observer-generation expiration, if configured.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Raw 32-byte Ed25519 signing key, readable only by the sampler principal.
    pub private_key_path: PathBuf,
    /// Deployment-owned producer identity.
    pub producer_issuer: String,
    /// Exact key identity.
    pub producer_key_id: String,
    /// Pinned effective execution context for `available_parallelism()`.
    pub capacity_context_id: Sha256Digest,
}

/// Closed provider-side selector policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfigV1 {
    /// Must be `nq.passive_load_provider_config.v1`.
    pub schema: String,
    /// Read-only sample store.
    pub sample_store: PathBuf,
    /// Deployment ceiling on NQ-requested age.
    pub max_sample_age_ms: u64,
    /// Exact sampler profile.
    pub observer_profile: String,
    /// Exact sampler executable digest.
    pub observer_artifact_digest: Sha256Digest,
    /// Exact sampler configuration digest.
    pub observer_config_digest: Sha256Digest,
    /// Expected producer issuer.
    pub producer_issuer: String,
    /// Expected key identity.
    pub producer_key_id: String,
    /// Lowercase hexadecimal Ed25519 public key.
    pub producer_public_key_hex: String,
    /// Pinned effective execution context.
    pub capacity_context_id: Sha256Digest,
}

/// Read-only projection of the effective inputs relevant to Rust's Linux
/// `available_parallelism()` implementation for this closed deployment.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityContextV1 {
    /// Exact schema.
    pub schema: String,
    /// Effective scheduler affinity list from `/proc/self/status`.
    pub cpus_allowed_list: String,
    /// Cgroup version detected for the process.
    pub cgroup_mode: String,
    /// Effective v2 CPU quota, or an explicit absent marker.
    pub cpu_max: Option<String>,
    /// Effective v2 cpuset, or an explicit absent marker.
    pub cpuset_cpus_effective: Option<String>,
}

/// Observer/provider failure. No variant authorizes fallback measurement.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration or stored evidence is malformed or substituted.
    #[error("invalid passive-load contract: {0}")]
    Invalid(String),
    /// Bounded filesystem operation failed.
    #[error("passive-load I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Serialization failed.
    #[error("passive-load serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Configuration parsing failed.
    #[error("passive-load configuration failed: {0}")]
    Config(#[from] toml::de::Error),
    /// The finite append-only generation is exhausted.
    #[error("passive-load sample generation is exhausted: {0}")]
    Exhausted(String),
}

/// Generate one software-held sample signing key. It authenticates producer
/// custody only and is not a physical-host identity.
///
/// # Errors
///
/// Refuses an existing path, unsafe identifier, or failed durable write.
pub fn keygen(path: &Path, issuer: &str, key_id: &str) -> Result<(), Error> {
    validate_identifier("producer_issuer", issuer)?;
    validate_identifier("producer_key_id", key_id)?;
    require_absolute("private_key", path)?;
    let mut secret = [0_u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&secret)?;
    file.sync_all()?;
    let public = key.verifying_key().to_bytes();
    let receipt = json!({
        "schema": "nq.passive_load_sample_key_receipt.v1",
        "producer_issuer": issuer,
        "producer_key_id": key_id,
        "public_key_hex": hex::encode(public),
        "public_key_digest": sha256_bytes(&public),
    });
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

/// Print the current capacity-context identity and exact parallelism value.
///
/// # Errors
///
/// Returns a bounded local read or canonicalization error.
pub fn inspect_capacity_context() -> Result<(), Error> {
    let context = capacity_context()?;
    let digest = semantic_digest(&context).map_err(|error| Error::Invalid(error.to_string()))?;
    let logical_cpu_count = available_parallelism()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "nq.passive_load_capacity_context_inspection.v1",
            "capacity_context": context,
            "capacity_context_id": digest,
            "logical_cpu_count": logical_cpu_count,
        }))?
    );
    Ok(())
}

/// Append exactly one authentic raw-fact sample.
///
/// # Errors
///
/// Refuses context drift, exhausted finite custody, corrupt history, expired
/// configuration, or any source/signing/storage failure.
pub fn sample_once(config_path: &Path) -> Result<SignedPassiveHostLoadSampleV1, Error> {
    ObserverSession::open(config_path)?.append_one()
}

/// Run one long-lived bounded observer. Sampling is anchored to this observer
/// process and never backfills missed intervals after a stall or restart.
///
/// # Errors
///
/// Returns when the generation is exhausted or a sample cannot be retained.
pub fn observe(config_path: &Path) -> Result<(), Error> {
    let mut session = ObserverSession::open(config_path)?;
    let interval = StdDuration::from_millis(session.config.sample_interval_ms);
    loop {
        let started = Instant::now();
        match session.append_one() {
            Ok(_) => {}
            Err(Error::Exhausted(_)) => return Ok(()),
            Err(error) => return Err(error),
        }
        if let Some(remaining) = interval.checked_sub(started.elapsed()) {
            thread::sleep(remaining);
        }
    }
}

impl ObserverSession {
    fn open(config_path: &Path) -> Result<Self, Error> {
        let (config, config_bytes) = load_toml::<ObserverConfigV1>(config_path)?;
        validate_observer_config(&config)?;
        let lock = acquire_observer_lock(&config.sample_store)?;
        let key = load_signing_key(&config.private_key_path)?;
        let public = key.verifying_key();
        let observer_artifact_digest = executable_digest()?;
        let observer_config_digest = sha256_bytes(&config_bytes);
        let existing = load_samples(
            &config.sample_store,
            &public,
            &ExpectedSampleIdentity {
                observer_profile: OBSERVER_PROFILE,
                observer_artifact_digest: Some(&observer_artifact_digest),
                observer_config_digest: Some(&observer_config_digest),
                producer_issuer: &config.producer_issuer,
                producer_key_id: &config.producer_key_id,
                capacity_context_id: &config.capacity_context_id,
                binding: Some(&config.binding),
            },
        )?;
        let sample_count = u64::try_from(existing.len()).unwrap_or(u64::MAX);
        let next_sequence = existing
            .last()
            .map_or(1, |sample| sample.payload.sequence.saturating_add(1));
        let bytes_used = store_bytes(&config.sample_store)?;
        Ok(Self {
            config,
            key,
            observer_artifact_digest,
            observer_config_digest,
            observer_run_id: format!("observer-run:{}", Uuid::new_v4()),
            next_sequence,
            sample_count,
            bytes_used,
            _lock: lock,
        })
    }

    fn append_one(&mut self) -> Result<SignedPassiveHostLoadSampleV1, Error> {
        let now = Utc::now();
        if self.config.expires_at.is_some_and(|expiry| now >= expiry) {
            return Err(Error::Exhausted(
                "observer configuration has expired".into(),
            ));
        }
        if self.sample_count >= self.config.max_samples {
            return Err(Error::Exhausted("maximum sample count reached".into()));
        }
        let context_id = semantic_digest(&capacity_context()?)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        if context_id != self.config.capacity_context_id {
            return Err(Error::Invalid(
                "available_parallelism capacity/vantage context drifted".into(),
            ));
        }
        let load_1m_token = load_1m_token()?;
        let logical_cpu_count = available_parallelism()?;
        let payload = PassiveHostLoadSamplePayloadV1 {
            schema: nq_protocol::PASSIVE_HOST_LOAD_SAMPLE_PAYLOAD_SCHEMA_V1.into(),
            sample_occurrence_id: format!("sample:{}", Uuid::new_v4()),
            binding: self.config.binding.clone(),
            observed_at: Utc::now(),
            sequence: self.next_sequence,
            observer_run_id: self.observer_run_id.clone(),
            observer_profile: OBSERVER_PROFILE.into(),
            observer_artifact_digest: self.observer_artifact_digest.clone(),
            observer_config_digest: self.observer_config_digest.clone(),
            load_1m_token,
            logical_cpu_count,
            source_basis: SOURCE_BASIS.into(),
            capacity_context_id: context_id,
        };
        payload.validate().map_err(Error::Invalid)?;
        let payload_digest =
            semantic_digest(&payload).map_err(|error| Error::Invalid(error.to_string()))?;
        let signature = self.key.sign(payload_digest.as_str().as_bytes());
        let sample = SignedPassiveHostLoadSampleV1 {
            schema: nq_protocol::SIGNED_PASSIVE_HOST_LOAD_SAMPLE_SCHEMA_V1.into(),
            payload,
            payload_digest,
            producer_issuer: self.config.producer_issuer.clone(),
            producer_key_id: self.config.producer_key_id.clone(),
            signature: hex::encode(signature.to_bytes()),
        };
        sample.validate_structure().map_err(Error::Invalid)?;
        let document = nq_protocol::canonical_json_bytes(&sample)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let projected = self
            .bytes_used
            .saturating_add(u64::try_from(document.len()).unwrap_or(u64::MAX));
        if projected > self.config.max_store_bytes {
            return Err(Error::Exhausted(
                "hard store byte bound would be exceeded; no history was deleted".into(),
            ));
        }
        append_sample(&self.config.sample_store, &sample, &document)?;
        self.bytes_used = projected;
        self.sample_count = self.sample_count.saturating_add(1);
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(sample)
    }
}

/// Serve one bounded provider exchange using only a pre-existing sample.
///
/// # Errors
///
/// Returns only for framing, configuration, or output failures before a valid
/// helper response can be emitted. Missing or ineligible samples receive a
/// typed retriable refusal and never cause a kernel read.
pub fn serve_stdio(config_path: &Path) -> Result<(), Error> {
    serve(config_path, io::stdin().lock(), io::stdout().lock())
}

/// Serve one exchange over supplied bounded streams.
///
/// # Errors
///
/// Uses the same closed law as [`serve_stdio`].
pub fn serve(
    config_path: &Path,
    mut input: impl Read,
    mut output: impl Write,
) -> Result<(), Error> {
    let (config, _) = load_toml::<ProviderConfigV1>(config_path)?;
    validate_provider_config(&config)?;
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(u64::try_from(MAX_REQUEST_FRAME_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(Error::Invalid("request exceeds protocol bound".into()));
    }
    let request = parse_request(&bytes).map_err(|error| Error::Invalid(error.to_string()))?;
    let response = match select_sample(&config, &request) {
        Ok(sample) => HelperResponse::report(&request, build_report(&request, &sample)?),
        Err(error) => HelperResponse::refusal(
            &request,
            Refusal {
                responsible_instance_id: request.instance_id.clone(),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "no exact eligible pre-existing passive load sample is available".into(),
                retriable: true,
                details: json!({"reason": error.to_string()}),
            },
        ),
    };
    validate_exchange(&request, &response).map_err(|error| Error::Invalid(error.to_string()))?;
    let frame = encode_ndjson(&response).map_err(|error| Error::Invalid(error.to_string()))?;
    output.write_all(&frame)?;
    output.flush()?;
    Ok(())
}

fn build_report(
    request: &HelperRequest,
    sample: &SignedPassiveHostLoadSampleV1,
) -> Result<EvidenceReport, Error> {
    let load = sample
        .payload
        .load_1m_token
        .parse::<f64>()
        .map_err(|error| Error::Invalid(error.to_string()))?;
    let observed_at = sample.payload.observed_at;
    let coverage = |kind: &str, state| -> Result<CoverageDeclaration, Error> {
        Ok(CoverageDeclaration {
            kind: CoverageKind::new(kind).map_err(|error| Error::Invalid(error.to_string()))?,
            subject: None,
            state,
            detail: None,
        })
    };
    let read_procfs =
        Capability::new(READ_PROCFS).map_err(|error| Error::Invalid(error.to_string()))?;
    let read_system_info =
        Capability::new(READ_SYSTEM_INFO).map_err(|error| Error::Invalid(error.to_string()))?;
    EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        observed_at,
        ReportStatus::Partial,
        BackendProvenance {
            implementation: BackendIdentity {
                name: ImplementationName::new("nq-passive-load-helper")
                    .map_err(|error| Error::Invalid(error.to_string()))?,
                version: Some(env!("CARGO_PKG_VERSION").into()),
                digest: Some(executable_digest()?),
            },
            tools: Vec::new(),
        },
    )
    .coverage(coverage("host_identity", CoverageState::Unavailable)?)
    .coverage(coverage("uptime", CoverageState::Unavailable)?)
    .coverage(coverage("load", CoverageState::Complete)?)
    .observed_payload(
        ObservationKind::new("host_snapshot")
            .map_err(|error| Error::Invalid(error.to_string()))?,
        request.binding.subject.clone(),
        observed_at,
        json!({
            "evidence_basis": {
                "scope": request.binding.scope,
                "vantage": request.binding.vantage,
                "access_path": "procfs_sysinfo",
                "basis": "kernel_snapshot",
                "regime": "normal",
                "capabilities_used": [READ_PROCFS, READ_SYSTEM_INFO],
            },
            "hostname": null,
            "uptime_seconds": null,
            "cpu_count": sample.payload.logical_cpu_count,
            "load_1m": load,
            "passive_sample": sample,
        }),
    )
    .used_capability(read_procfs)
    .used_capability(read_system_info)
    .error(ReportError {
        code: ErrorCode::new("passive_load_only_scope")
            .map_err(|error| Error::Invalid(error.to_string()))?,
        severity: ErrorSeverity::Warning,
        message: "this closed passive source retains load/capacity facts only; hostname and uptime are intentionally unavailable".into(),
        subject: None,
        observation_ordinal: Some(0),
        retriable: false,
    })
    .build()
    .map_err(|error| Error::Invalid(error.to_string()))
}

fn select_sample(
    config: &ProviderConfigV1,
    request: &HelperRequest,
) -> Result<SignedPassiveHostLoadSampleV1, Error> {
    let selection = request
        .passive_host_load_sample
        .as_ref()
        .ok_or_else(|| Error::Invalid("request lacks passive sample selection law".into()))?;
    let public_bytes = decode_public_key(&config.producer_public_key_hex)?;
    if request.checkpoint.is_some()
        || request.granted_capabilities
            != [
                Capability::new(READ_PROCFS).map_err(|error| Error::Invalid(error.to_string()))?,
                Capability::new(READ_SYSTEM_INFO)
                    .map_err(|error| Error::Invalid(error.to_string()))?,
            ]
        || request.profile.id.as_str() != host::PROFILE_ID
        || request.profile.version.as_str() != host::PROFILE_VERSION.to_string()
        || request.profile.digest.as_str()
            != host::MODULE
                .descriptor()
                .digest()
                .map_err(|error| Error::Invalid(error.to_string()))?
                .as_str()
        || selection.max_age_ms > config.max_sample_age_ms
        || selection.observer_profile != config.observer_profile
        || selection.observer_artifact_digest != config.observer_artifact_digest
        || selection.observer_config_digest != config.observer_config_digest
        || selection.producer_issuer != config.producer_issuer
        || selection.producer_key_id != config.producer_key_id
        || selection.producer_public_key_digest != sha256_bytes(&public_bytes)
        || selection.capacity_context_id != config.capacity_context_id
    {
        return Err(Error::Invalid(
            "request differs from the exact passive provider deployment".into(),
        ));
    }
    let public = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| Error::Invalid("invalid producer public key".into()))?;
    let samples = load_samples(
        &config.sample_store,
        &public,
        &ExpectedSampleIdentity {
            observer_profile: &config.observer_profile,
            observer_artifact_digest: Some(&config.observer_artifact_digest),
            observer_config_digest: Some(&config.observer_config_digest),
            producer_issuer: &config.producer_issuer,
            producer_key_id: &config.producer_key_id,
            capacity_context_id: &config.capacity_context_id,
            binding: Some(&request.binding),
        },
    )?;
    samples
        .into_iter()
        .filter(|sample| {
            let age = selection
                .cutoff_at
                .signed_duration_since(sample.payload.observed_at);
            age >= chrono::Duration::zero()
                && u64::try_from(age.num_milliseconds()).unwrap_or(u64::MAX) <= selection.max_age_ms
        })
        .max_by_key(|sample| (sample.payload.observed_at, sample.payload.sequence))
        .ok_or_else(|| Error::Invalid("no sample satisfies cutoff and age".into()))
}

struct ExpectedSampleIdentity<'a> {
    observer_profile: &'a str,
    observer_artifact_digest: Option<&'a Sha256Digest>,
    observer_config_digest: Option<&'a Sha256Digest>,
    producer_issuer: &'a str,
    producer_key_id: &'a str,
    capacity_context_id: &'a Sha256Digest,
    binding: Option<&'a SubjectBinding>,
}

fn load_samples(
    store: &Path,
    public: &VerifyingKey,
    expected: &ExpectedSampleIdentity<'_>,
) -> Result<Vec<SignedPassiveHostLoadSampleV1>, Error> {
    require_sample_store(store)?;
    let mut samples = Vec::new();
    for entry in fs::read_dir(store)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| Error::Invalid("sample filename is not UTF-8".into()))?;
        if name == OBSERVER_LOCK_FILE {
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() || metadata.mode() & 0o002 != 0 {
                return Err(Error::Invalid(
                    "observer lock is not a non-world-writable regular file".into(),
                ));
            }
            continue;
        }
        let Some(stem) = name.strip_suffix(".json") else {
            return Err(Error::Invalid(format!(
                "unexpected entry in dedicated sample store: {name}"
            )));
        };
        if !stem.starts_with("sample-") {
            return Err(Error::Invalid(format!(
                "unexpected entry in dedicated sample store: {name}"
            )));
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_SAMPLE_BYTES as u64 {
            return Err(Error::Invalid(format!("invalid sample file: {name}")));
        }
        let bytes = fs::read(entry.path())?;
        let sample: SignedPassiveHostLoadSampleV1 = serde_json::from_slice(&bytes)?;
        verify_sample(&sample, public, expected)?;
        let expected_name = sample_filename(&sample);
        if name != expected_name {
            return Err(Error::Invalid(
                "sample filename/custody identity mismatch".into(),
            ));
        }
        samples.push(sample);
    }
    samples.sort_by_key(|sample| sample.payload.sequence);
    let mut sequences = BTreeSet::new();
    let mut occurrences = BTreeSet::new();
    for (index, sample) in samples.iter().enumerate() {
        if !sequences.insert(sample.payload.sequence)
            || !occurrences.insert(sample.payload.sample_occurrence_id.clone())
        {
            return Err(Error::Invalid(
                "duplicate passive sample sequence or occurrence identity".into(),
            ));
        }
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if sample.payload.sequence != expected_sequence {
            return Err(Error::Invalid(
                "passive sample sequence has a missing or rolled-back occurrence".into(),
            ));
        }
    }
    Ok(samples)
}

fn verify_sample(
    sample: &SignedPassiveHostLoadSampleV1,
    public: &VerifyingKey,
    expected: &ExpectedSampleIdentity<'_>,
) -> Result<(), Error> {
    sample.validate_structure().map_err(Error::Invalid)?;
    if sample.producer_issuer != expected.producer_issuer
        || sample.producer_key_id != expected.producer_key_id
        || sample.payload.observer_profile != expected.observer_profile
        || sample.payload.capacity_context_id != *expected.capacity_context_id
        || expected
            .observer_artifact_digest
            .is_some_and(|digest| sample.payload.observer_artifact_digest != *digest)
        || expected
            .observer_config_digest
            .is_some_and(|digest| sample.payload.observer_config_digest != *digest)
        || expected
            .binding
            .is_some_and(|binding| sample.payload.binding != *binding)
    {
        return Err(Error::Invalid(
            "sample differs from exact producer, observer, context, or binding".into(),
        ));
    }
    let signature = hex::decode(&sample.signature)
        .map_err(|error| Error::Invalid(format!("invalid signature hex: {error}")))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| Error::Invalid("signature is not 64 bytes".into()))?;
    public
        .verify(
            sample.payload_digest.as_str().as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| Error::Invalid("sample signature is not authentic".into()))
}

fn validate_observer_config(config: &ObserverConfigV1) -> Result<(), Error> {
    if config.schema != OBSERVER_CONFIG_SCHEMA
        || !(100..=3_600_000).contains(&config.sample_interval_ms)
        || !(1..=100_000).contains(&config.max_samples)
        || !(4_096..=1_073_741_824).contains(&config.max_store_bytes)
    {
        return Err(Error::Invalid(
            "observer policy is outside closed bounds".into(),
        ));
    }
    require_absolute("sample_store", &config.sample_store)?;
    require_absolute("private_key_path", &config.private_key_path)?;
    validate_identifier("producer_issuer", &config.producer_issuer)?;
    validate_identifier("producer_key_id", &config.producer_key_id)?;
    require_binding(&config.binding)
}

fn validate_provider_config(config: &ProviderConfigV1) -> Result<(), Error> {
    if config.schema != PROVIDER_CONFIG_SCHEMA
        || config.observer_profile != OBSERVER_PROFILE
        || !(1..=300_000).contains(&config.max_sample_age_ms)
    {
        return Err(Error::Invalid(
            "provider policy is outside closed bounds".into(),
        ));
    }
    require_absolute("sample_store", &config.sample_store)?;
    validate_identifier("producer_issuer", &config.producer_issuer)?;
    validate_identifier("producer_key_id", &config.producer_key_id)?;
    decode_public_key(&config.producer_public_key_hex).map(|_| ())
}

fn require_binding(binding: &SubjectBinding) -> Result<(), Error> {
    let scope_id = binding
        .scope
        .value
        .as_object()
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid("host scope requires one id string".into()))?;
    if binding.scope.kind.as_str() != "host"
        || binding.vantage.kind.as_str() != "local"
        || binding.vantage.value != json!({})
        || binding.subject.as_str() != format!("host:{scope_id}")
    {
        return Err(Error::Invalid(
            "passive observer binding is not the exact local host vantage".into(),
        ));
    }
    Ok(())
}

fn capacity_context() -> Result<CapacityContextV1, Error> {
    let status = read_bounded(Path::new("/proc/self/status"), 65_536)?;
    let cpus_allowed_list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Invalid("/proc/self/status lacks Cpus_allowed_list".into()))?
        .to_owned();
    let cgroup = read_bounded(Path::new("/proc/self/cgroup"), 65_536)?;
    if let Some(relative) = cgroup.lines().find_map(|line| line.strip_prefix("0::")) {
        let relative = relative.trim_start_matches('/');
        let root = Path::new("/sys/fs/cgroup").join(relative);
        Ok(CapacityContextV1 {
            schema: "nq.available_parallelism_context.v1".into(),
            cpus_allowed_list,
            cgroup_mode: "v2".into(),
            cpu_max: read_optional_trimmed(&root.join("cpu.max"))?,
            cpuset_cpus_effective: read_optional_trimmed(&root.join("cpuset.cpus.effective"))?,
        })
    } else {
        Err(Error::Invalid(
            "this V1 qualification requires Linux cgroup v2 capacity context".into(),
        ))
    }
}

fn read_optional_trimmed(path: &Path) -> Result<Option<String>, Error> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            Ok(Some(read_bounded(path, 4_096)?.trim().to_owned()))
        }
        Ok(_) => Err(Error::Invalid(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

fn load_1m_token() -> Result<String, Error> {
    let text = read_bounded(Path::new("/proc/loadavg"), MAX_PROC_BYTES)?;
    let token = text
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| Error::Invalid("/proc/loadavg is empty".into()))?;
    let parsed = token
        .parse::<f64>()
        .map_err(|error| Error::Invalid(format!("invalid load token: {error}")))?;
    if !parsed.is_finite() || parsed.is_sign_negative() {
        return Err(Error::Invalid(
            "/proc/loadavg first token is not finite non-negative".into(),
        ));
    }
    Ok(token.to_owned())
}

fn available_parallelism() -> Result<u32, Error> {
    let value = std::thread::available_parallelism()
        .map_err(|error| Error::Invalid(format!("available_parallelism failed: {error}")))?
        .get();
    u32::try_from(value).map_err(|_| Error::Invalid("available parallelism exceeds u32".into()))
}

fn executable_digest() -> Result<Sha256Digest, Error> {
    let bytes = fs::read("/proc/self/exe")?;
    Ok(sha256_bytes(&bytes))
}

fn append_sample(
    store: &Path,
    sample: &SignedPassiveHostLoadSampleV1,
    document: &[u8],
) -> Result<(), Error> {
    let path = store.join(sample_filename(sample));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o440)
        .open(path)?;
    file.write_all(document)?;
    file.sync_all()?;
    File::open(store)?.sync_all()?;
    Ok(())
}

fn sample_filename(sample: &SignedPassiveHostLoadSampleV1) -> String {
    format!(
        "sample-{:020}-{}.json",
        sample.payload.sequence,
        sample.payload_digest.as_str().trim_start_matches("sha256:")
    )
}

fn store_bytes(store: &Path) -> Result<u64, Error> {
    require_sample_store(store)?;
    let mut total = 0_u64;
    for entry in fs::read_dir(store)? {
        let entry = entry?;
        total = total.saturating_add(fs::symlink_metadata(entry.path())?.len());
    }
    Ok(total)
}

fn acquire_observer_lock(store: &Path) -> Result<Flock<File>, Error> {
    require_sample_store(store)?;
    let path = store.join(OBSERVER_LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o640)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o002 != 0 {
        return Err(Error::Invalid(
            "observer lock is not a non-world-writable regular file".into(),
        ));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| Error::Invalid(format!("another observer owns this store: {error}")))
}

fn require_sample_store(path: &Path) -> Result<(), Error> {
    require_absolute("sample_store", path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o002 != 0 {
        return Err(Error::Invalid(
            "sample store must be a non-world-writable real directory".into(),
        ));
    }
    Ok(())
}

fn load_signing_key(path: &Path) -> Result<SigningKey, Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o077 != 0 {
        return Err(Error::Invalid(
            "sample signing key must be a regular file inaccessible to group/other".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Invalid("sample signing key is not 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn decode_public_key(value: &str) -> Result<[u8; 32], Error> {
    if value != value.to_ascii_lowercase() {
        return Err(Error::Invalid(
            "public key must be lowercase hexadecimal".into(),
        ));
    }
    hex::decode(value)
        .map_err(|error| Error::Invalid(format!("invalid public key hex: {error}")))?
        .try_into()
        .map_err(|_| Error::Invalid("public key is not 32 bytes".into()))
}

fn load_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<(T, Vec<u8>), Error> {
    require_absolute("config", path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(Error::Invalid(
            "config is not a bounded regular file".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::Invalid("config is not UTF-8".into()))?;
    Ok((toml::from_str(text)?, bytes))
}

fn require_absolute(field: &str, path: &Path) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::Invalid(format!("{field} must be absolute")));
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_-".contains(character))
    {
        return Err(Error::Invalid(format!(
            "{field} is not a bounded identifier"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, max: usize) -> Result<String, Error> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(Error::Invalid(format!(
            "{} exceeds bounded source",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(max).min(max));
    File::open(path)?
        .take(u64::try_from(max + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(Error::Invalid(format!(
            "{} exceeds bounded source",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| Error::Invalid(format!("{} is not UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use nq_profiles::{ProfileModule as _, host};
    use nq_protocol::{
        Capability, HelperRequest, InstanceId, MonotonicClock, MonotonicDeadline,
        PassiveHostLoadSampleSelectionV1, ProfileBinding, ProfileId, ProfileVersion, RequestId,
        ResponseOutcome, ScopeBinding, ScopeKind, Sha256Digest, SubjectBinding, SubjectId,
        VantageBinding, VantageKind, encode_ndjson, parse_response, sha256_bytes,
    };
    use serde_json::json;
    use tempfile::TempDir;

    use super::{
        CapacityContextV1, OBSERVER_PROFILE, ObserverConfigV1, ObserverSession, ProviderConfigV1,
        SOURCE_BASIS, capacity_context, executable_digest, sample_once, serve,
    };

    #[test]
    fn exact_threshold_vectors_remain_inclusive() {
        let evaluate = |load: f64, capacity: u32| load / f64::from(capacity) >= 2.0;
        assert!(!evaluate(7.996, 4));
        assert!(evaluate(8.0, 4));
        assert!(evaluate(8.004, 4));
    }

    #[test]
    fn source_basis_is_closed_to_exact_kernel_inputs() {
        assert_eq!(
            SOURCE_BASIS,
            "linux_proc_loadavg_plus_rust_available_parallelism_v1"
        );
        let _shape = CapacityContextV1 {
            schema: "nq.available_parallelism_context.v1".into(),
            cpus_allowed_list: "0-3".into(),
            cgroup_mode: "v2".into(),
            cpu_max: Some("max 100000".into()),
            cpuset_cpus_effective: Some("0-3".into()),
        };
    }

    struct Fixture {
        root: TempDir,
        observer_config_path: std::path::PathBuf,
        provider_config_path: std::path::PathBuf,
        binding: SubjectBinding,
        public: [u8; 32],
        observer_artifact: Sha256Digest,
        observer_config_digest: Sha256Digest,
        capacity_context_id: Sha256Digest,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new().expect("temp root");
            let store = root.path().join("samples");
            fs::create_dir(&store).expect("sample store");
            fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).expect("store mode");
            let private_key_path = root.path().join("sample.key");
            let secret = [23_u8; 32];
            let mut key_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&private_key_path)
                .expect("key file");
            key_file.write_all(&secret).expect("key bytes");
            let public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
            let binding = SubjectBinding {
                subject: SubjectId::new("host:passive-fixture").unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("host").unwrap(),
                    value: json!({"id": "passive-fixture"}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").unwrap(),
                    value: json!({}),
                },
            };
            let capacity_context_id =
                nq_protocol::semantic_digest(&capacity_context().expect("capacity context"))
                    .unwrap();
            let observer_config = ObserverConfigV1 {
                schema: "nq.passive_load_observer_config.v1".into(),
                sample_store: store.clone(),
                binding: binding.clone(),
                sample_interval_ms: 100,
                max_samples: 4,
                max_store_bytes: 262_144,
                expires_at: None,
                private_key_path,
                producer_issuer: "fixture.passive-observer".into(),
                producer_key_id: "fixture-key-1".into(),
                capacity_context_id: capacity_context_id.clone(),
            };
            let observer_text = toml::to_string(&observer_config).expect("observer config");
            let observer_config_path = root.path().join("observer.toml");
            fs::write(&observer_config_path, observer_text.as_bytes())
                .expect("write observer config");
            let observer_config_digest = sha256_bytes(observer_text.as_bytes());
            let observer_artifact = executable_digest().expect("artifact digest");
            let provider_config = ProviderConfigV1 {
                schema: "nq.passive_load_provider_config.v1".into(),
                sample_store: store,
                max_sample_age_ms: 60_000,
                observer_profile: OBSERVER_PROFILE.into(),
                observer_artifact_digest: observer_artifact.clone(),
                observer_config_digest: observer_config_digest.clone(),
                producer_issuer: "fixture.passive-observer".into(),
                producer_key_id: "fixture-key-1".into(),
                producer_public_key_hex: hex::encode(public),
                capacity_context_id: capacity_context_id.clone(),
            };
            let provider_config_path = root.path().join("provider.toml");
            fs::write(
                &provider_config_path,
                toml::to_string(&provider_config).expect("provider config"),
            )
            .expect("write provider config");
            Self {
                root,
                observer_config_path,
                provider_config_path,
                binding,
                public,
                observer_artifact,
                observer_config_digest,
                capacity_context_id,
            }
        }

        fn request(&self, request_id: &str) -> HelperRequest {
            let descriptor = host::MODULE.descriptor();
            HelperRequest::builder(
                RequestId::new(request_id).unwrap(),
                InstanceId::new("passive.fixture").unwrap(),
                ProfileBinding {
                    id: ProfileId::new(host::PROFILE_ID).unwrap(),
                    version: ProfileVersion::new(host::PROFILE_VERSION.to_string()).unwrap(),
                    digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str().to_owned())
                        .unwrap(),
                },
                self.binding.clone(),
                MonotonicDeadline {
                    clock: MonotonicClock::LinuxBoottime,
                    expires_at_ns: 1,
                },
            )
            .capability(Capability::new("read_procfs").unwrap())
            .capability(Capability::new("read_system_info").unwrap())
            .passive_host_load_sample(PassiveHostLoadSampleSelectionV1 {
                schema: nq_protocol::PASSIVE_HOST_LOAD_SELECTION_SCHEMA_V1.into(),
                cutoff_at: Utc::now(),
                max_age_ms: 60_000,
                observer_profile: OBSERVER_PROFILE.into(),
                observer_artifact_digest: self.observer_artifact.clone(),
                observer_config_digest: self.observer_config_digest.clone(),
                producer_issuer: "fixture.passive-observer".into(),
                producer_key_id: "fixture-key-1".into(),
                producer_public_key_digest: sha256_bytes(&self.public),
                capacity_context_id: self.capacity_context_id.clone(),
            })
            .build()
            .unwrap()
        }

        fn exchange(&self, request: &HelperRequest) -> nq_protocol::HelperResponse {
            let frame = encode_ndjson(request).unwrap();
            let mut output = Vec::new();
            serve(&self.provider_config_path, frame.as_slice(), &mut output).unwrap();
            parse_response(request, &output).unwrap()
        }
    }

    #[test]
    fn provider_replays_exact_preexisting_sample_without_resampling() {
        let fixture = Fixture::new();
        let first = sample_once(&fixture.observer_config_path).expect("first sample");
        let request = fixture.request("request-passive-1");
        let response = fixture.exchange(&request);
        let replay = fixture.exchange(&request);
        assert_eq!(response, replay);
        let ResponseOutcome::Report { report } = response.outcome else {
            panic!("eligible sample must report")
        };
        let embedded: nq_protocol::SignedPassiveHostLoadSampleV1 =
            serde_json::from_value(report.observations[0].payload["passive_sample"].clone())
                .unwrap();
        assert_eq!(embedded.payload_digest, first.payload_digest);
        assert_eq!(
            fs::read_dir(fixture.root.path().join("samples"))
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .is_ok_and(|entry| entry.file_name() != ".observer.lock")
                })
                .count(),
            1
        );
    }

    #[test]
    fn new_sample_is_distinct_and_missing_sample_refuses_without_fallback() {
        let fixture = Fixture::new();
        let missing = fixture.exchange(&fixture.request("request-missing"));
        assert!(matches!(missing.outcome, ResponseOutcome::Refusal { .. }));
        let first = sample_once(&fixture.observer_config_path).unwrap();
        let second = sample_once(&fixture.observer_config_path).unwrap();
        assert_ne!(first.payload_digest, second.payload_digest);
        assert_eq!(first.payload.sequence, 1);
        assert_eq!(second.payload.sequence, 2);
        let response = fixture.exchange(&fixture.request("request-passive-2"));
        let ResponseOutcome::Report { report } = response.outcome else {
            panic!("second sample must report")
        };
        let embedded: nq_protocol::SignedPassiveHostLoadSampleV1 =
            serde_json::from_value(report.observations[0].payload["passive_sample"].clone())
                .unwrap();
        assert_eq!(embedded.payload.sequence, 2);
    }

    #[test]
    fn duplicate_sampler_cannot_race_sequence_or_delivery() {
        let fixture = Fixture::new();
        let mut owner = ObserverSession::open(&fixture.observer_config_path).unwrap();
        let error = sample_once(&fixture.observer_config_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another observer owns this store")
        );
        let first = owner.append_one().unwrap();
        drop(owner);
        let second = sample_once(&fixture.observer_config_path).unwrap();
        assert_eq!(first.payload.sequence, 1);
        assert_eq!(second.payload.sequence, 2);
    }

    #[test]
    fn observer_configuration_drift_cannot_extend_existing_generation() {
        let fixture = Fixture::new();
        sample_once(&fixture.observer_config_path).unwrap();
        let mut config: ObserverConfigV1 =
            toml::from_str(&fs::read_to_string(&fixture.observer_config_path).unwrap()).unwrap();
        config.sample_interval_ms += 1;
        fs::write(
            &fixture.observer_config_path,
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
        let error = sample_once(&fixture.observer_config_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("sample differs from exact producer, observer, context, or binding")
        );
    }

    #[test]
    fn missing_sample_in_sequence_fails_closed() {
        let fixture = Fixture::new();
        sample_once(&fixture.observer_config_path).unwrap();
        sample_once(&fixture.observer_config_path).unwrap();
        let first = fs::read_dir(fixture.root.path().join("samples"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("sample-00000000000000000001-")
            })
            .unwrap();
        fs::remove_file(first.path()).unwrap();
        let error = sample_once(&fixture.observer_config_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing or rolled-back occurrence")
        );
    }
}
