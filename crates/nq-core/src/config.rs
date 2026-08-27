//! Strict human-edited configuration.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use nq_helper_sandbox::IsolationLimits;

/// The supported configuration document schema.
pub const CONFIG_SCHEMA: &str = "nq.config.v1";

/// Maximum accepted UTF-8 configuration document size.
pub const MAX_CONFIG_BYTES: usize = 1_048_576;

/// Maximum independently scheduled watcher instances in one daemon.
///
/// Together with the per-launch descriptor cap, this keeps the service's
/// worst-case retained helper descriptors below the packaged `LimitNOFILE`.
pub const MAX_WATCHERS: usize = 32;

/// One strictly parsed configuration and the exact source bytes that produced it.
///
/// Keeping the bytes next to the parsed value lets an operator workflow validate
/// intent once and atomically activate that same document without reopening a
/// mutable pathname.
#[derive(Debug)]
pub struct LoadedConfig {
    config: NqConfig,
    source_path: PathBuf,
    source_identity: ConfigSourceIdentity,
    source_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigSourceIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Complete daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NqConfig {
    /// Exact configuration schema identifier.
    pub schema: String,
    /// `SQLite` database path.
    pub database_path: PathBuf,
    /// Local daemon API socket.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    /// Directory containing active admission locks.
    pub admissions_dir: PathBuf,
    /// Root for NQ-owned private persistent-helper socket directories.
    #[serde(default = "default_helper_runtime_dir")]
    pub helper_runtime_dir: PathBuf,
    /// Independently scheduled watcher instances.
    #[serde(default)]
    pub watchers: Vec<WatcherConfig>,
}

/// NQ-owned watcher deployment binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WatcherConfig {
    /// Stable, operator-chosen instance identifier.
    pub instance_id: String,
    /// Fixed executable and argument vector.
    pub command: CommandConfig,
    /// Helper carrier.
    #[serde(default)]
    pub carrier: Carrier,
    /// Requested compiled profile.
    pub profile: ProfileSelection,
    /// Profile-specific root subject token.
    pub subject: String,
    /// Maximum scope the instance may observe.
    pub scope: ScopeConfig,
    /// Named collection vantage.
    pub vantage: VantageConfig,
    /// Configured capability ceiling.
    #[serde(default)]
    pub capability_ceiling: BTreeSet<String>,
    /// Independent scheduling policy.
    #[serde(default)]
    pub schedule: ScheduleConfig,
    /// Per-request resource limits.
    #[serde(default)]
    pub resources: ResourceLimits,
    /// Optional checkpoint handling.
    #[serde(default)]
    pub checkpoint_policy: CheckpointPolicy,
    /// Closed passive host-load sample provider policy. Absence preserves the
    /// ordinary occurrence-bounded helper law byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive_host_load_sample: Option<PassiveHostLoadProviderConfigV1>,
}

/// Immutable deployment selection for the one qualified passive load source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PassiveHostLoadProviderConfigV1 {
    /// Must be `nq.passive_host_load_provider_config.v1`.
    pub schema: String,
    /// Maximum age of a sample at the NQ-owned pre-launch cutoff.
    pub max_sample_age_ms: u64,
    /// Exact closed sampler profile.
    pub observer_profile: String,
    /// Exact deployed observer executable digest.
    pub observer_artifact_digest: String,
    /// Exact deployed observer configuration digest.
    pub observer_config_digest: String,
    /// Authenticated sample-producer issuer.
    pub producer_issuer: String,
    /// Exact Ed25519 sample-producer key identity.
    pub producer_key_id: String,
    /// Lowercase hexadecimal Ed25519 public key bytes.
    pub producer_public_key_hex: String,
    /// Qualified `available_parallelism()` execution/vantage context digest.
    pub capacity_context_id: String,
}

/// Fixed helper command. No shell interpolation is performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandConfig {
    /// Absolute executable path.
    pub executable: PathBuf,
    /// Fixed arguments following argv[0].
    #[serde(default)]
    pub args: Vec<String>,
    /// Minimal explicit environment additions after sanitization.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Local account name or decimal UID used only for this helper process.
    pub execution_account: String,
    /// Explicit debug-build exception for unprivileged same-identity tests.
    #[serde(default)]
    pub allow_same_identity_in_debug: bool,
    /// Sanitized working directory.
    pub working_directory: PathBuf,
}

/// Helper transport selection.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// One request per process over stdin/stdout.
    #[default]
    Stdio,
    /// Supervised persistent request/response helper over a private Unix socket.
    Unix,
}

/// Exact compiled profile selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelection {
    /// Profile identifier.
    pub id: String,
    /// Profile semantic version.
    pub version: u32,
}

/// Profile-controlled scope binding with NQ-owned bounded parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    /// Compiled scope vocabulary entry.
    pub kind: String,
    /// Bounded structured scope. V1 profiles conventionally include an `id`
    /// string used for exact correlation.
    pub value: serde_json::Value,
}

/// Profile-controlled vantage binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VantageConfig {
    /// Compiled vantage vocabulary entry.
    pub kind: String,
    /// Bounded structured vantage parameters.
    pub value: serde_json::Value,
}

/// Per-instance scheduling and deadline policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    /// Collection cadence.
    pub interval_seconds: u64,
    /// Maximum symmetric startup jitter.
    pub jitter_seconds: u64,
    /// Hard request deadline.
    pub deadline_ms: u64,
    /// Initial retry backoff.
    pub retry_backoff_seconds: u64,
    /// Maximum retry backoff.
    pub max_retry_backoff_seconds: u64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 300,
            jitter_seconds: 15,
            deadline_ms: 30_000,
            retry_backoff_seconds: 10,
            max_retry_backoff_seconds: 300,
        }
    }
}

/// Bounds sent to and independently enforced against a helper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum response frame bytes.
    pub max_response_bytes: usize,
    /// Maximum retained stderr bytes.
    pub max_stderr_bytes: usize,
    /// Maximum observations in a report.
    pub max_observations: usize,
    /// Maximum virtual address space for each helper process.
    pub max_address_space_bytes: u64,
    /// Maximum CPU seconds consumed by each helper process.
    pub max_cpu_seconds: u64,
    /// Maximum processes/threads available to the helper execution account.
    pub max_processes: u64,
    /// Maximum open descriptors available to each helper process.
    pub max_open_files: u64,
    /// Maximum size of any regular file written by a helper process.
    pub max_file_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 1_048_576,
            max_stderr_bytes: 65_536,
            max_observations: 1_024,
            max_address_space_bytes: 536_870_912,
            max_cpu_seconds: 60,
            max_processes: 32,
            max_open_files: 128,
            max_file_bytes: 67_108_864,
        }
    }
}

impl ResourceLimits {
    pub(crate) fn isolation_limits(&self) -> IsolationLimits {
        IsolationLimits {
            address_space_bytes: self.max_address_space_bytes,
            cpu_seconds: self.max_cpu_seconds,
            processes: self.max_processes,
            open_files: self.max_open_files,
            file_bytes: self.max_file_bytes,
        }
    }
}

/// Checkpoint advancement policy.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPolicy {
    /// This helper does not use checkpoints.
    #[default]
    Disabled,
    /// Advance only after the corresponding report commits as admitted.
    AdvanceAfterAdmission,
}

/// Configuration parsing or semantic validation failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML parsing failed.
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    /// A semantic constraint failed.
    #[error("invalid configuration at {path}: {message}")]
    Invalid {
        /// Configuration path.
        path: String,
        /// Human-readable explanation.
        message: String,
    },
}

impl LoadedConfig {
    /// Open, bound, parse, and validate one regular configuration file without
    /// following a final symlink.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for an unsafe or unstable source, invalid UTF-8,
    /// an oversized document, or an invalid configuration.
    pub fn load(path: &Path) -> Result<Self, io::Error> {
        let (source_bytes, source_identity) = read_config_source(path)?;
        let input = std::str::from_utf8(&source_bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("configuration is not UTF-8: {error}"),
            )
        })?;
        let config = NqConfig::from_toml(input)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Self {
            config,
            source_path: path.to_path_buf(),
            source_identity,
            source_bytes,
        })
    }

    /// Return the strictly parsed configuration value.
    #[must_use]
    pub const fn config(&self) -> &NqConfig {
        &self.config
    }

    /// Return the exact bytes that were parsed and validated.
    #[must_use]
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    /// Consume the snapshot and return its parsed configuration.
    #[must_use]
    pub fn into_config(self) -> NqConfig {
        self.config
    }

    /// Verify that the named source still identifies the same file and exact
    /// bytes captured by [`Self::load`].
    ///
    /// Activation remains safe even if the source changes immediately after
    /// this check because callers persist [`Self::source_bytes`], never bytes
    /// reopened from the pathname.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the source is gone, unsafe, oversized, or has
    /// changed since it was parsed.
    pub fn verify_source_unchanged(&self) -> Result<(), io::Error> {
        let (current_bytes, current_identity) = read_config_source(&self.source_path)?;
        if current_identity != self.source_identity || current_bytes != self.source_bytes {
            return Err(io::Error::other(
                "configuration source changed after validation",
            ));
        }
        Ok(())
    }
}

impl NqConfig {
    /// Parse and strictly validate a TOML document.
    ///
    /// # Errors
    ///
    /// Returns a strict TOML shape error or a semantic configuration error.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Parse a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or wraps invalid configuration as invalid data.
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        LoadedConfig::load(path).map(LoadedConfig::into_config)
    }

    /// Enforce cross-field invariants that TOML shape cannot express.
    ///
    /// # Errors
    ///
    /// Returns the exact configuration path and violated invariant.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != CONFIG_SCHEMA {
            return Err(invalid("schema", format!("expected {CONFIG_SCHEMA}")));
        }
        require_absolute("database_path", &self.database_path)?;
        require_absolute("socket_path", &self.socket_path)?;
        require_absolute("admissions_dir", &self.admissions_dir)?;
        require_absolute("helper_runtime_dir", &self.helper_runtime_dir)?;
        if self.watchers.len() > MAX_WATCHERS {
            return Err(invalid(
                "watchers",
                format!("at most {MAX_WATCHERS} watcher instances are accepted"),
            ));
        }

        let mut ids = HashSet::new();
        for (index, watcher) in self.watchers.iter().enumerate() {
            let base = format!("watchers[{index}]");
            if watcher.instance_id.is_empty()
                || watcher.instance_id.len() > 128
                || !watcher
                    .instance_id
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
            {
                return Err(invalid(
                    format!("{base}.instance_id"),
                    "must be 1..=128 ASCII identifier characters",
                ));
            }
            if !ids.insert(&watcher.instance_id) {
                return Err(invalid(
                    format!("{base}.instance_id"),
                    "duplicate instance identifier",
                ));
            }
            require_absolute(
                format!("{base}.command.executable"),
                &watcher.command.executable,
            )?;
            require_absolute(
                format!("{base}.command.working_directory"),
                &watcher.command.working_directory,
            )?;
            nq_helper_sandbox::resolve_account(
                &watcher.command.execution_account,
                watcher.command.allow_same_identity_in_debug,
            )
            .map_err(|error| {
                invalid(
                    format!("{base}.command.execution_account"),
                    error.to_string(),
                )
            })?;
            if watcher.command.args.len() > 128
                || watcher
                    .command
                    .args
                    .iter()
                    .any(|argument| argument.len() > 4_096)
            {
                return Err(invalid(
                    format!("{base}.command.args"),
                    "at most 128 arguments of at most 4096 bytes are accepted",
                ));
            }
            if watcher.command.env.len() > 64
                || watcher
                    .command
                    .env
                    .values()
                    .any(|value| value.len() > 4_096)
            {
                return Err(invalid(
                    format!("{base}.command.env"),
                    "at most 64 variables with values of at most 4096 bytes are accepted",
                ));
            }
            if watcher.profile.id.is_empty() || watcher.profile.version == 0 {
                return Err(invalid(
                    format!("{base}.profile"),
                    "invalid profile identity",
                ));
            }
            validate_binding_token(&format!("{base}.subject"), &watcher.subject)?;
            validate_binding_token(&format!("{base}.scope.kind"), &watcher.scope.kind)?;
            validate_binding_token(&format!("{base}.vantage.kind"), &watcher.vantage.kind)?;
            let scope_bytes = serde_json::to_vec(&watcher.scope.value)
                .map_err(|error| invalid(format!("{base}.scope.value"), error.to_string()))?
                .len();
            let vantage_bytes = serde_json::to_vec(&watcher.vantage.value)
                .map_err(|error| invalid(format!("{base}.vantage.value"), error.to_string()))?
                .len();
            if scope_bytes > 65_536 || vantage_bytes > 65_536 {
                return Err(invalid(
                    format!("{base}.scope/vantage"),
                    "binding JSON exceeds 65536 bytes",
                ));
            }
            if watcher.schedule.interval_seconds == 0 {
                return Err(invalid(
                    format!("{base}.schedule.interval_seconds"),
                    "must be non-zero",
                ));
            }
            if watcher.schedule.interval_seconds > 31_536_000
                || watcher.schedule.jitter_seconds > watcher.schedule.interval_seconds
            {
                return Err(invalid(
                    format!("{base}.schedule"),
                    "interval is capped at one year and jitter may not exceed interval",
                ));
            }
            if !(10..=3_600_000).contains(&watcher.schedule.deadline_ms) {
                return Err(invalid(
                    format!("{base}.schedule.deadline_ms"),
                    "must be between 10 and 3600000",
                ));
            }
            if watcher.schedule.retry_backoff_seconds > watcher.schedule.max_retry_backoff_seconds {
                return Err(invalid(
                    format!("{base}.schedule"),
                    "initial retry backoff exceeds maximum",
                ));
            }
            if !(256..=16_777_216).contains(&watcher.resources.max_response_bytes) {
                return Err(invalid(
                    format!("{base}.resources.max_response_bytes"),
                    "must be between 256 and 16777216",
                ));
            }
            if watcher.resources.max_stderr_bytes > 1_048_576 {
                return Err(invalid(
                    format!("{base}.resources.max_stderr_bytes"),
                    "must be no greater than 1048576",
                ));
            }
            if !(1..=100_000).contains(&watcher.resources.max_observations) {
                return Err(invalid(
                    format!("{base}.resources.max_observations"),
                    "must be between 1 and 100000",
                ));
            }
            if !(67_108_864..=4_294_967_296).contains(&watcher.resources.max_address_space_bytes) {
                return Err(invalid(
                    format!("{base}.resources.max_address_space_bytes"),
                    "must be between 67108864 and 4294967296",
                ));
            }
            if !(1..=3_600).contains(&watcher.resources.max_cpu_seconds) {
                return Err(invalid(
                    format!("{base}.resources.max_cpu_seconds"),
                    "must be between 1 and 3600",
                ));
            }
            if !(1..=256).contains(&watcher.resources.max_processes) {
                return Err(invalid(
                    format!("{base}.resources.max_processes"),
                    "must be between 1 and 256",
                ));
            }
            if !(64..=1_024).contains(&watcher.resources.max_open_files) {
                return Err(invalid(
                    format!("{base}.resources.max_open_files"),
                    "must be between 64 and 1024",
                ));
            }
            if watcher.resources.max_file_bytes > 1_073_741_824 {
                return Err(invalid(
                    format!("{base}.resources.max_file_bytes"),
                    "must be no greater than 1073741824",
                ));
            }
            for key in watcher.command.env.keys() {
                if !valid_env_key(key)
                    || key.starts_with("LD_")
                    || key.starts_with("DYLD_")
                    || matches!(
                        key.as_str(),
                        "PATH"
                            | "LANG"
                            | "LC_ALL"
                            | "TZ"
                            | "HOME"
                            | "LD_PRELOAD"
                            | "LD_LIBRARY_PATH"
                            | "PYTHONPATH"
                            | "PYTHONHOME"
                            | "PERL5LIB"
                            | "PERL5OPT"
                            | "RUBYLIB"
                            | "RUBYOPT"
                            | "NODE_PATH"
                            | "NODE_OPTIONS"
                            | "BASH_ENV"
                            | "ENV"
                            | "GCONV_PATH"
                            | "GLIBC_TUNABLES"
                            | "LOCPATH"
                            | "JAVA_TOOL_OPTIONS"
                            | "JDK_JAVA_OPTIONS"
                            | "NQ_HELPER_SOCKET"
                            | "NQ_HELPER_INSTANCE_ID"
                    )
                {
                    return Err(invalid(
                        format!("{base}.command.env.{key}"),
                        "unsafe, reserved, or invalid environment key",
                    ));
                }
            }
            if watcher.capability_ceiling.len() > 256 {
                return Err(invalid(
                    format!("{base}.capability_ceiling"),
                    "at most 256 capabilities are accepted",
                ));
            }
            for capability in &watcher.capability_ceiling {
                validate_binding_token(&format!("{base}.capability_ceiling"), capability)?;
            }
            if let Some(passive) = &watcher.passive_host_load_sample {
                if passive.schema != "nq.passive_host_load_provider_config.v1" {
                    return Err(invalid(
                        format!("{base}.passive_host_load_sample.schema"),
                        "expected nq.passive_host_load_provider_config.v1",
                    ));
                }
                if watcher.profile.id != "nq.host" || watcher.profile.version != 1 {
                    return Err(invalid(
                        format!("{base}.passive_host_load_sample"),
                        "the closed passive source supports only nq.host/v1",
                    ));
                }
                if watcher.carrier != Carrier::Stdio {
                    return Err(invalid(
                        format!("{base}.carrier"),
                        "passive sample retrieval uses one bounded stdio custody exchange",
                    ));
                }
                if watcher.checkpoint_policy != CheckpointPolicy::Disabled {
                    return Err(invalid(
                        format!("{base}.checkpoint_policy"),
                        "passive samples have exact occurrence identity and do not use polling checkpoints",
                    ));
                }
                if watcher.capability_ceiling
                    != BTreeSet::from(["read_procfs".to_owned(), "read_system_info".to_owned()])
                {
                    return Err(invalid(
                        format!("{base}.capability_ceiling"),
                        "passive custody must retain the exact underlying procfs plus Rust system-info capability basis",
                    ));
                }
                if !(1..=300_000).contains(&passive.max_sample_age_ms) {
                    return Err(invalid(
                        format!("{base}.passive_host_load_sample.max_sample_age_ms"),
                        "must be between 1 and the nq.host/v1 300000ms reliance horizon",
                    ));
                }
                for (field, value) in [
                    ("observer_profile", passive.observer_profile.as_str()),
                    ("producer_issuer", passive.producer_issuer.as_str()),
                    ("producer_key_id", passive.producer_key_id.as_str()),
                ] {
                    if value.is_empty() || value.len() > 256 {
                        return Err(invalid(
                            format!("{base}.passive_host_load_sample.{field}"),
                            "must contain 1 through 256 UTF-8 bytes",
                        ));
                    }
                }
                let public_key = hex::decode(&passive.producer_public_key_hex).map_err(|_| {
                    invalid(
                        format!("{base}.passive_host_load_sample.producer_public_key_hex"),
                        "must be lowercase hexadecimal Ed25519 public-key bytes",
                    )
                })?;
                if public_key.len() != 32
                    || passive.producer_public_key_hex
                        != passive.producer_public_key_hex.to_ascii_lowercase()
                {
                    return Err(invalid(
                        format!("{base}.passive_host_load_sample.producer_public_key_hex"),
                        "must encode exactly 32 bytes in lowercase hexadecimal",
                    ));
                }
                nq_protocol::Sha256Digest::parse(passive.capacity_context_id.clone()).map_err(
                    |error| {
                        invalid(
                            format!("{base}.passive_host_load_sample.capacity_context_id"),
                            error.to_string(),
                        )
                    },
                )?;
                for (field, value) in [
                    (
                        "observer_artifact_digest",
                        &passive.observer_artifact_digest,
                    ),
                    ("observer_config_digest", &passive.observer_config_digest),
                ] {
                    nq_protocol::Sha256Digest::parse(value.clone()).map_err(|error| {
                        invalid(
                            format!("{base}.passive_host_load_sample.{field}"),
                            error.to_string(),
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Resolve one configured instance.
    #[must_use]
    pub fn watcher(&self, instance_id: &str) -> Option<&WatcherConfig> {
        self.watchers
            .iter()
            .find(|watcher| watcher.instance_id == instance_id)
    }
}

fn read_config_source(path: &Path) -> Result<(Vec<u8>, ConfigSourceIdentity), io::Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let identity_before = config_source_identity(&file)?;
    if identity_before.length > MAX_CONFIG_BYTES as u64 {
        return Err(config_too_large(identity_before.length));
    }

    let capacity = usize::try_from(identity_before.length)
        .map_err(|_| config_too_large(identity_before.length))?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(config_too_large(bytes.len() as u64));
    }

    let identity_after = config_source_identity(&file)?;
    if identity_before != identity_after || identity_after.length != bytes.len() as u64 {
        return Err(io::Error::other(
            "configuration source changed while it was being read",
        ));
    }
    Ok((bytes, identity_after))
}

fn config_source_identity(file: &File) -> Result<ConfigSourceIdentity, io::Error> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration source must be a regular file",
        ));
    }
    Ok(ConfigSourceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        group: metadata.gid(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn config_too_large(actual_bytes: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("configuration exceeds the {MAX_CONFIG_BYTES}-byte limit ({actual_bytes} bytes)"),
    )
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        path: path.into(),
        message: message.into(),
    }
}

fn require_absolute(path: impl Into<String>, value: &Path) -> Result<(), ConfigError> {
    if value.is_absolute() {
        Ok(())
    } else {
        Err(invalid(path, "must be absolute"))
    }
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn validate_binding_token(path: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':' | '/' | '@'))
    {
        Err(invalid(path, "invalid controlled vocabulary token"))
    } else {
        Ok(())
    }
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/nq/nqd.sock")
}

fn default_helper_runtime_dir() -> PathBuf {
    PathBuf::from("/run/nq/helpers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn minimal() -> String {
        format!(
            r#"
schema = "nq.config.v1"
database_path = "/var/lib/nq/nq.db"
admissions_dir = "/var/lib/nq/admissions"

[[watchers]]
instance_id = "host.primary"
subject = "host:local"
scope = {{ kind = "host", value = {{ id = "local" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = ["host.read"]

[watchers.command]
executable = "/usr/lib/nq/nq-host-helper"
args = ["--stdio"]
execution_account = "{}"
allow_same_identity_in_debug = true
working_directory = "/var/empty"

[watchers.profile]
id = "nq.host"
version = 1
"#,
            nix::unistd::geteuid().as_raw()
        )
    }

    #[test]
    fn parses_minimal_strict_config() {
        let config = NqConfig::from_toml(&minimal()).expect("valid config");
        assert_eq!(config.watchers[0].schedule.deadline_ms, 30_000);
        assert_eq!(config.watchers[0].carrier, Carrier::Stdio);
    }

    #[test]
    fn passive_load_policy_is_closed_and_cannot_enable_measurement_fallback() {
        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        let watcher = &mut config.watchers[0];
        watcher.capability_ceiling =
            BTreeSet::from(["read_procfs".to_owned(), "read_system_info".to_owned()]);
        watcher.passive_host_load_sample = Some(PassiveHostLoadProviderConfigV1 {
            schema: "nq.passive_host_load_provider_config.v1".into(),
            max_sample_age_ms: 60_000,
            observer_profile: "nq.host_load_passive_sampler.v1".into(),
            observer_artifact_digest: format!("sha256:{}", "a".repeat(64)),
            observer_config_digest: format!("sha256:{}", "b".repeat(64)),
            producer_issuer: "fixture.passive-observer".into(),
            producer_key_id: "fixture-key-1".into(),
            producer_public_key_hex: "11".repeat(32),
            capacity_context_id: format!("sha256:{}", "c".repeat(64)),
        });
        config.validate().expect("closed passive policy");

        let mut fallback = config.clone();
        fallback.watchers[0]
            .capability_ceiling
            .insert("arbitrary.read".into());
        assert!(matches!(
            fallback.validate(),
            Err(ConfigError::Invalid { path, .. }) if path.ends_with("capability_ceiling")
        ));

        let mut stale = config;
        stale.watchers[0]
            .passive_host_load_sample
            .as_mut()
            .unwrap()
            .max_sample_age_ms = 300_001;
        assert!(matches!(
            stale.validate(),
            Err(ConfigError::Invalid { path, .. }) if path.ends_with("max_sample_age_ms")
        ));
    }

    #[test]
    fn passive_generation_rotation_changes_exact_watcher_semantics() {
        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        let watcher = &mut config.watchers[0];
        watcher.capability_ceiling =
            BTreeSet::from(["read_procfs".to_owned(), "read_system_info".to_owned()]);
        watcher.passive_host_load_sample = Some(PassiveHostLoadProviderConfigV1 {
            schema: "nq.passive_host_load_provider_config.v1".into(),
            max_sample_age_ms: 30_000,
            observer_profile: "nq.host_load_passive_sampler.v1".into(),
            observer_artifact_digest: format!("sha256:{}", "a".repeat(64)),
            observer_config_digest: format!("sha256:{}", "b".repeat(64)),
            producer_issuer: "fixture.passive-observer".into(),
            producer_key_id: "fixture-key-1".into(),
            producer_public_key_hex: "11".repeat(32),
            capacity_context_id: format!("sha256:{}", "c".repeat(64)),
        });
        let first = nq_protocol::semantic_digest(watcher).expect("first exact watcher digest");
        watcher
            .passive_host_load_sample
            .as_mut()
            .unwrap()
            .observer_config_digest = format!("sha256:{}", "d".repeat(64));
        let successor =
            nq_protocol::semantic_digest(watcher).expect("successor exact watcher digest");
        assert_ne!(first, successor);
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = format!("{}\nmagic = true", minimal());
        assert!(matches!(
            NqConfig::from_toml(&text),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn rejects_duplicate_instances() {
        let text = format!(
            "{}\n{}",
            minimal(),
            minimal().split("[[watchers]]").nth(1).unwrap()
        );
        assert!(NqConfig::from_toml(&text).is_err());
    }

    #[test]
    fn rejects_more_than_the_proven_watcher_descriptor_budget() {
        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        let template = config.watchers[0].clone();
        config.watchers = (0..=MAX_WATCHERS)
            .map(|index| {
                let mut watcher = template.clone();
                watcher.instance_id = format!("host.{index}");
                watcher
            })
            .collect();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid { path, message })
                if path == "watchers" && message.contains("at most 32")
        ));
    }

    #[test]
    fn rejects_os_resource_limits_outside_the_compiled_ceiling() {
        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        config.watchers[0].resources.max_address_space_bytes = 67_108_863;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid { path, .. })
                if path.ends_with("resources.max_address_space_bytes")
        ));

        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        config.watchers[0].resources.max_cpu_seconds = 3_601;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid { path, .. })
                if path.ends_with("resources.max_cpu_seconds")
        ));

        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        config.watchers[0].resources.max_processes = 257;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid { path, .. })
                if path.ends_with("resources.max_processes")
        ));

        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        config.watchers[0].resources.max_open_files = 63;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid { path, .. })
                if path.ends_with("resources.max_open_files")
        ));

        let mut config = NqConfig::from_toml(&minimal()).expect("valid config");
        config.watchers[0].resources.max_file_bytes = 1_073_741_825;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid { path, .. })
                if path.ends_with("resources.max_file_bytes")
        ));
    }

    #[test]
    fn rejects_loader_environment_escape() {
        for (key, value) in [
            ("LD_PRELOAD", "/tmp/x.so"),
            ("GLIBC_TUNABLES", "glibc.rtld.nns=8"),
            ("PATH", "/tmp"),
        ] {
            let text = minimal().replace(
                "working_directory = \"/var/empty\"",
                &format!(
                    "working_directory = \"/var/empty\"\n[watchers.command.env]\n{key} = \"{value}\""
                ),
            );
            assert!(NqConfig::from_toml(&text).is_err());
        }
    }

    #[test]
    fn loaded_config_retains_exact_validated_bytes_and_detects_mutation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("candidate.toml");
        let source = minimal();
        std::fs::write(&path, &source).expect("write candidate");

        let loaded = LoadedConfig::load(&path).expect("load candidate snapshot");
        assert_eq!(loaded.source_bytes(), source.as_bytes());
        assert_eq!(loaded.config().schema, CONFIG_SCHEMA);

        std::fs::write(&path, b"unvalidated = true\n").expect("mutate candidate");
        let error = loaded
            .verify_source_unchanged()
            .expect_err("mutated candidate must be rejected");
        assert!(error.to_string().contains("changed after validation"));
        assert_eq!(loaded.source_bytes(), source.as_bytes());
    }

    #[test]
    fn loaded_config_detects_path_replacement_even_with_identical_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("candidate.toml");
        let retained = directory.path().join("retained.toml");
        let source = minimal();
        std::fs::write(&path, &source).expect("write candidate");
        let loaded = LoadedConfig::load(&path).expect("load candidate snapshot");

        std::fs::rename(&path, &retained).expect("retain original inode");
        std::fs::write(&path, &source).expect("replace with same bytes");
        let error = loaded
            .verify_source_unchanged()
            .expect_err("replacement inode must be rejected");
        assert!(error.to_string().contains("changed after validation"));
    }

    #[test]
    fn file_loader_rejects_symlinks_and_oversized_documents() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.toml");
        let link = directory.path().join("candidate.toml");
        std::fs::write(&target, minimal()).expect("write target");
        symlink(&target, &link).expect("create candidate symlink");
        assert!(
            LoadedConfig::load(&link).is_err(),
            "a candidate final symlink must not be followed"
        );

        let oversized = directory.path().join("oversized.toml");
        std::fs::write(&oversized, vec![b' '; MAX_CONFIG_BYTES + 1])
            .expect("write oversized candidate");
        let error = LoadedConfig::load(&oversized).expect_err("oversized input must fail");
        assert!(error.to_string().contains("byte limit"));
    }
}
