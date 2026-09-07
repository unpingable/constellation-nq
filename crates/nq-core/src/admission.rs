//! Explicit, drift-detecting watcher admission locks.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use nix::unistd::{Gid, Uid};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::config::WatcherConfig;
use crate::identity::{ExecutionIdentity, IdentityError};

/// Exact admission document schema.
pub const ADMISSION_SCHEMA: &str = "nq.admission_lock.v1";

/// Hard upper bound for one canonical admission document.
const MAX_ADMISSION_LOCK_BYTES: u64 = 1_048_576;

/// Machine-produced active watcher binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLock {
    /// Exact lock schema.
    pub schema: String,
    /// Opaque NQ-owned identity of this admission event.
    pub admission_id: String,
    /// NQ-owned instance.
    pub instance_id: String,
    /// Canonical configured-instance digest.
    pub config_digest: String,
    /// Complete locally verifiable executable identity.
    pub execution: ExecutionIdentity,
    /// Independently resolved profile identity.
    pub profile: AdmittedProfile,
    /// Exact profile-owned verdict policy admitted with this binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_policy: Option<nq_profiles::ThresholdPolicyInput>,
    /// Exact helper protocol version.
    pub protocol_version: String,
    /// Capabilities actually granted after intersection with the ceiling.
    pub granted_capabilities: BTreeSet<String>,
    /// Bounded conformance result used for this admission.
    pub conformance: ConformanceReceipt,
    /// Admission wall time.
    pub admitted_at: DateTime<Utc>,
    /// Local operator identity.
    pub operator: OperatorIdentity,
}

/// Compiled profile bound by an admission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmittedProfile {
    /// Profile identifier.
    pub id: String,
    /// Profile version.
    pub version: u32,
    /// Digest of its canonical compiled descriptor.
    pub digest: String,
}

/// Evidence that the candidate completed the admission-time checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReceipt {
    /// Conformance implementation/tool version.
    pub tool_version: String,
    /// Successful protocol corpus result.
    pub protocol_passed: bool,
    /// Content identity of the exact embedded corpus that passed.
    pub protocol_corpus_digest: String,
    /// Number of valid and hostile corpus fixtures actually checked.
    pub protocol_fixtures_checked: u16,
    /// Successful bounded dry collection result.
    pub dry_collection_passed: bool,
    /// Semantic digest of the mandatory profile-valid dry report.
    pub dry_report_digest: Option<String>,
}

/// Auditable local actor identity. Names are presentation hints; numeric IDs
/// are the local identity basis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorIdentity {
    /// Effective Unix user ID.
    pub uid: u32,
    /// Effective Unix group ID.
    pub gid: u32,
    /// Optional local login hint supplied by the invoking environment.
    pub login_hint: Option<String>,
}

/// Successful recomputation result used to bind a run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionVerification {
    /// Digest of the entire canonical active lock.
    pub binding_digest: String,
    /// Exact lock admitted time.
    pub admitted_at: DateTime<Utc>,
}

/// Candidate inputs that only the admission workflow may supply after actual
/// conformance and dry collection.
#[derive(Debug, Clone)]
pub struct CandidateEvidence {
    /// Compiled profile digest.
    pub profile_digest: String,
    /// Exact protocol version.
    pub protocol_version: String,
    /// Helper-declared capabilities. This declaration is untrusted and is only
    /// intersected with the configured ceiling.
    pub declared_capabilities: BTreeSet<String>,
    /// Conformance receipt.
    pub conformance: ConformanceReceipt,
}

/// Admission lock manager.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdmissionManager;

/// Typed admission diagnostic.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// Executable identity could not be established or drifted.
    #[error(transparent)]
    Binary(#[from] IdentityError),
    /// Configuration differs from the active lock.
    #[error("config drift for instance {instance_id}")]
    ConfigDrift {
        /// Affected instance.
        instance_id: String,
    },
    /// Profile differs from the active lock.
    #[error("profile drift for instance {instance_id}: {message}")]
    ProfileDrift {
        /// Affected instance.
        instance_id: String,
        /// Differing profile fact.
        message: String,
    },
    /// Protocol differs from the active lock.
    #[error("protocol drift for instance {instance_id}")]
    ProtocolDrift {
        /// Affected instance.
        instance_id: String,
    },
    /// Lock shape or invariants are malformed.
    #[error("malformed admission for {instance_id}: {message}")]
    Malformed {
        /// Affected instance or `unknown` before decoding.
        instance_id: String,
        /// Explanation.
        message: String,
    },
    /// Conformance did not pass.
    #[error("candidate did not pass conformance: {0}")]
    ConformanceFailed(String),
    /// The locally compiled conformance corpus differs from the admitted one.
    #[error("conformance drift for instance {instance_id}: {message}")]
    ConformanceDrift {
        /// Affected instance.
        instance_id: String,
        /// Differing conformance fact.
        message: String,
    },
    /// Admission file I/O failed.
    #[error("admission I/O at {path}: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
}

impl AdmissionManager {
    /// Compute the canonical binding digest of a validated lock without
    /// requalifying executable bytes. This is used only to detect an active
    /// binding-file replacement and never substitutes for [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns when the lock shape or canonical representation is invalid.
    pub fn binding_digest(&self, lock: &AdmissionLock) -> Result<String, AdmissionError> {
        lock.validate_shape()?;
        Ok(digest_bytes(&canonical_json(lock)?))
    }

    /// Create a candidate only after the caller has run the conformance corpus
    /// and a bounded dry collection.
    ///
    /// # Errors
    ///
    /// Returns a typed admission error when conformance did not pass or the
    /// executable/interpreter chain cannot be identified safely.
    pub fn candidate(
        &self,
        watcher: &WatcherConfig,
        evidence: CandidateEvidence,
    ) -> Result<AdmissionLock, AdmissionError> {
        let execution = ExecutionIdentity::resolve_command(&watcher.command)?;
        Self::candidate_with_execution(watcher, evidence, execution)
    }

    /// Build a candidate from the exact descriptor-bound identity used by the
    /// dry collection.
    pub(crate) fn candidate_with_execution(
        watcher: &WatcherConfig,
        evidence: CandidateEvidence,
        execution: ExecutionIdentity,
    ) -> Result<AdmissionLock, AdmissionError> {
        if !evidence.conformance.protocol_passed {
            return Err(AdmissionError::ConformanceFailed(
                "protocol corpus failed".into(),
            ));
        }
        if !evidence.conformance.dry_collection_passed {
            return Err(AdmissionError::ConformanceFailed(
                "bounded dry collection failed".into(),
            ));
        }
        let granted_capabilities = evidence
            .declared_capabilities
            .intersection(&watcher.capability_ceiling)
            .cloned()
            .collect();
        validate_candidate_profile(watcher, &evidence, &granted_capabilities)?;
        Ok(AdmissionLock {
            schema: ADMISSION_SCHEMA.into(),
            admission_id: uuid::Uuid::new_v4().to_string(),
            instance_id: watcher.instance_id.clone(),
            config_digest: config_digest(watcher)?,
            execution,
            profile: AdmittedProfile {
                id: watcher.profile.id.clone(),
                version: watcher.profile.version,
                digest: evidence.profile_digest,
            },
            threshold_policy: watcher.threshold_policy.clone(),
            protocol_version: evidence.protocol_version,
            granted_capabilities,
            conformance: evidence.conformance,
            admitted_at: Utc::now(),
            operator: OperatorIdentity {
                uid: Uid::effective().as_raw(),
                gid: Gid::effective().as_raw(),
                login_hint: std::env::var("LOGNAME")
                    .ok()
                    .filter(|value| value.len() <= 128),
            },
        })
    }

    /// Load a canonical admission lock.
    ///
    /// # Errors
    ///
    /// Returns a typed malformed-lock or filesystem diagnostic.
    pub fn load(&self, path: &Path) -> Result<AdmissionLock, AdmissionError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        if !file
            .metadata()
            .map_err(|source| io_error(path, source))?
            .is_file()
        {
            return Err(AdmissionError::Malformed {
                instance_id: "unknown".into(),
                message: "lock is not a regular file".into(),
            });
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_ADMISSION_LOCK_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(path, source))?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if length == 0 || length > MAX_ADMISSION_LOCK_BYTES {
            return Err(AdmissionError::Malformed {
                instance_id: "unknown".into(),
                message: format!(
                    "lock length {length} is outside 1..={MAX_ADMISSION_LOCK_BYTES} bytes"
                ),
            });
        }
        if bytes.last() != Some(&b'\n') || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n') {
            return Err(AdmissionError::Malformed {
                instance_id: "unknown".into(),
                message: "lock must be one LF-terminated canonical JSON document".into(),
            });
        }
        let lock: AdmissionLock =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).map_err(|error| {
                AdmissionError::Malformed {
                    instance_id: "unknown".into(),
                    message: error.to_string(),
                }
            })?;
        lock.validate_shape()?;
        let expected = canonical_json(&lock)?;
        if expected.as_slice() != &bytes[..bytes.len() - 1] {
            return Err(AdmissionError::Malformed {
                instance_id: lock.instance_id,
                message: "document is not canonical JSON".into(),
            });
        }
        Ok(lock)
    }

    /// Atomically activate a fully checked candidate lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock is malformed or cannot be durably written.
    pub fn activate(
        &self,
        directory: &Path,
        lock: &AdmissionLock,
    ) -> Result<PathBuf, AdmissionError> {
        lock.validate_shape()?;
        std::fs::create_dir_all(directory).map_err(|source| io_error(directory, source))?;
        let destination = directory.join(format!("{}.json", lock.instance_id));
        let mut temporary =
            NamedTempFile::new_in(directory).map_err(|source| io_error(directory, source))?;
        let bytes = canonical_json(lock)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ADMISSION_LOCK_BYTES {
            return Err(AdmissionError::Malformed {
                instance_id: lock.instance_id.clone(),
                message: format!("lock exceeds {MAX_ADMISSION_LOCK_BYTES} bytes"),
            });
        }
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.write_all(b"\n"))
            .and_then(|()| temporary.as_file_mut().sync_all())
            .map_err(|source| io_error(temporary.path(), source))?;
        temporary
            .persist(&destination)
            .map_err(|error| io_error(&destination, error.error))?;
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|source| io_error(directory, source))?;
        Ok(destination)
    }

    /// Recompute every locally verifiable binding fact. Nothing is refreshed.
    ///
    /// # Errors
    ///
    /// Returns distinct config, binary, profile, protocol, or malformed-lock
    /// diagnostics when the active binding has drifted.
    pub fn verify(
        &self,
        watcher: &WatcherConfig,
        lock: &AdmissionLock,
        compiled_profile_digest: &str,
        protocol_version: &str,
    ) -> Result<AdmissionVerification, AdmissionError> {
        let current_execution = ExecutionIdentity::resolve_command(&watcher.command)?;
        (*self).verify_opened_execution(
            watcher,
            lock,
            compiled_profile_digest,
            protocol_version,
            &current_execution,
        )
    }

    /// Verify an active lock against an identity computed from the exact
    /// descriptors that will be used for this launch.
    pub(crate) fn verify_opened_execution(
        self,
        watcher: &WatcherConfig,
        lock: &AdmissionLock,
        compiled_profile_digest: &str,
        protocol_version: &str,
        current_execution: &ExecutionIdentity,
    ) -> Result<AdmissionVerification, AdmissionError> {
        lock.validate_shape()?;
        if lock.instance_id != watcher.instance_id || lock.config_digest != config_digest(watcher)?
        {
            return Err(AdmissionError::ConfigDrift {
                instance_id: watcher.instance_id.clone(),
            });
        }
        if lock.profile.id != watcher.profile.id
            || lock.profile.version != watcher.profile.version
            || lock.profile.digest != compiled_profile_digest
            || lock.threshold_policy != watcher.threshold_policy
        {
            return Err(AdmissionError::ProfileDrift {
                instance_id: watcher.instance_id.clone(),
                message: "configured or compiled profile identity differs".into(),
            });
        }
        if lock.protocol_version != protocol_version {
            return Err(AdmissionError::ProtocolDrift {
                instance_id: watcher.instance_id.clone(),
            });
        }
        if !lock
            .granted_capabilities
            .is_subset(&watcher.capability_ceiling)
        {
            return Err(AdmissionError::Malformed {
                instance_id: watcher.instance_id.clone(),
                message: "granted capability escapes configured ceiling".into(),
            });
        }
        lock.execution.verify_matches(current_execution)?;
        let current_corpus =
            nq_protocol::verify_embedded_conformance_corpus().map_err(|error| {
                AdmissionError::ConformanceDrift {
                    instance_id: watcher.instance_id.clone(),
                    message: format!("embedded corpus no longer verifies: {error}"),
                }
            })?;
        if lock.conformance.tool_version != current_corpus.version.verifier_version
            || lock.conformance.protocol_corpus_digest
                != current_corpus.version.corpus_digest.to_string()
            || lock.conformance.protocol_fixtures_checked != current_corpus.fixtures_checked
            || lock.protocol_version != current_corpus.version.protocol_version
        {
            return Err(AdmissionError::ConformanceDrift {
                instance_id: watcher.instance_id.clone(),
                message: "embedded verifier version, corpus digest, fixture count, or protocol identity differs"
                    .into(),
            });
        }
        Ok(AdmissionVerification {
            binding_digest: self.binding_digest(lock)?,
            admitted_at: lock.admitted_at,
        })
    }
}

impl AdmissionLock {
    fn validate_shape(&self) -> Result<(), AdmissionError> {
        if self.schema != ADMISSION_SCHEMA {
            return Err(malformed(
                self,
                format!("expected schema {ADMISSION_SCHEMA}"),
            ));
        }
        if uuid::Uuid::parse_str(&self.admission_id).is_err()
            || self.instance_id.is_empty()
            || self.profile.id.is_empty()
            || self.profile.version == 0
            || !is_digest(&self.config_digest)
            || !is_digest(&self.profile.digest)
            || !is_digest(&self.execution.sha256)
            || self
                .execution
                .execution_account
                .as_ref()
                .is_none_or(|account| {
                    account.configured.is_empty()
                        || account.name.is_empty()
                        || account.uid == 0
                        || account.gid == 0
                        || (!cfg!(debug_assertions) && account.debug_same_identity)
                })
            || !is_digest(&self.conformance.protocol_corpus_digest)
            || self.conformance.protocol_fixtures_checked == 0
            || self
                .conformance
                .dry_report_digest
                .as_deref()
                .is_none_or(|digest| !is_digest(digest))
            || self.conformance.tool_version.is_empty()
            || self.conformance.tool_version.len() > 128
        {
            return Err(malformed(self, "invalid required identity"));
        }
        if let Some(policy) = &self.threshold_policy {
            policy
                .verify_digest()
                .map_err(|error| malformed(self, error))?;
            let policy_bytes = nq_protocol::canonical_json_bytes(&policy.value)
                .map_err(|error| malformed(self, error.to_string()))?;
            if policy.id.is_empty()
                || policy.id.len() > 255
                || policy.version.is_empty()
                || policy.version.len() > 255
                || policy_bytes.len() > 65_536
            {
                return Err(malformed(
                    self,
                    "threshold policy identity or canonical bytes exceed admission bounds",
                ));
            }
        }
        if !self.conformance.protocol_passed || !self.conformance.dry_collection_passed {
            return Err(malformed(
                self,
                "stored conformance result is not successful",
            ));
        }
        Ok(())
    }
}

fn validate_candidate_profile(
    watcher: &WatcherConfig,
    evidence: &CandidateEvidence,
    granted_capabilities: &BTreeSet<String>,
) -> Result<(), AdmissionError> {
    let profile = nq_profiles::resolve_profile(&watcher.profile.id, watcher.profile.version)
        .ok_or_else(|| AdmissionError::ProfileDrift {
            instance_id: watcher.instance_id.clone(),
            message: "configured profile is not in the compiled registry".into(),
        })?;
    let descriptor = profile.descriptor();
    let descriptor_digest = descriptor
        .digest()
        .map_err(|error| AdmissionError::ProfileDrift {
            instance_id: watcher.instance_id.clone(),
            message: format!("compiled descriptor is not canonical: {error}"),
        })?;
    if evidence.profile_digest != descriptor_digest.as_str() {
        return Err(AdmissionError::ProfileDrift {
            instance_id: watcher.instance_id.clone(),
            message: "candidate profile digest differs from the compiled descriptor".into(),
        });
    }
    if !watcher.subject.starts_with(&descriptor.subjects.namespace)
        || !descriptor
            .scope_kinds
            .iter()
            .any(|term| term.name == watcher.scope.kind)
        || !descriptor
            .vantages
            .iter()
            .any(|term| term.name == watcher.vantage.kind)
        || watcher.capability_ceiling.iter().any(|capability| {
            !descriptor
                .capabilities
                .iter()
                .any(|term| term.name == capability.as_str())
        })
    {
        return Err(AdmissionError::ProfileDrift {
            instance_id: watcher.instance_id.clone(),
            message:
                "candidate subject, scope, vantage, or capability is outside the compiled profile"
                    .into(),
        });
    }
    let context = nq_profiles::ValidationContext {
        instance_id: watcher.instance_id.clone(),
        request_subject: watcher.subject.clone(),
        scope: nq_profiles::ScopeGrant {
            kind: watcher.scope.kind.clone(),
            value: watcher.scope.value.clone(),
        },
        vantage: nq_profiles::VantageGrant {
            kind: watcher.vantage.kind.clone(),
            value: watcher.vantage.value.clone(),
        },
        granted_capabilities: granted_capabilities.clone(),
        received_at: Utc::now(),
        max_observations: u32::try_from(watcher.resources.max_observations)
            .unwrap_or(u32::MAX)
            .min(descriptor.limits.max_observations),
        max_future_skew: Duration::seconds(60),
    };
    profile
        .validate_binding(&context)
        .map_err(|refusal| AdmissionError::ProfileDrift {
            instance_id: watcher.instance_id.clone(),
            message: format!("profile binding refused: {}", refusal.message),
        })?;
    profile
        .validate_threshold_policy(&context, watcher.threshold_policy.as_ref())
        .map_err(|refusal| AdmissionError::ProfileDrift {
            instance_id: watcher.instance_id.clone(),
            message: format!("profile threshold policy refused: {}", refusal.message),
        })
}

fn config_digest(watcher: &WatcherConfig) -> Result<String, AdmissionError> {
    canonical_json(watcher).map(|bytes| digest_bytes(&bytes))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, AdmissionError> {
    let value = serde_json::to_value(value).map_err(|error| AdmissionError::Malformed {
        instance_id: "unknown".into(),
        message: error.to_string(),
    })?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output).map_err(|error| AdmissionError::Malformed {
        instance_id: "unknown".into(),
        message: error.to_string(),
    })?;
    Ok(output)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> serde_json::Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            output.push(b'{');
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_value(value, output)?;
            }
            output.push(b'}');
        }
        serde_json::Value::Array(array) => {
            output.push(b'[');
            for (index, value) in array.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        _ => serde_json::to_writer(output, value)?,
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn malformed(lock: &AdmissionLock, message: impl Into<String>) -> AdmissionError {
    AdmissionError::Malformed {
        instance_id: lock.instance_id.clone(),
        message: message.into(),
    }
}

fn io_error(path: &Path, source: io::Error) -> AdmissionError {
    AdmissionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use nq_profiles::ProfileModule;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use crate::config::{
        Carrier, CheckpointPolicy, CommandConfig, ProfileSelection, ResourceLimits, ScheduleConfig,
        ScopeConfig, VantageConfig,
    };

    use super::*;

    fn watcher(path: PathBuf, workdir: PathBuf) -> WatcherConfig {
        WatcherConfig {
            instance_id: "fixture.primary".into(),
            command: CommandConfig {
                executable: path,
                args: vec![],
                env: BTreeMap::new(),
                execution_account: nix::unistd::geteuid().as_raw().to_string(),
                allow_same_identity_in_debug: true,
                working_directory: workdir,
            },
            carrier: Carrier::Stdio,
            profile: ProfileSelection {
                id: "nq.conformance".into(),
                version: 1,
            },
            threshold_policy: None,
            subject: "conformance:local".into(),
            scope: ScopeConfig {
                kind: "fixture".into(),
                value: serde_json::json!({"id": "local", "nonce": "test"}),
            },
            vantage: VantageConfig {
                kind: "local".into(),
                value: serde_json::json!({}),
            },
            capability_ceiling: BTreeSet::new(),
            schedule: ScheduleConfig::default(),
            resources: ResourceLimits::default(),
            checkpoint_policy: CheckpointPolicy::Disabled,
        }
    }

    fn profile_digest() -> String {
        nq_profiles::resolve_profile("nq.conformance", 1)
            .expect("compiled conformance profile")
            .descriptor()
            .digest()
            .expect("canonical descriptor")
            .as_str()
            .to_owned()
    }

    fn candidate_evidence(watcher: &WatcherConfig) -> CandidateEvidence {
        let corpus = nq_protocol::verify_embedded_conformance_corpus().unwrap();
        CandidateEvidence {
            profile_digest: nq_profiles::resolve_profile(
                &watcher.profile.id,
                watcher.profile.version,
            )
            .expect("compiled profile")
            .descriptor()
            .digest()
            .expect("canonical profile descriptor")
            .as_str()
            .to_owned(),
            protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.into(),
            declared_capabilities: {
                let mut declared = watcher.capability_ceiling.clone();
                declared.insert("forbidden".into());
                declared
            },
            conformance: ConformanceReceipt {
                tool_version: corpus.version.verifier_version,
                protocol_passed: true,
                protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                protocol_fixtures_checked: corpus.fixtures_checked,
                dry_collection_passed: true,
                dry_report_digest: Some(format!("sha256:{}", "b".repeat(64))),
            },
        }
    }

    fn candidate(manager: AdmissionManager, watcher: &WatcherConfig) -> AdmissionLock {
        manager
            .candidate(watcher, candidate_evidence(watcher))
            .unwrap()
    }

    #[test]
    fn capability_declaration_can_only_narrow() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        fs::write(&helper, b"executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let watcher = watcher(helper, dir.path().to_path_buf());
        let lock = candidate(AdmissionManager, &watcher);
        assert!(lock.granted_capabilities.is_empty());
        let account = lock
            .execution
            .execution_account
            .as_ref()
            .expect("admission records helper account");
        assert_eq!(account.uid, nix::unistd::geteuid().as_raw());
        assert_eq!(account.gid, nix::unistd::getegid().as_raw());
    }

    #[test]
    fn atomic_lock_round_trip_is_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        fs::write(&helper, b"executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let watcher = watcher(helper, dir.path().to_path_buf());
        let manager = AdmissionManager;
        let lock = candidate(manager, &watcher);
        let admissions = dir.path().join("admissions");
        let path = manager.activate(&admissions, &lock).unwrap();
        let loaded = manager.load(&path).unwrap();
        assert_eq!(loaded, lock);
        manager
            .verify(
                &watcher,
                &loaded,
                &profile_digest(),
                nq_protocol::HELPER_PROTOCOL_VERSION,
            )
            .unwrap();
    }

    #[test]
    fn lock_loading_rejects_symlinks_and_oversize_documents() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular.json");
        fs::write(&regular, b"{}\n").unwrap();
        let link = dir.path().join("link.json");
        symlink(&regular, &link).unwrap();
        assert!(matches!(
            AdmissionManager.load(&link),
            Err(AdmissionError::Io { .. })
        ));

        let oversize = dir.path().join("oversize.json");
        fs::write(
            &oversize,
            vec![b' '; usize::try_from(MAX_ADMISSION_LOCK_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(matches!(
            AdmissionManager.load(&oversize),
            Err(AdmissionError::Malformed { .. })
        ));
    }

    #[test]
    fn config_and_binary_drift_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        fs::write(&helper, b"executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let mut watcher = watcher(helper.clone(), dir.path().to_path_buf());
        let manager = AdmissionManager;
        let lock = candidate(manager, &watcher);
        watcher.vantage.kind = "changed".into();
        assert!(matches!(
            manager.verify(
                &watcher,
                &lock,
                &profile_digest(),
                nq_protocol::HELPER_PROTOCOL_VERSION
            ),
            Err(AdmissionError::ConfigDrift { .. })
        ));
        watcher.vantage.kind = "local".into();
        fs::write(helper, b"different").unwrap();
        assert!(matches!(
            manager.verify(
                &watcher,
                &lock,
                &profile_digest(),
                nq_protocol::HELPER_PROTOCOL_VERSION
            ),
            Err(AdmissionError::Binary(_))
        ));
    }

    #[test]
    fn stored_execution_identity_cannot_redirect_the_configured_command() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        let replacement = dir.path().join("replacement");
        fs::write(&helper, b"configured").unwrap();
        fs::write(&replacement, b"different executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        let watcher = watcher(helper, dir.path().to_path_buf());
        let manager = AdmissionManager;
        let mut lock = candidate(manager, &watcher);
        let mut redirected = watcher.command.clone();
        redirected.executable = replacement;
        lock.execution = ExecutionIdentity::resolve_command(&redirected).unwrap();
        assert!(matches!(
            manager.verify(
                &watcher,
                &lock,
                &profile_digest(),
                nq_protocol::HELPER_PROTOCOL_VERSION
            ),
            Err(AdmissionError::Binary(_))
        ));
    }

    #[test]
    fn profile_owned_policy_validation_precedes_admission() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        fs::write(&helper, b"executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let mut watcher = watcher(helper, dir.path().to_path_buf());
        let value = serde_json::json!({
            "schema": "nq.fixture_threshold_policy.v1",
            "subject": "conformance:local",
            "expected": "ready",
        });
        watcher.threshold_policy = Some(nq_profiles::ThresholdPolicyInput {
            id: "nq.fixture.threshold_policy".to_owned(),
            version: "fixture-001".to_owned(),
            digest: nq_protocol::semantic_digest(&value).unwrap(),
            value,
        });
        assert!(matches!(
            AdmissionManager.candidate(&watcher, candidate_evidence(&watcher)),
            Err(AdmissionError::ProfileDrift { .. })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn operator_beta_policies_are_owner_validated_before_admission() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        fs::write(&helper, b"executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let service_subject = serde_json::json!({
            "schema": "constellation.operator_beta.service_subject.v1",
            "campaign_id": "constellation-operator-beta-2026",
            "fixture_run_id": "fixture-001",
            "target_machine_identity": "machine:fixture-001",
            "unit_name": "constellation-beta-http-fixture.service",
            "unit_file_sha256": format!("sha256:{}", "c".repeat(64)),
        });
        let bytes = nq_protocol::canonical_json_bytes(&service_subject).unwrap();
        let domain = "constellation/operator-beta/service-subject/v1";
        let mut hasher = Sha256::new();
        hasher.update(b"ag-ng\0digest\0v1\0");
        hasher.update((domain.len() as u128).to_be_bytes());
        hasher.update(domain.as_bytes());
        hasher.update((bytes.len() as u128).to_be_bytes());
        hasher.update(bytes);
        let subject = format!("sha256:{}", hex::encode(hasher.finalize()));

        let mut systemd = watcher(helper.clone(), dir.path().to_path_buf());
        systemd.instance_id = "operator-beta-systemd".into();
        systemd.profile = ProfileSelection {
            id: nq_profiles::systemd_unit::PROFILE_ID.into(),
            version: nq_profiles::systemd_unit::PROFILE_VERSION,
        };
        systemd.subject.clone_from(&subject);
        systemd.scope = ScopeConfig {
            kind: "systemd_unit".into(),
            value: serde_json::json!({
                "schema": "nq.operator_beta.systemd_unit_scope.v1",
                "subject_identity": subject,
                "target_machine_identity": "machine:fixture-001",
                "unit_name": "constellation-beta-http-fixture.service",
                "unit_file_sha256": format!("sha256:{}", "c".repeat(64)),
                "manager_interface": "org.freedesktop.systemd1",
                "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
            }),
        };
        systemd.vantage = VantageConfig {
            kind: "target_local".into(),
            value: serde_json::json!({}),
        };
        systemd.capability_ceiling = BTreeSet::from(["read_systemd_unit".into()]);
        let descriptor = nq_profiles::systemd_unit::MODULE.descriptor();
        let systemd_scope = serde_json::json!({
            "id": "nq.scope.systemd_unit",
            "version": descriptor.profile.version.to_string(),
            "digest": nq_protocol::semantic_digest(&serde_json::json!({
                "schema": "nq.diagnostic_scope.v1",
                "subject": systemd.subject,
                "scope": {
                    "kind": systemd.scope.kind,
                    "value": systemd.scope.value,
                },
                "profile": {
                    "id": descriptor.profile.id,
                    "version": descriptor.profile.version.to_string(),
                    "digest": descriptor.digest().unwrap().as_str(),
                },
            })).unwrap(),
        });
        let value = serde_json::json!({
            "schema": nq_profiles::systemd_unit::THRESHOLD_POLICY_SCHEMA,
            "fixture_run_id": "fixture-001",
            "service_subject": service_subject,
            "subject_identity": systemd.subject,
            "request_scope": systemd_scope,
            "expected_load_state": "loaded",
            "expected_active_state": "active",
            "expected_sub_state": "running",
            "expected_unit_file_state": "disabled",
        });
        systemd.threshold_policy = Some(nq_profiles::ThresholdPolicyInput {
            id: nq_profiles::systemd_unit::THRESHOLD_POLICY_ID.into(),
            version: "fixture-001".into(),
            digest: nq_protocol::semantic_digest(&value).unwrap(),
            value,
        });
        let systemd_lock = AdmissionManager
            .candidate(&systemd, candidate_evidence(&systemd))
            .unwrap();
        assert_eq!(systemd_lock.threshold_policy, systemd.threshold_policy);

        let mut wrong_descriptor = candidate_evidence(&systemd);
        wrong_descriptor.profile_digest = format!("sha256:{}", "e".repeat(64));
        assert!(matches!(
            AdmissionManager.candidate(&systemd, wrong_descriptor),
            Err(AdmissionError::ProfileDrift { .. })
        ));
        let mut wrong_subject = systemd.clone();
        let policy = wrong_subject.threshold_policy.as_mut().unwrap();
        policy.value["service_subject"]["target_machine_identity"] =
            serde_json::json!("machine:substituted");
        policy.digest = nq_protocol::semantic_digest(&policy.value).unwrap();
        assert!(matches!(
            AdmissionManager.candidate(&wrong_subject, candidate_evidence(&wrong_subject)),
            Err(AdmissionError::ProfileDrift { .. })
        ));

        let mut http = watcher(helper, dir.path().to_path_buf());
        http.instance_id = "operator-beta-http".into();
        http.profile = ProfileSelection {
            id: nq_profiles::http_endpoint::PROFILE_ID.into(),
            version: nq_profiles::http_endpoint::PROFILE_VERSION,
        };
        http.subject.clone_from(&subject);
        http.scope = ScopeConfig {
            kind: "http_endpoint".into(),
            value: serde_json::json!({
                "schema": "nq.operator_beta.http_endpoint_scope.v1",
                "subject_identity": subject,
                "controller_vantage_identity": "controller:fixture-001",
                "endpoint": "http://192.0.2.10:18080/healthz",
                "method": "GET",
                "redirect_policy": "refuse",
                "max_response_bytes": 1024,
            }),
        };
        http.vantage = VantageConfig {
            kind: "controller_http".into(),
            value: serde_json::json!({
                "controller_vantage_identity": "controller:fixture-001"
            }),
        };
        http.capability_ceiling = BTreeSet::from(["read_http_endpoint".into()]);
        let descriptor = nq_profiles::http_endpoint::MODULE.descriptor();
        let http_scope = serde_json::json!({
            "id": "nq.scope.http_endpoint",
            "version": descriptor.profile.version.to_string(),
            "digest": nq_protocol::semantic_digest(&serde_json::json!({
                "schema": "nq.diagnostic_scope.v1",
                "subject": http.subject,
                "scope": {"kind": http.scope.kind, "value": http.scope.value},
                "profile": {
                    "id": descriptor.profile.id,
                    "version": descriptor.profile.version.to_string(),
                    "digest": descriptor.digest().unwrap().as_str(),
                },
            })).unwrap(),
        });
        let value = serde_json::json!({
            "schema": nq_profiles::http_endpoint::THRESHOLD_POLICY_SCHEMA,
            "fixture_run_id": "fixture-001",
            "service_subject": service_subject,
            "subject_identity": http.subject,
            "request_scope": http_scope,
            "expected_status": 200,
            "expected_body_sha256": format!("sha256:{}", "d".repeat(64)),
        });
        http.threshold_policy = Some(nq_profiles::ThresholdPolicyInput {
            id: nq_profiles::http_endpoint::THRESHOLD_POLICY_ID.into(),
            version: "fixture-001".into(),
            digest: nq_protocol::semantic_digest(&value).unwrap(),
            value,
        });
        let http_lock = AdmissionManager
            .candidate(&http, candidate_evidence(&http))
            .unwrap();
        assert_eq!(http_lock.threshold_policy, http.threshold_policy);
    }

    #[test]
    fn corpus_drift_is_distinct_from_protocol_and_binary_drift() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        fs::write(&helper, b"executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let watcher = watcher(helper, dir.path().to_path_buf());
        let manager = AdmissionManager;
        let mut lock = candidate(manager, &watcher);
        lock.conformance.protocol_corpus_digest = format!("sha256:{}", "c".repeat(64));
        assert!(matches!(
            manager.verify(
                &watcher,
                &lock,
                &profile_digest(),
                nq_protocol::HELPER_PROTOCOL_VERSION
            ),
            Err(AdmissionError::ConformanceDrift { .. })
        ));
    }
}
