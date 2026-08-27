//! Exact, directed continuity between distinct passive-load watcher identities.
//!
//! The relation records a closed custody/generation transition.  It is not
//! watcher identity equivalence and grants no admission, sampling, recurrence,
//! acquisition, or diagnostic authority.

use std::path::PathBuf;

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{PassiveHostLoadProviderConfigV1, WatcherConfig};

/// Canonical relation schema.
pub const PASSIVE_WATCHER_SUCCESSION_SCHEMA_V1: &str = "nq.passive_watcher_succession.v1";

/// Exact passive selector custody beside one watcher configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveProviderCustodyV1 {
    /// Absolute path passed as the sole selector configuration argument.
    pub provider_config_path: PathBuf,
    /// Digest of the exact provider configuration bytes.
    pub provider_config_digest: String,
    /// Immutable sample-store generation selected by the provider.
    pub sample_store: PathBuf,
    /// Exact deployment ceiling on selected sample age.
    pub max_sample_age_ms: u64,
    /// Exact sampler implementation/profile.
    pub observer_profile: String,
    /// Exact sampler executable identity.
    pub observer_artifact_digest: String,
    /// Exact observer-generation/configuration identity.
    pub observer_config_digest: String,
    /// Exact sample issuer.
    pub producer_issuer: String,
    /// Exact bounded signing-key generation.
    pub producer_key_id: String,
    /// Exact signing public key.
    pub producer_public_key_hex: String,
    /// Exact effective `available_parallelism()` context.
    pub capacity_context_id: String,
}

/// Closed changes that occurred across one typed succession edge.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PassiveWatcherSuccessionDeltaV1 {
    /// A new watcher instance identity is mandatory.
    WatcherInstance,
    /// The sole passive selector configuration path changes.
    ProviderConfigPath,
    /// The exact provider configuration bytes change as a derived identity.
    ProviderConfigDigest,
    /// A new immutable sample-store generation is selected.
    SampleStoreGeneration,
    /// A new observer generation/configuration is selected.
    ObserverGeneration,
    /// An optional bounded signing-key generation changes as one pair.
    SigningKeyGeneration,
}

/// Directed, immutable, content-bound succession relation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveWatcherSuccessionV1 {
    /// Exact schema.
    pub schema: String,
    /// Content-derived relation identity.
    pub relation_id: String,
    /// Exact predecessor watcher configuration.
    pub predecessor: WatcherConfig,
    /// Exact successor watcher configuration.
    pub successor: WatcherConfig,
    /// Exact predecessor selector custody.
    pub predecessor_custody: PassiveProviderCustodyV1,
    /// Exact successor selector custody.
    pub successor_custody: PassiveProviderCustodyV1,
    /// Closed, derived delta projection.
    pub deltas: Vec<PassiveWatcherSuccessionDeltaV1>,
    /// Existing operator-boundary provenance; this does not itself grant authority.
    pub operator_occurrence_id: String,
    /// Record creation time, not an observation time.
    pub created_at_unix_ms: i64,
}

/// Succession refusal.
#[derive(Debug, Error)]
pub enum PassiveWatcherSuccessionError {
    /// The document is malformed or changes a forbidden semantic field.
    #[error("passive watcher succession refused: {0}")]
    Refused(String),
    /// Canonical identity calculation failed.
    #[error("passive watcher succession identity failed: {0}")]
    Identity(#[from] nq_protocol::CanonicalizationError),
}

impl PassiveWatcherSuccessionV1 {
    /// Construct and validate one exact directed edge.
    ///
    /// # Errors
    ///
    /// Refuses any field transition outside the closed custody/generation set
    /// or any malformed/content-identity input.
    pub fn new(
        predecessor: WatcherConfig,
        successor: WatcherConfig,
        predecessor_custody: PassiveProviderCustodyV1,
        successor_custody: PassiveProviderCustodyV1,
        operator_occurrence_id: String,
        created_at_unix_ms: i64,
    ) -> Result<Self, PassiveWatcherSuccessionError> {
        let deltas = validate_pair(
            &predecessor,
            &successor,
            &predecessor_custody,
            &successor_custody,
        )?;
        validate_token(&operator_occurrence_id, "operator occurrence")?;
        let preimage = (
            PASSIVE_WATCHER_SUCCESSION_SCHEMA_V1,
            &predecessor,
            &successor,
            &predecessor_custody,
            &successor_custody,
            &deltas,
            &operator_occurrence_id,
            created_at_unix_ms,
        );
        let relation_id = semantic_digest(&preimage)?.to_string();
        Ok(Self {
            schema: PASSIVE_WATCHER_SUCCESSION_SCHEMA_V1.into(),
            relation_id,
            predecessor,
            successor,
            predecessor_custody,
            successor_custody,
            deltas,
            operator_occurrence_id,
            created_at_unix_ms,
        })
    }

    /// Revalidate exact content identity and the closed field transition.
    ///
    /// # Errors
    ///
    /// Refuses substituted content, declared deltas, or semantic drift.
    pub fn validate(&self) -> Result<(), PassiveWatcherSuccessionError> {
        if self.schema != PASSIVE_WATCHER_SUCCESSION_SCHEMA_V1 {
            return refused("unsupported relation schema");
        }
        validate_token(&self.operator_occurrence_id, "operator occurrence")?;
        let expected_deltas = validate_pair(
            &self.predecessor,
            &self.successor,
            &self.predecessor_custody,
            &self.successor_custody,
        )?;
        if self.deltas != expected_deltas {
            return refused("declared delta set differs from exact field comparison");
        }
        let preimage = (
            self.schema.as_str(),
            &self.predecessor,
            &self.successor,
            &self.predecessor_custody,
            &self.successor_custody,
            &self.deltas,
            &self.operator_occurrence_id,
            self.created_at_unix_ms,
        );
        if semantic_digest(&preimage)?.as_str() != self.relation_id {
            return refused("relation identity differs from exact canonical content");
        }
        Ok(())
    }

    /// Exact predecessor watcher digest.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical digest construction fails.
    pub fn predecessor_digest(&self) -> Result<String, PassiveWatcherSuccessionError> {
        Ok(semantic_digest(&self.predecessor)?.to_string())
    }

    /// Exact successor watcher digest.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical digest construction fails.
    pub fn successor_digest(&self) -> Result<String, PassiveWatcherSuccessionError> {
        Ok(semantic_digest(&self.successor)?.to_string())
    }
}

fn validate_pair(
    predecessor: &WatcherConfig,
    successor: &WatcherConfig,
    predecessor_custody: &PassiveProviderCustodyV1,
    successor_custody: &PassiveProviderCustodyV1,
) -> Result<Vec<PassiveWatcherSuccessionDeltaV1>, PassiveWatcherSuccessionError> {
    let predecessor_passive = passive(predecessor)?;
    let successor_passive = passive(successor)?;
    validate_custody(predecessor, predecessor_passive, predecessor_custody)?;
    validate_custody(successor, successor_passive, successor_custody)?;

    if predecessor.instance_id == successor.instance_id {
        return refused("successor watcher identity must be distinct");
    }
    // Every field below is diagnostic/provider/temporal behavior and is
    // intentionally compared explicitly. New WatcherConfig fields make this
    // code fail to compile until their succession meaning is reviewed.
    if predecessor.carrier != successor.carrier
        || predecessor.profile != successor.profile
        || predecessor.subject != successor.subject
        || predecessor.scope != successor.scope
        || predecessor.vantage != successor.vantage
        || predecessor.capability_ceiling != successor.capability_ceiling
        || predecessor.schedule != successor.schedule
        || predecessor.resources != successor.resources
        || predecessor.checkpoint_policy != successor.checkpoint_policy
    {
        return refused("diagnostic, subject/vantage, cadence, or runtime semantics changed");
    }
    if predecessor.command.executable != successor.command.executable
        || predecessor.command.env != successor.command.env
        || predecessor.command.execution_account != successor.command.execution_account
        || predecessor.command.allow_same_identity_in_debug
            != successor.command.allow_same_identity_in_debug
        || predecessor.command.working_directory != successor.command.working_directory
    {
        return refused("provider executable or runtime semantics changed");
    }
    validate_selector_args(predecessor, predecessor_custody)?;
    validate_selector_args(successor, successor_custody)?;

    if predecessor_passive.schema != successor_passive.schema
        || predecessor_passive.max_sample_age_ms != successor_passive.max_sample_age_ms
        || predecessor_passive.observer_profile != successor_passive.observer_profile
        || predecessor_passive.observer_artifact_digest
            != successor_passive.observer_artifact_digest
        || predecessor_passive.producer_issuer != successor_passive.producer_issuer
        || predecessor_passive.capacity_context_id != successor_passive.capacity_context_id
    {
        return refused("passive provider, eligibility, or capacity semantics changed");
    }
    if predecessor_passive.observer_config_digest == successor_passive.observer_config_digest
        || predecessor_custody.sample_store == successor_custody.sample_store
        || predecessor_custody.provider_config_path == successor_custody.provider_config_path
        || predecessor_custody.provider_config_digest == successor_custody.provider_config_digest
    {
        return refused("successor must select a new exact generation and custody boundary");
    }

    let key_id_changed = predecessor_passive.producer_key_id != successor_passive.producer_key_id;
    let key_bytes_changed =
        predecessor_passive.producer_public_key_hex != successor_passive.producer_public_key_hex;
    if key_id_changed != key_bytes_changed {
        return refused("signing key identity and public bytes must rotate together");
    }

    let mut deltas = vec![
        PassiveWatcherSuccessionDeltaV1::WatcherInstance,
        PassiveWatcherSuccessionDeltaV1::ProviderConfigPath,
        PassiveWatcherSuccessionDeltaV1::ProviderConfigDigest,
        PassiveWatcherSuccessionDeltaV1::SampleStoreGeneration,
        PassiveWatcherSuccessionDeltaV1::ObserverGeneration,
    ];
    if key_id_changed {
        deltas.push(PassiveWatcherSuccessionDeltaV1::SigningKeyGeneration);
    }
    Ok(deltas)
}

fn passive(
    watcher: &WatcherConfig,
) -> Result<&PassiveHostLoadProviderConfigV1, PassiveWatcherSuccessionError> {
    watcher
        .passive_host_load_sample
        .as_ref()
        .ok_or_else(|| PassiveWatcherSuccessionError::Refused("watcher is not passive load".into()))
}

fn validate_custody(
    watcher: &WatcherConfig,
    passive: &PassiveHostLoadProviderConfigV1,
    custody: &PassiveProviderCustodyV1,
) -> Result<(), PassiveWatcherSuccessionError> {
    if !custody.provider_config_path.is_absolute() || !custody.sample_store.is_absolute() {
        return refused("provider configuration and sample store must be absolute");
    }
    Sha256Digest::parse(custody.provider_config_digest.clone()).map_err(|_| {
        PassiveWatcherSuccessionError::Refused("invalid provider config digest".into())
    })?;
    if passive.max_sample_age_ms != custody.max_sample_age_ms
        || passive.observer_profile != custody.observer_profile
        || passive.observer_artifact_digest != custody.observer_artifact_digest
        || passive.observer_config_digest != custody.observer_config_digest
        || passive.producer_issuer != custody.producer_issuer
        || passive.producer_key_id != custody.producer_key_id
        || passive.producer_public_key_hex != custody.producer_public_key_hex
        || passive.capacity_context_id != custody.capacity_context_id
    {
        return refused("provider custody does not exactly bind its watcher configuration");
    }
    validate_token(&watcher.instance_id, "watcher instance")
}

fn validate_selector_args(
    watcher: &WatcherConfig,
    custody: &PassiveProviderCustodyV1,
) -> Result<(), PassiveWatcherSuccessionError> {
    let expected = vec![
        "serve-stdio".to_owned(),
        custody.provider_config_path.to_string_lossy().into_owned(),
    ];
    if watcher.command.args != expected {
        return refused("passive selector argv is not exactly serve-stdio plus its custody path");
    }
    Ok(())
}

fn validate_token(value: &str, field: &str) -> Result<(), PassiveWatcherSuccessionError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|b| b.is_ascii_control()) {
        return refused(format!("{field} is not a bounded identity"));
    }
    Ok(())
}

fn refused<T>(message: impl Into<String>) -> Result<T, PassiveWatcherSuccessionError> {
    Err(PassiveWatcherSuccessionError::Refused(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn watcher(instance: &str, generation: char, key: char) -> WatcherConfig {
        serde_json::from_value(json!({
            "instance_id": instance,
            "command": {
                "executable": "/opt/nq/bin/nq-passive-load-helper",
                "args": ["serve-stdio", format!("/etc/nq/provider-{generation}.toml")],
                "env": {},
                "execution_account": "nq-passive-provider",
                "working_directory": "/var/empty"
            },
            "profile": {"id": "nq.host", "version": 1},
            "subject": "host:test",
            "scope": {"kind": "host", "value": {"id": "test"}},
            "vantage": {"kind": "local", "value": {}},
            "capability_ceiling": ["read_procfs", "read_system_info"],
            "passive_host_load_sample": {
                "schema": "nq.passive_host_load_provider_config.v1",
                "max_sample_age_ms": 30000,
                "observer_profile": "nq.host_load_passive_sampler.v1",
                "observer_artifact_digest": format!("sha256:{}", "a".repeat(64)),
                "observer_config_digest": format!("sha256:{}", generation.to_string().repeat(64)),
                "producer_issuer": "observer:test",
                "producer_key_id": format!("key:{key}"),
                "producer_public_key_hex": key.to_string().repeat(64),
                "capacity_context_id": format!("sha256:{}", "c".repeat(64))
            }
        }))
        .unwrap()
    }

    fn custody(watcher: &WatcherConfig, generation: char) -> PassiveProviderCustodyV1 {
        let passive = watcher.passive_host_load_sample.as_ref().unwrap();
        PassiveProviderCustodyV1 {
            provider_config_path: PathBuf::from(format!("/etc/nq/provider-{generation}.toml")),
            provider_config_digest: format!("sha256:{}", generation.to_string().repeat(64)),
            sample_store: PathBuf::from(format!("/var/lib/nq/samples-{generation}")),
            max_sample_age_ms: passive.max_sample_age_ms,
            observer_profile: passive.observer_profile.clone(),
            observer_artifact_digest: passive.observer_artifact_digest.clone(),
            observer_config_digest: passive.observer_config_digest.clone(),
            producer_issuer: passive.producer_issuer.clone(),
            producer_key_id: passive.producer_key_id.clone(),
            producer_public_key_hex: passive.producer_public_key_hex.clone(),
            capacity_context_id: passive.capacity_context_id.clone(),
        }
    }

    #[test]
    fn exact_generation_custody_succession_preserves_distinct_identity() {
        let predecessor = watcher("watcher-g1", '1', 'd');
        let successor = watcher("watcher-g2", '2', 'd');
        let relation = PassiveWatcherSuccessionV1::new(
            predecessor.clone(),
            successor.clone(),
            custody(&predecessor, '1'),
            custody(&successor, '2'),
            "operator:succession-1".into(),
            1_000,
        )
        .unwrap();
        relation.validate().unwrap();
        assert_ne!(
            relation.predecessor_digest().unwrap(),
            relation.successor_digest().unwrap()
        );
        assert_eq!(
            relation.deltas,
            vec![
                PassiveWatcherSuccessionDeltaV1::WatcherInstance,
                PassiveWatcherSuccessionDeltaV1::ProviderConfigPath,
                PassiveWatcherSuccessionDeltaV1::ProviderConfigDigest,
                PassiveWatcherSuccessionDeltaV1::SampleStoreGeneration,
                PassiveWatcherSuccessionDeltaV1::ObserverGeneration,
            ]
        );
    }

    #[test]
    fn bounded_key_rotation_is_one_closed_paired_delta() {
        let predecessor = watcher("watcher-g1", '1', 'd');
        let successor = watcher("watcher-g2", '2', 'e');
        let relation = PassiveWatcherSuccessionV1::new(
            predecessor.clone(),
            successor.clone(),
            custody(&predecessor, '1'),
            custody(&successor, '2'),
            "operator:key-rotation".into(),
            1_000,
        )
        .unwrap();
        assert!(
            relation
                .deltas
                .contains(&PassiveWatcherSuccessionDeltaV1::SigningKeyGeneration)
        );
    }

    #[test]
    fn semantic_subject_vantage_capacity_cadence_and_provider_drift_refuse() {
        let predecessor = watcher("watcher-g1", '1', 'd');
        for mut successor in [
            watcher("watcher-g2", '2', 'd'),
            watcher("watcher-g2", '2', 'd'),
            watcher("watcher-g2", '2', 'd'),
            watcher("watcher-g2", '2', 'd'),
            watcher("watcher-g2", '2', 'd'),
        ]
        .into_iter()
        .enumerate()
        {
            match successor.0 {
                0 => successor.1.subject = "host:other".into(),
                1 => successor.1.vantage.kind = "remote".into(),
                2 => {
                    successor
                        .1
                        .passive_host_load_sample
                        .as_mut()
                        .unwrap()
                        .capacity_context_id = format!("sha256:{}", "f".repeat(64));
                }
                3 => successor.1.schedule.interval_seconds += 1,
                4 => successor.1.command.executable = PathBuf::from("/opt/nq/bin/other"),
                _ => unreachable!(),
            }
            let successor_custody = custody(&successor.1, '2');
            assert!(
                PassiveWatcherSuccessionV1::new(
                    predecessor.clone(),
                    successor.1,
                    custody(&predecessor, '1'),
                    successor_custody,
                    "operator:drift".into(),
                    1_000,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn recomputed_outer_identity_cannot_hide_declared_delta_or_key_substitution() {
        let predecessor = watcher("watcher-g1", '1', 'd');
        let successor = watcher("watcher-g2", '2', 'd');
        let mut relation = PassiveWatcherSuccessionV1::new(
            predecessor.clone(),
            successor.clone(),
            custody(&predecessor, '1'),
            custody(&successor, '2'),
            "operator:substitution".into(),
            1_000,
        )
        .unwrap();
        relation
            .deltas
            .push(PassiveWatcherSuccessionDeltaV1::SigningKeyGeneration);
        assert!(relation.validate().is_err());

        let mut mismatched = successor;
        mismatched
            .passive_host_load_sample
            .as_mut()
            .unwrap()
            .producer_key_id = "key:e".into();
        assert!(
            PassiveWatcherSuccessionV1::new(
                predecessor.clone(),
                mismatched.clone(),
                custody(&predecessor, '1'),
                custody(&mismatched, '2'),
                "operator:mismatched-key".into(),
                1_000,
            )
            .is_err()
        );
    }
}
