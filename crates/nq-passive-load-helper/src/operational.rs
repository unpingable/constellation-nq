//! Finite operational continuity for the closed passive host-load observer.
//!
//! This module governs sampling infrastructure only. It has no NQ store,
//! recurrence, Nightshift, alerting, cron, or arbitrary-command surface.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use nix::fcntl::Flock;
use nix::libc;
use nq_protocol::{
    PassiveHostLoadSamplePayloadV1, Sha256Digest, SignedPassiveHostLoadSampleV1, SubjectBinding,
    canonical_json_bytes, semantic_digest, sha256_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{
    Error, ExpectedSampleIdentity, OBSERVER_PROFILE, SOURCE_BASIS, acquire_observer_lock,
    append_sample, available_parallelism, capacity_context, executable_digest, load_1m_token,
    load_samples, load_signing_key, require_absolute, require_binding, store_bytes,
    validate_identifier,
};

const POLICY_SCHEMA: &str = "nq.passive_load_operational_policy.v1";
const GENERATION_SPEC_SCHEMA: &str = "nq.passive_load_observer_generation_spec.v1";
const GENERATION_SCHEMA: &str = "nq.passive_load_observer_generation.v1";
const SAMPLING_SLOT_SCHEMA: &str = "nq.passive_load_sampling_slot.v1";
const GENERATION_EVENT_SCHEMA: &str = "nq.passive_load_observer_generation_event.v1";
const GENERATION_MANIFEST: &str = ".observer-generation.json";
const EVENT_DIRECTORY: &str = ".observer-events";
const MAX_OPERATIONAL_DOCUMENT_BYTES: usize = 262_144;

/// Closed observer startup behavior. Process startup itself has no sampling
/// meaning; this immutable selection does.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingStartupPolicyV1 {
    /// The first eligible slot is strictly after generation creation.
    WaitForNextSampleSlot,
    /// The slot open at generation creation is eligible.
    SampleCurrentSlot,
}

/// V1 retains every sample in its finite generation. Archive/delete semantics
/// are deliberately absent until independently qualified.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionModeV1 {
    /// No sample is deleted or rewritten.
    RetainAll,
}

/// Versioned deployment-owned safety envelope. It permits bounded generation
/// selections but creates no sampling or diagnostic authority.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalPolicyV1 {
    /// Exact closed schema.
    pub schema: String,
    /// Deployment-owned profile identity; it creates no authority.
    pub deployment_profile_ref: String,
    /// Inclusive lower bound for generation sampling intervals.
    pub min_sampling_interval_ms: u64,
    /// Inclusive upper bound for generation sampling intervals.
    pub max_sampling_interval_ms: u64,
    /// Finest scheduling precision the deployment claims to enforce.
    pub min_timer_granularity_ms: u64,
    /// Maximum ordinary wakeup delay used in coverage validation.
    pub max_scheduling_jitter_ms: u64,
    /// Maximum finite lifetime of any generation.
    pub max_generation_duration_ms: u64,
    /// Maximum finite sample count of any generation.
    pub max_generation_samples: u64,
    /// Maximum bytes one active generation store may occupy.
    pub max_active_store_bytes: u64,
    /// Minimum free filesystem bytes required before sampling.
    pub min_required_free_bytes: u64,
    /// Highest operator-selectable consecutive-failure pause threshold.
    pub max_consecutive_sample_failures: u16,
    /// Highest downstream sample eligibility horizon supported.
    pub max_sample_eligibility_age_ms: u64,
    /// Maximum overlap between predecessor and successor key windows.
    pub max_key_overlap_ms: u64,
    /// Closed deployment-permitted startup laws.
    pub allowed_startup_policies: BTreeSet<SamplingStartupPolicyV1>,
    /// Closed deployment-permitted retention laws.
    pub allowed_retention_modes: BTreeSet<RetentionModeV1>,
}

/// Operator-selected terms for one finite observer generation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverGenerationSpecV1 {
    /// Exact closed schema.
    pub schema: String,
    /// Existing explicit deployment/operator boundary occurrence.
    pub operator_occurrence_id: String,
    /// Exact predecessor generation for an explicit renewal, if any.
    pub previous_generation_id: Option<String>,
    /// Dedicated append-only store for this generation only.
    pub sample_store: PathBuf,
    /// Governed subject, scope, and local vantage.
    pub binding: SubjectBinding,
    /// Immutable UTC/unix sampling schedule anchor.
    pub sampling_anchor_unix_ms: i64,
    /// Fixed interval selected within deployment policy.
    pub sample_interval_ms: u64,
    /// Explicit first-slot startup behavior.
    pub startup_policy: SamplingStartupPolicyV1,
    /// Materialization occurrence time used by the startup law.
    pub created_at_unix_ms: i64,
    /// Inclusive generation activation boundary.
    pub not_before_unix_ms: i64,
    /// Exclusive generation expiration boundary.
    pub expires_at_unix_ms: i64,
    /// Finite sample-occurrence budget.
    pub max_samples: u64,
    /// Hard active-store byte ceiling.
    pub max_store_bytes: u64,
    /// Required free filesystem bytes before sampling.
    pub min_free_bytes: u64,
    /// Consecutive source-failure count that pauses the generation.
    pub failure_pause_threshold: u16,
    /// Exact closed retention selection.
    pub retention_mode: RetentionModeV1,
    /// Downstream eligibility horizon used by cadence validation.
    pub max_sample_eligibility_age_ms: u64,
    /// Exact software signing-key custody path.
    pub private_key_path: PathBuf,
    /// Deployment-owned sample producer issuer.
    pub producer_issuer: String,
    /// Exact signing-key generation identity.
    pub producer_key_id: String,
    /// Public verification bytes retained for historical verification.
    pub producer_public_key_hex: String,
    /// Inclusive key activation boundary.
    pub key_not_before_unix_ms: i64,
    /// Exclusive key retirement boundary for new samples.
    pub key_retire_at_unix_ms: i64,
    /// Pinned `available_parallelism()` and local-vantage context.
    pub capacity_context_id: Sha256Digest,
}

/// Immutable materialized generation. Its generation ID is the SHA-256 digest
/// of its exact canonical JSON bytes; those same bytes are hashed into every
/// produced sample as `observer_config_digest`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverGenerationV1 {
    /// Exact closed schema.
    pub schema: String,
    /// Content identity of the policy that constrained materialization.
    pub deployment_policy_id: Sha256Digest,
    /// Exact original policy snapshot; later policy cannot reinterpret it.
    pub deployment_policy: OperationalPolicyV1,
    /// Closed passive observer profile.
    pub observer_profile: String,
    /// Exact observer executable used to materialize and run the generation.
    pub observer_artifact_digest: Sha256Digest,
    /// Immutable bounded operator selection.
    pub spec: ObserverGenerationSpecV1,
}

/// Exact deterministic sampling opportunity, independent of NQ recurrence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingSlotV1 {
    pub schema: String,
    pub slot_id: Sha256Digest,
    pub generation_id: Sha256Digest,
    pub slot_index: u64,
    pub scheduled_for_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GenerationEventKindV1 {
    SampleCommitted,
    SampleRecovered,
    SampleFailed,
    CapacityContextDrift,
    StorageRefused,
    OperatorRetired,
    SigningKeyRevoked,
}

impl GenerationEventKindV1 {
    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CapacityContextDrift
                | Self::StorageRefused
                | Self::OperatorRetired
                | Self::SigningKeyRevoked
        )
    }

    const fn is_success(self) -> bool {
        matches!(self, Self::SampleCommitted | Self::SampleRecovered)
    }

    const fn is_failure(self) -> bool {
        matches!(self, Self::SampleFailed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationEventV1 {
    schema: String,
    event_id: Sha256Digest,
    generation_id: Sha256Digest,
    event_index: u64,
    occurred_at_unix_ms: i64,
    kind: GenerationEventKindV1,
    slot: Option<SamplingSlotV1>,
    sample_id: Option<Sha256Digest>,
    operation_id: Option<String>,
    reason_code: String,
}

/// One-shot sampling decision. None of these outcomes is an NQ acquisition or
/// a diagnostic judgment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum GenerationSampleActionV1 {
    Sampled {
        generation_id: Sha256Digest,
        slot: SamplingSlotV1,
        sample_id: Sha256Digest,
        sample_occurrence_id: String,
    },
    NotDue {
        generation_id: Sha256Digest,
        next_slot: SamplingSlotV1,
    },
    AlreadySampled {
        generation_id: Sha256Digest,
        slot: SamplingSlotV1,
        sample_id: Sha256Digest,
    },
    Exhausted {
        generation_id: Sha256Digest,
        reason: String,
    },
    Paused {
        generation_id: Sha256Digest,
        reason: String,
    },
}

/// Read-only projection over immutable generation, sample, and event custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverGenerationStatusV1 {
    pub schema: String,
    pub generation_id: Sha256Digest,
    pub original_deployment_policy_id: Sha256Digest,
    pub current_deployment_policy_id: Sha256Digest,
    pub current_policy_permits_generation: bool,
    pub state: String,
    pub state_reason: String,
    pub sampling_interval_ms: u64,
    pub sampling_anchor_unix_ms: i64,
    pub first_eligible_slot: u64,
    pub next_sampling_slot: Option<SamplingSlotV1>,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub samples_produced: u64,
    pub remaining_samples: u64,
    pub last_sample_id: Option<Sha256Digest>,
    pub last_sample_observed_at: Option<DateTime<Utc>>,
    pub last_failure_code: Option<String>,
    pub failure_streak: u16,
    pub missed_sampling_slots: u64,
    pub store_bytes: u64,
    pub max_store_bytes: u64,
    pub free_bytes: u64,
    pub min_free_bytes: u64,
    pub producer_issuer: String,
    pub producer_key_id: String,
    pub producer_public_key_digest: Sha256Digest,
    pub key_not_before_unix_ms: i64,
    pub key_retire_at_unix_ms: i64,
    pub capacity_context_id: Sha256Digest,
    pub retention_mode: RetentionModeV1,
    pub previous_generation_id: Option<String>,
}

struct GenerationSession {
    generation: ObserverGenerationV1,
    generation_id: Sha256Digest,
    current_policy_path: PathBuf,
    key: SigningKey,
    samples: Vec<SignedPassiveHostLoadSampleV1>,
    events: Vec<GenerationEventV1>,
    observer_run_id: String,
    next_sequence: u64,
    bytes_used: u64,
    _lock: Flock<File>,
}

/// Materialize one immutable generation after validating it against a current
/// deployment policy and, for renewal, its exact predecessor.
///
/// # Errors
///
/// Refuses malformed, unsafe, substituted, non-canonical, or out-of-policy
/// inputs and any failed durable output write.
pub fn materialize_generation(
    policy_path: &Path,
    spec_path: &Path,
    previous_generation_path: Option<&Path>,
    output_path: &Path,
) -> Result<ObserverGenerationV1, Error> {
    let (policy, _) = read_json::<OperationalPolicyV1>(policy_path)?;
    validate_policy(&policy)?;
    let (spec, _) = read_json::<ObserverGenerationSpecV1>(spec_path)?;
    let previous = previous_generation_path
        .map(load_generation)
        .transpose()?
        .map(|(generation, id, _)| (generation, id));
    validate_generation_spec(&spec, &policy, previous.as_ref())?;

    let key = load_signing_key(&spec.private_key_path)?;
    let configured_public = decode_public_key(&spec.producer_public_key_hex)?;
    if key.verifying_key().to_bytes() != configured_public {
        return Err(Error::Invalid(
            "generation signing key does not match configured public key".into(),
        ));
    }
    let context_id =
        semantic_digest(&capacity_context()?).map_err(|error| Error::Invalid(error.to_string()))?;
    if context_id != spec.capacity_context_id {
        return Err(Error::Invalid(
            "generation capacity/vantage context does not match this observer process".into(),
        ));
    }
    let policy_id = semantic_digest(&policy).map_err(|error| Error::Invalid(error.to_string()))?;
    let generation = ObserverGenerationV1 {
        schema: GENERATION_SCHEMA.into(),
        deployment_policy_id: policy_id,
        deployment_policy: policy,
        observer_profile: OBSERVER_PROFILE.into(),
        observer_artifact_digest: executable_digest()?,
        spec,
    };
    validate_generation(&generation, previous.as_ref())?;
    write_canonical_new(output_path, &generation, 0o440)?;
    Ok(generation)
}

/// Produce at most one sample for the exact currently eligible sampling slot.
///
/// # Errors
///
/// Refuses invalid generation custody, source/context drift, unsafe storage,
/// signing failure, or a failure to durably retain the resulting fact.
pub fn sample_once_generation(
    policy_path: &Path,
    generation_path: &Path,
) -> Result<GenerationSampleActionV1, Error> {
    let mut session = GenerationSession::open(policy_path, generation_path)?;
    session.tick_at(Utc::now().timestamp_millis())
}

/// Run the bounded long-lived observer until its immutable generation is
/// exhausted or paused. Missed slots are never backfilled.
///
/// # Errors
///
/// Refuses invalid generation/policy custody and returns the exact bounded
/// sampling or persistence failure that stopped the observer.
pub fn observe_generation(policy_path: &Path, generation_path: &Path) -> Result<(), Error> {
    let mut session = GenerationSession::open(policy_path, generation_path)?;
    loop {
        let now = Utc::now().timestamp_millis();
        match session.tick_at(now)? {
            GenerationSampleActionV1::Exhausted { .. }
            | GenerationSampleActionV1::Paused { .. } => return Ok(()),
            GenerationSampleActionV1::Sampled { slot, .. }
            | GenerationSampleActionV1::AlreadySampled { slot, .. } => {
                let next = slot.scheduled_for_unix_ms.saturating_add(
                    i64::try_from(session.generation.spec.sample_interval_ms).unwrap_or(i64::MAX),
                );
                sleep_until(next);
            }
            GenerationSampleActionV1::NotDue { next_slot, .. } => {
                sleep_until(next_slot.scheduled_for_unix_ms);
            }
        }
    }
}

/// Derive exact observer status without creating a sample or authority.
///
/// # Errors
///
/// Refuses malformed or substituted generation, sample, event, key, context,
/// or storage custody.
pub fn generation_status(
    policy_path: &Path,
    generation_path: &Path,
) -> Result<ObserverGenerationStatusV1, Error> {
    let (current_policy, _) = read_json::<OperationalPolicyV1>(policy_path)?;
    validate_policy(&current_policy)?;
    let current_policy_id =
        semantic_digest(&current_policy).map_err(|error| Error::Invalid(error.to_string()))?;
    let (generation, generation_id, _) = load_generation(generation_path)?;
    let policy_permits = validate_generation_spec(&generation.spec, &current_policy, None).is_ok();
    let public = VerifyingKey::from_bytes(&decode_public_key(
        &generation.spec.producer_public_key_hex,
    )?)
    .map_err(|_| Error::Invalid("generation public key is invalid".into()))?;
    let samples = load_generation_samples(&generation, &generation_id, &public)?;
    let events = load_events(&generation.spec.sample_store, &generation_id)?;
    project_status(
        &generation,
        &generation_id,
        current_policy_id,
        policy_permits,
        &samples,
        &events,
        Utc::now().timestamp_millis(),
    )
}

/// Append an explicit terminal administrative retirement. It stops future
/// samples but does not delete or reinterpret any sample.
///
/// # Errors
///
/// Refuses an invalid target, operation identity, conflicting replay, or
/// failed durable event append.
pub fn retire_generation(
    generation_path: &Path,
    operation_id: &str,
    reason: &str,
) -> Result<Sha256Digest, Error> {
    append_terminal_operator_event(
        generation_path,
        operation_id,
        reason,
        GenerationEventKindV1::OperatorRetired,
    )
}

/// Append a terminal key-revocation boundary. Historical public-key
/// verification remains available; no new sample may be accepted afterward.
///
/// # Errors
///
/// Refuses an invalid target, operation identity, conflicting replay, or
/// failed durable event append.
pub fn revoke_generation_key(
    generation_path: &Path,
    operation_id: &str,
    reason: &str,
) -> Result<Sha256Digest, Error> {
    append_terminal_operator_event(
        generation_path,
        operation_id,
        reason,
        GenerationEventKindV1::SigningKeyRevoked,
    )
}

fn append_terminal_operator_event(
    generation_path: &Path,
    operation_id: &str,
    reason: &str,
    kind: GenerationEventKindV1,
) -> Result<Sha256Digest, Error> {
    validate_identifier("operation_id", operation_id)?;
    validate_reason(reason)?;
    let (generation, generation_id, _) = load_generation(generation_path)?;
    let _lock = acquire_observer_lock(&generation.spec.sample_store)?;
    ensure_generation_store(&generation, &generation_id, generation_path)?;
    let mut events = load_events(&generation.spec.sample_store, &generation_id)?;
    if let Some(existing) = events
        .iter()
        .find(|event| event.kind == kind && event.operation_id.as_deref() == Some(operation_id))
    {
        return Ok(existing.event_id.clone());
    }
    if events
        .iter()
        .any(|event| event.operation_id.as_deref() == Some(operation_id))
    {
        return Err(Error::Invalid(
            "operator occurrence is already bound to a different generation event".into(),
        ));
    }
    let event = new_event(
        &generation_id,
        next_event_index(&events),
        Utc::now().timestamp_millis(),
        kind,
        None,
        None,
        Some(operation_id.to_owned()),
        reason.to_owned(),
    )?;
    append_event(&generation.spec.sample_store, &event)?;
    events.push(event.clone());
    Ok(event.event_id)
}

impl GenerationSession {
    fn open(policy_path: &Path, generation_path: &Path) -> Result<Self, Error> {
        let (current_policy, _) = read_json::<OperationalPolicyV1>(policy_path)?;
        validate_policy(&current_policy)?;
        let (generation, generation_id, generation_bytes) = load_generation(generation_path)?;
        validate_generation_spec(&generation.spec, &current_policy, None)?;
        let lock = acquire_observer_lock(&generation.spec.sample_store)?;
        ensure_generation_store(&generation, &generation_id, generation_path)?;

        let key = load_signing_key(&generation.spec.private_key_path)?;
        let public = key.verifying_key();
        if public.to_bytes() != decode_public_key(&generation.spec.producer_public_key_hex)? {
            return Err(Error::Invalid(
                "generation signing key no longer matches its immutable public key".into(),
            ));
        }
        if executable_digest()? != generation.observer_artifact_digest {
            return Err(Error::Invalid(
                "observer executable differs from the immutable generation".into(),
            ));
        }
        if sha256_bytes(&generation_bytes) != generation_id {
            return Err(Error::Invalid("generation byte identity changed".into()));
        }
        let samples = load_generation_samples(&generation, &generation_id, &public)?;
        let mut events = load_events(&generation.spec.sample_store, &generation_id)?;
        recover_sample_events(&generation, &generation_id, &samples, &mut events)?;
        validate_sample_slots(&generation, &generation_id, &samples)?;
        let next_sequence = samples
            .last()
            .map_or(1, |sample| sample.payload.sequence.saturating_add(1));
        let bytes_used = generation_store_bytes(&generation.spec.sample_store)?;
        Ok(Self {
            generation,
            generation_id,
            current_policy_path: policy_path.to_path_buf(),
            key,
            samples,
            events,
            observer_run_id: format!("observer-run:{}", Uuid::new_v4()),
            next_sequence,
            bytes_used,
            _lock: lock,
        })
    }

    fn tick_at(&mut self, now: i64) -> Result<GenerationSampleActionV1, Error> {
        let (current_policy, _) = read_json::<OperationalPolicyV1>(&self.current_policy_path)?;
        validate_policy(&current_policy)?;
        if let Err(error) = validate_generation_spec(&self.generation.spec, &current_policy, None) {
            return Ok(GenerationSampleActionV1::Paused {
                generation_id: self.generation_id.clone(),
                reason: format!("current deployment policy refuses generation: {error}"),
            });
        }
        let status = project_status(
            &self.generation,
            &self.generation_id,
            semantic_digest(&current_policy).map_err(|error| Error::Invalid(error.to_string()))?,
            true,
            &self.samples,
            &self.events,
            now,
        )?;
        if status.state == "exhausted" {
            return Ok(GenerationSampleActionV1::Exhausted {
                generation_id: self.generation_id.clone(),
                reason: status.state_reason,
            });
        }
        if status.state == "paused" || status.state == "retired" {
            return Ok(GenerationSampleActionV1::Paused {
                generation_id: self.generation_id.clone(),
                reason: status.state_reason,
            });
        }
        let Some(slot) = due_or_next_slot(&self.generation, &self.generation_id, now)? else {
            return Ok(GenerationSampleActionV1::Exhausted {
                generation_id: self.generation_id.clone(),
                reason: "generation expiration reached".into(),
            });
        };
        if now < slot.scheduled_for_unix_ms {
            return Ok(GenerationSampleActionV1::NotDue {
                generation_id: self.generation_id.clone(),
                next_slot: slot,
            });
        }
        if let Some(sample) = self.sample_for_slot(&slot)? {
            return Ok(GenerationSampleActionV1::AlreadySampled {
                generation_id: self.generation_id.clone(),
                slot,
                sample_id: sample.payload_digest.clone(),
            });
        }
        match self.try_sample(&slot, now) {
            Ok(sample) => Ok(GenerationSampleActionV1::Sampled {
                generation_id: self.generation_id.clone(),
                slot,
                sample_id: sample.payload_digest.clone(),
                sample_occurrence_id: sample.payload.sample_occurrence_id.clone(),
            }),
            Err(error) => {
                self.record_failure(&slot, now, &error)?;
                Err(error)
            }
        }
    }

    fn try_sample(
        &mut self,
        slot: &SamplingSlotV1,
        now: i64,
    ) -> Result<SignedPassiveHostLoadSampleV1, Error> {
        if now < self.generation.spec.not_before_unix_ms
            || now >= self.generation.spec.expires_at_unix_ms
            || now < self.generation.spec.key_not_before_unix_ms
            || now >= self.generation.spec.key_retire_at_unix_ms
        {
            return Err(Error::Exhausted(
                "generation or signing-key window is not active".into(),
            ));
        }
        let context_id = semantic_digest(&capacity_context()?)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        if context_id != self.generation.spec.capacity_context_id {
            return Err(Error::Invalid(
                "available_parallelism capacity/vantage context drifted".into(),
            ));
        }
        let free_bytes = free_bytes(&self.generation.spec.sample_store)?;
        if free_bytes < self.generation.spec.min_free_bytes {
            return Err(Error::Exhausted(
                "required free-space guard refuses sampling".into(),
            ));
        }
        let load_1m_token = load_1m_token()?;
        let logical_cpu_count = available_parallelism()?;
        let observed_at = DateTime::<Utc>::from_timestamp_millis(now)
            .ok_or_else(|| Error::Invalid("sampling time is outside datetime range".into()))?;
        let payload = PassiveHostLoadSamplePayloadV1 {
            schema: nq_protocol::PASSIVE_HOST_LOAD_SAMPLE_PAYLOAD_SCHEMA_V1.into(),
            sample_occurrence_id: format!("sample:{}", Uuid::new_v4()),
            binding: self.generation.spec.binding.clone(),
            observed_at,
            sequence: self.next_sequence,
            observer_run_id: self.observer_run_id.clone(),
            observer_profile: OBSERVER_PROFILE.into(),
            observer_artifact_digest: self.generation.observer_artifact_digest.clone(),
            observer_config_digest: self.generation_id.clone(),
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
            producer_issuer: self.generation.spec.producer_issuer.clone(),
            producer_key_id: self.generation.spec.producer_key_id.clone(),
            signature: hex::encode(signature.to_bytes()),
        };
        sample.validate_structure().map_err(Error::Invalid)?;
        let document =
            canonical_json_bytes(&sample).map_err(|error| Error::Invalid(error.to_string()))?;
        let projected = self
            .bytes_used
            .saturating_add(u64::try_from(document.len()).unwrap_or(u64::MAX));
        if projected > self.generation.spec.max_store_bytes {
            return Err(Error::Exhausted(
                "hard active-store byte bound would be exceeded".into(),
            ));
        }
        append_sample(&self.generation.spec.sample_store, &sample, &document)?;
        let event = new_event(
            &self.generation_id,
            next_event_index(&self.events),
            now,
            GenerationEventKindV1::SampleCommitted,
            Some(slot.clone()),
            Some(sample.payload_digest.clone()),
            None,
            "sample_committed".into(),
        )?;
        append_event(&self.generation.spec.sample_store, &event)?;
        self.events.push(event);
        self.bytes_used = generation_store_bytes(&self.generation.spec.sample_store)?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.samples.push(sample.clone());
        Ok(sample)
    }

    fn record_failure(
        &mut self,
        slot: &SamplingSlotV1,
        now: i64,
        error: &Error,
    ) -> Result<(), Error> {
        let text = error.to_string();
        let (kind, code) = if text.contains("capacity/vantage context drifted") {
            (
                GenerationEventKindV1::CapacityContextDrift,
                "capacity_context_drift",
            )
        } else if text.contains("store byte bound") || text.contains("free-space guard") {
            (
                GenerationEventKindV1::StorageRefused,
                "storage_guard_refused",
            )
        } else {
            (GenerationEventKindV1::SampleFailed, "sample_failed")
        };
        let event = new_event(
            &self.generation_id,
            next_event_index(&self.events),
            now,
            kind,
            Some(slot.clone()),
            None,
            None,
            code.into(),
        )?;
        append_event(&self.generation.spec.sample_store, &event)?;
        self.events.push(event);
        Ok(())
    }

    fn sample_for_slot(
        &self,
        slot: &SamplingSlotV1,
    ) -> Result<Option<&SignedPassiveHostLoadSampleV1>, Error> {
        let mut found = None;
        for sample in &self.samples {
            let sample_slot = sampling_slot_for_observed(
                &self.generation,
                &self.generation_id,
                sample.payload.observed_at.timestamp_millis(),
            )?;
            if sample_slot.slot_id == slot.slot_id {
                if found.is_some() {
                    return Err(Error::Invalid(
                        "more than one sample occupies one deterministic sampling slot".into(),
                    ));
                }
                found = Some(sample);
            }
        }
        Ok(found)
    }
}

fn validate_policy(policy: &OperationalPolicyV1) -> Result<(), Error> {
    if policy.schema != POLICY_SCHEMA
        || policy.deployment_profile_ref.is_empty()
        || policy.deployment_profile_ref.len() > 256
        || policy.min_sampling_interval_ms == 0
        || policy.min_sampling_interval_ms > policy.max_sampling_interval_ms
        || policy.min_timer_granularity_ms == 0
        || policy.min_sampling_interval_ms < policy.min_timer_granularity_ms
        || policy.max_generation_duration_ms == 0
        || policy.max_generation_samples == 0
        || policy.max_active_store_bytes < 4_096
        || policy.min_required_free_bytes == 0
        || policy.max_consecutive_sample_failures == 0
        || !(1..=300_000).contains(&policy.max_sample_eligibility_age_ms)
        || policy.allowed_startup_policies.is_empty()
        || policy.allowed_retention_modes != BTreeSet::from([RetentionModeV1::RetainAll])
        || policy
            .max_sampling_interval_ms
            .saturating_add(policy.max_scheduling_jitter_ms)
            >= policy.max_sample_eligibility_age_ms
    {
        return Err(Error::Invalid(
            "passive operational policy violates closed or relational safety bounds".into(),
        ));
    }
    Ok(())
}

fn validate_generation_spec(
    spec: &ObserverGenerationSpecV1,
    policy: &OperationalPolicyV1,
    previous: Option<&(ObserverGenerationV1, Sha256Digest)>,
) -> Result<(), Error> {
    validate_policy(policy)?;
    require_absolute("sample_store", &spec.sample_store)?;
    require_absolute("private_key_path", &spec.private_key_path)?;
    require_binding(&spec.binding)?;
    validate_identifier("operator_occurrence_id", &spec.operator_occurrence_id)?;
    validate_identifier("producer_issuer", &spec.producer_issuer)?;
    validate_identifier("producer_key_id", &spec.producer_key_id)?;
    decode_public_key(&spec.producer_public_key_hex)?;
    if spec.schema != GENERATION_SPEC_SCHEMA
        || spec.created_at_unix_ms < 0
        || spec.not_before_unix_ms < spec.created_at_unix_ms
        || spec.expires_at_unix_ms <= spec.not_before_unix_ms
        || spec.key_not_before_unix_ms > spec.not_before_unix_ms
        || spec.key_retire_at_unix_ms < spec.expires_at_unix_ms
        || spec.sampling_anchor_unix_ms < 0
        || spec.sample_interval_ms < policy.min_sampling_interval_ms
        || spec.sample_interval_ms > policy.max_sampling_interval_ms
        || spec.sample_interval_ms < policy.min_timer_granularity_ms
        || !policy
            .allowed_startup_policies
            .contains(&spec.startup_policy)
        || !policy
            .allowed_retention_modes
            .contains(&spec.retention_mode)
        || spec.max_samples == 0
        || spec.max_samples > policy.max_generation_samples
        || spec.max_store_bytes < 4_096
        || spec.max_store_bytes > policy.max_active_store_bytes
        || spec.min_free_bytes < policy.min_required_free_bytes
        || spec.failure_pause_threshold == 0
        || spec.failure_pause_threshold > policy.max_consecutive_sample_failures
        || spec.max_sample_eligibility_age_ms > policy.max_sample_eligibility_age_ms
        || spec
            .sample_interval_ms
            .saturating_add(policy.max_scheduling_jitter_ms)
            >= spec.max_sample_eligibility_age_ms
        || u64::try_from(spec.expires_at_unix_ms - spec.not_before_unix_ms).unwrap_or(u64::MAX)
            > policy.max_generation_duration_ms
    {
        return Err(Error::Invalid(
            "observer generation selection is outside deployment safety policy".into(),
        ));
    }
    match previous {
        None => {
            if let Some(previous_id) = &spec.previous_generation_id {
                Sha256Digest::parse(previous_id.clone()).map_err(|error| {
                    Error::Invalid(format!("previous generation identity is invalid: {error}"))
                })?;
            }
        }
        Some((prior, prior_id))
            if spec.previous_generation_id.as_deref() == Some(prior_id.as_str()) =>
        {
            if spec.sample_store == prior.spec.sample_store
                || spec.binding != prior.spec.binding
                || spec.capacity_context_id != prior.spec.capacity_context_id
                || spec.not_before_unix_ms < prior.spec.expires_at_unix_ms
                || spec.operator_occurrence_id == prior.spec.operator_occurrence_id
            {
                return Err(Error::Invalid(
                    "observer generation renewal changed semantic context, overlapped sampling, reused custody, or reused its operator occurrence".into(),
                ));
            }
            let key_overlap = prior
                .spec
                .key_retire_at_unix_ms
                .saturating_sub(spec.key_not_before_unix_ms);
            if u64::try_from(key_overlap.max(0)).unwrap_or(u64::MAX) > policy.max_key_overlap_ms {
                return Err(Error::Invalid(
                    "observer generation key overlap exceeds deployment policy".into(),
                ));
            }
        }
        Some(_) => {
            return Err(Error::Invalid(
                "observer generation predecessor binding is missing or substituted".into(),
            ));
        }
    }
    Ok(())
}

fn validate_generation(
    generation: &ObserverGenerationV1,
    previous: Option<&(ObserverGenerationV1, Sha256Digest)>,
) -> Result<(), Error> {
    if generation.schema != GENERATION_SCHEMA
        || generation.observer_profile != OBSERVER_PROFILE
        || generation.deployment_policy_id
            != semantic_digest(&generation.deployment_policy)
                .map_err(|error| Error::Invalid(error.to_string()))?
    {
        return Err(Error::Invalid(
            "observer generation identity or profile is invalid".into(),
        ));
    }
    validate_generation_spec(&generation.spec, &generation.deployment_policy, previous)
}

fn load_generation(path: &Path) -> Result<(ObserverGenerationV1, Sha256Digest, Vec<u8>), Error> {
    let (generation, bytes) = read_json::<ObserverGenerationV1>(path)?;
    validate_generation(&generation, None)?;
    let canonical =
        canonical_json_bytes(&generation).map_err(|error| Error::Invalid(error.to_string()))?;
    if bytes != canonical {
        return Err(Error::Invalid(
            "observer generation file must be exact canonical JSON bytes".into(),
        ));
    }
    let generation_id = sha256_bytes(&bytes);
    Ok((generation, generation_id, bytes))
}

fn load_generation_samples(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    public: &VerifyingKey,
) -> Result<Vec<SignedPassiveHostLoadSampleV1>, Error> {
    load_samples(
        &generation.spec.sample_store,
        public,
        &ExpectedSampleIdentity {
            observer_profile: OBSERVER_PROFILE,
            observer_artifact_digest: Some(&generation.observer_artifact_digest),
            observer_config_digest: Some(generation_id),
            producer_issuer: &generation.spec.producer_issuer,
            producer_key_id: &generation.spec.producer_key_id,
            capacity_context_id: &generation.spec.capacity_context_id,
            binding: Some(&generation.spec.binding),
        },
    )
}

fn ensure_generation_store(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    generation_path: &Path,
) -> Result<(), Error> {
    let manifest = generation.spec.sample_store.join(GENERATION_MANIFEST);
    let source = fs::read(generation_path)?;
    match fs::read(&manifest) {
        Ok(existing) if existing == source && sha256_bytes(&existing) == *generation_id => {}
        Ok(_) => {
            return Err(Error::Invalid(
                "sample store belongs to a different observer generation".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_bytes_new(&manifest, &source, 0o440)?;
        }
        Err(error) => return Err(Error::Io(error)),
    }
    let events = generation.spec.sample_store.join(EVENT_DIRECTORY);
    if !events.exists() {
        let mut builder = DirBuilder::new();
        builder.mode(0o750);
        builder.create(&events)?;
        File::open(&generation.spec.sample_store)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(&events)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o002 != 0 {
        return Err(Error::Invalid(
            "generation event store is not a non-world-writable real directory".into(),
        ));
    }
    Ok(())
}

fn load_events(
    store: &Path,
    generation_id: &Sha256Digest,
) -> Result<Vec<GenerationEventV1>, Error> {
    let directory = store.join(EVENT_DIRECTORY);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() || metadata.len() > 65_536 {
            return Err(Error::Invalid(
                "invalid observer generation event file".into(),
            ));
        }
        let bytes = fs::read(entry.path())?;
        let event: GenerationEventV1 = serde_json::from_slice(&bytes)?;
        validate_event(&event, generation_id)?;
        if canonical_json_bytes(&event).map_err(|error| Error::Invalid(error.to_string()))? != bytes
        {
            return Err(Error::Invalid(
                "generation event is not canonical JSON".into(),
            ));
        }
        let expected_name = event_filename(&event);
        if entry.file_name().to_string_lossy() != expected_name {
            return Err(Error::Invalid(
                "generation event filename identity mismatch".into(),
            ));
        }
        events.push(event);
    }
    events.sort_by_key(|event| event.event_index);
    for (index, event) in events.iter().enumerate() {
        if event.event_index != u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1) {
            return Err(Error::Invalid(
                "generation event sequence has a gap or rollback".into(),
            ));
        }
    }
    Ok(events)
}

fn validate_event(event: &GenerationEventV1, generation_id: &Sha256Digest) -> Result<(), Error> {
    if event.schema != GENERATION_EVENT_SCHEMA
        || event.generation_id != *generation_id
        || event.event_index == 0
        || event.occurred_at_unix_ms < 0
        || event.reason_code.is_empty()
        || event.reason_code.len() > 256
    {
        return Err(Error::Invalid(
            "generation event has invalid bounded fields".into(),
        ));
    }
    let expected = event_identity(
        &event.generation_id,
        event.event_index,
        event.occurred_at_unix_ms,
        event.kind,
        event.slot.as_ref(),
        event.sample_id.as_ref(),
        event.operation_id.as_deref(),
        &event.reason_code,
    )?;
    if event.event_id != expected {
        return Err(Error::Invalid(
            "generation event identity was substituted".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn new_event(
    generation_id: &Sha256Digest,
    event_index: u64,
    occurred_at_unix_ms: i64,
    kind: GenerationEventKindV1,
    slot: Option<SamplingSlotV1>,
    sample_id: Option<Sha256Digest>,
    operation_id: Option<String>,
    reason_code: String,
) -> Result<GenerationEventV1, Error> {
    let event_id = event_identity(
        generation_id,
        event_index,
        occurred_at_unix_ms,
        kind,
        slot.as_ref(),
        sample_id.as_ref(),
        operation_id.as_deref(),
        &reason_code,
    )?;
    Ok(GenerationEventV1 {
        schema: GENERATION_EVENT_SCHEMA.into(),
        event_id,
        generation_id: generation_id.clone(),
        event_index,
        occurred_at_unix_ms,
        kind,
        slot,
        sample_id,
        operation_id,
        reason_code,
    })
}

#[allow(clippy::too_many_arguments)]
fn event_identity(
    generation_id: &Sha256Digest,
    event_index: u64,
    occurred_at_unix_ms: i64,
    kind: GenerationEventKindV1,
    slot: Option<&SamplingSlotV1>,
    sample_id: Option<&Sha256Digest>,
    operation_id: Option<&str>,
    reason_code: &str,
) -> Result<Sha256Digest, Error> {
    semantic_digest(&json!({
        "schema": GENERATION_EVENT_SCHEMA,
        "generation_id": generation_id,
        "event_index": event_index,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "kind": kind,
        "slot": slot,
        "sample_id": sample_id,
        "operation_id": operation_id,
        "reason_code": reason_code,
    }))
    .map_err(|error| Error::Invalid(error.to_string()))
}

fn append_event(store: &Path, event: &GenerationEventV1) -> Result<(), Error> {
    let bytes = canonical_json_bytes(event).map_err(|error| Error::Invalid(error.to_string()))?;
    write_bytes_new(
        &store.join(EVENT_DIRECTORY).join(event_filename(event)),
        &bytes,
        0o440,
    )
}

fn event_filename(event: &GenerationEventV1) -> String {
    format!(
        "event-{:020}-{}.json",
        event.event_index,
        event.event_id.as_str().trim_start_matches("sha256:")
    )
}

fn next_event_index(events: &[GenerationEventV1]) -> u64 {
    events
        .last()
        .map_or(1, |event| event.event_index.saturating_add(1))
}

fn recover_sample_events(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    samples: &[SignedPassiveHostLoadSampleV1],
    events: &mut Vec<GenerationEventV1>,
) -> Result<(), Error> {
    let recorded: BTreeSet<_> = events
        .iter()
        .filter_map(|event| event.sample_id.as_ref().map(ToString::to_string))
        .collect();
    for sample in samples {
        if !recorded.contains(sample.payload_digest.as_str()) {
            let slot = sampling_slot_for_observed(
                generation,
                generation_id,
                sample.payload.observed_at.timestamp_millis(),
            )?;
            let event = new_event(
                generation_id,
                next_event_index(events),
                Utc::now().timestamp_millis(),
                GenerationEventKindV1::SampleRecovered,
                Some(slot),
                Some(sample.payload_digest.clone()),
                None,
                "durable_sample_recovered_after_interrupted_event_commit".into(),
            )?;
            append_event(&generation.spec.sample_store, &event)?;
            events.push(event);
        }
    }
    Ok(())
}

fn validate_sample_slots(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    samples: &[SignedPassiveHostLoadSampleV1],
) -> Result<(), Error> {
    let mut slots = BTreeSet::new();
    for sample in samples {
        let slot = sampling_slot_for_observed(
            generation,
            generation_id,
            sample.payload.observed_at.timestamp_millis(),
        )?;
        if !slots.insert(slot.slot_index) {
            return Err(Error::Invalid(
                "more than one immutable sample occupies one sampling slot".into(),
            ));
        }
    }
    Ok(())
}

fn due_or_next_slot(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    now: i64,
) -> Result<Option<SamplingSlotV1>, Error> {
    if now >= generation.spec.expires_at_unix_ms {
        return Ok(None);
    }
    let earliest = generation
        .spec
        .not_before_unix_ms
        .max(slot_time(generation, first_eligible_slot(generation)?)?);
    let target = now.max(earliest);
    let index = if target < generation.spec.sampling_anchor_unix_ms {
        first_eligible_slot(generation)?
    } else {
        u64::try_from(
            target.saturating_sub(generation.spec.sampling_anchor_unix_ms)
                / i64::try_from(generation.spec.sample_interval_ms).unwrap_or(i64::MAX),
        )
        .unwrap_or(u64::MAX)
        .max(first_eligible_slot(generation)?)
    };
    let scheduled = slot_time(generation, index)?;
    if scheduled >= generation.spec.expires_at_unix_ms {
        return Ok(None);
    }
    sampling_slot(generation_id, index, scheduled).map(Some)
}

fn sampling_slot_for_observed(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    observed_at: i64,
) -> Result<SamplingSlotV1, Error> {
    if observed_at < generation.spec.sampling_anchor_unix_ms {
        return Err(Error::Invalid(
            "sample predates its generation anchor".into(),
        ));
    }
    let interval = i64::try_from(generation.spec.sample_interval_ms).unwrap_or(i64::MAX);
    let index = u64::try_from(
        observed_at.saturating_sub(generation.spec.sampling_anchor_unix_ms) / interval,
    )
    .unwrap_or(u64::MAX);
    if index < first_eligible_slot(generation)? {
        return Err(Error::Invalid(
            "sample predates the first eligible generation slot".into(),
        ));
    }
    sampling_slot(generation_id, index, slot_time(generation, index)?)
}

fn sampling_slot(
    generation_id: &Sha256Digest,
    slot_index: u64,
    scheduled_for_unix_ms: i64,
) -> Result<SamplingSlotV1, Error> {
    let slot_id = semantic_digest(&json!({
        "schema": SAMPLING_SLOT_SCHEMA,
        "generation_id": generation_id,
        "slot_index": slot_index,
        "scheduled_for_unix_ms": scheduled_for_unix_ms,
    }))
    .map_err(|error| Error::Invalid(error.to_string()))?;
    Ok(SamplingSlotV1 {
        schema: SAMPLING_SLOT_SCHEMA.into(),
        slot_id,
        generation_id: generation_id.clone(),
        slot_index,
        scheduled_for_unix_ms,
    })
}

fn first_eligible_slot(generation: &ObserverGenerationV1) -> Result<u64, Error> {
    let current = slot_index_at(
        generation.spec.sampling_anchor_unix_ms,
        generation.spec.sample_interval_ms,
        generation.spec.created_at_unix_ms,
    )?;
    Ok(match generation.spec.startup_policy {
        SamplingStartupPolicyV1::SampleCurrentSlot => current,
        SamplingStartupPolicyV1::WaitForNextSampleSlot => current.saturating_add(1),
    })
}

fn slot_index_at(anchor: i64, interval_ms: u64, now: i64) -> Result<u64, Error> {
    if now < anchor {
        return Ok(0);
    }
    let interval = i64::try_from(interval_ms)
        .map_err(|_| Error::Invalid("sampling interval exceeds signed time range".into()))?;
    u64::try_from(now.saturating_sub(anchor) / interval)
        .map_err(|_| Error::Invalid("sampling slot index exceeds u64".into()))
}

fn slot_time(generation: &ObserverGenerationV1, index: u64) -> Result<i64, Error> {
    let offset = generation
        .spec
        .sample_interval_ms
        .checked_mul(index)
        .ok_or_else(|| Error::Invalid("sampling slot time overflow".into()))?;
    generation
        .spec
        .sampling_anchor_unix_ms
        .checked_add(
            i64::try_from(offset)
                .map_err(|_| Error::Invalid("sampling slot time exceeds i64".into()))?,
        )
        .ok_or_else(|| Error::Invalid("sampling slot time overflow".into()))
}

#[allow(clippy::too_many_lines)]
fn project_status(
    generation: &ObserverGenerationV1,
    generation_id: &Sha256Digest,
    current_policy_id: Sha256Digest,
    current_policy_permits_generation: bool,
    samples: &[SignedPassiveHostLoadSampleV1],
    events: &[GenerationEventV1],
    now: i64,
) -> Result<ObserverGenerationStatusV1, Error> {
    validate_sample_slots(generation, generation_id, samples)?;
    let mut failure_streak = 0_u16;
    let mut last_failure_code = None;
    for event in events {
        if event.kind.is_success() {
            failure_streak = 0;
        } else if event.kind.is_failure() {
            failure_streak = failure_streak.saturating_add(1);
            last_failure_code = Some(event.reason_code.clone());
        }
    }
    let terminal = events.iter().rev().find(|event| event.kind.is_terminal());
    let sample_count = u64::try_from(samples.len()).unwrap_or(u64::MAX);
    let (state, reason) = if let Some(event) = terminal {
        (
            if matches!(event.kind, GenerationEventKindV1::OperatorRetired) {
                "retired"
            } else {
                "paused"
            },
            event.reason_code.clone(),
        )
    } else if !current_policy_permits_generation {
        (
            "paused",
            "current deployment policy refuses future sampling".into(),
        )
    } else if failure_streak >= generation.spec.failure_pause_threshold {
        (
            "paused",
            "consecutive sample-failure threshold reached".into(),
        )
    } else if now >= generation.spec.expires_at_unix_ms {
        ("exhausted", "exclusive generation expiry reached".into())
    } else if sample_count >= generation.spec.max_samples {
        (
            "exhausted",
            "maximum generation sample count reached".into(),
        )
    } else if now < generation.spec.not_before_unix_ms {
        (
            "not_yet_active",
            "generation not-before boundary has not arrived".into(),
        )
    } else {
        (
            "active",
            "finite generation may evaluate an eligible sampling slot".into(),
        )
    };
    let next_sampling_slot = if state == "active" || state == "not_yet_active" {
        due_or_next_slot(generation, generation_id, now)?
    } else {
        None
    };
    let first = first_eligible_slot(generation)?;
    let current = slot_index_at(
        generation.spec.sampling_anchor_unix_ms,
        generation.spec.sample_interval_ms,
        now.max(generation.spec.not_before_unix_ms),
    )?;
    let sampled_slots: BTreeSet<_> = samples
        .iter()
        .map(|sample| {
            sampling_slot_for_observed(
                generation,
                generation_id,
                sample.payload.observed_at.timestamp_millis(),
            )
            .map(|slot| slot.slot_index)
        })
        .collect::<Result<_, _>>()?;
    let eligible_slots = current.saturating_sub(first).saturating_add(1);
    let missed_sampling_slots = eligible_slots.saturating_sub(
        u64::try_from(
            sampled_slots
                .iter()
                .filter(|slot| **slot <= current)
                .count(),
        )
        .unwrap_or(u64::MAX),
    );
    let public = decode_public_key(&generation.spec.producer_public_key_hex)?;
    Ok(ObserverGenerationStatusV1 {
        schema: "nq.passive_load_observer_generation_status.v1".into(),
        generation_id: generation_id.clone(),
        original_deployment_policy_id: generation.deployment_policy_id.clone(),
        current_deployment_policy_id: current_policy_id,
        current_policy_permits_generation,
        state: state.into(),
        state_reason: reason,
        sampling_interval_ms: generation.spec.sample_interval_ms,
        sampling_anchor_unix_ms: generation.spec.sampling_anchor_unix_ms,
        first_eligible_slot: first,
        next_sampling_slot,
        not_before_unix_ms: generation.spec.not_before_unix_ms,
        expires_at_unix_ms: generation.spec.expires_at_unix_ms,
        samples_produced: sample_count,
        remaining_samples: generation.spec.max_samples.saturating_sub(sample_count),
        last_sample_id: samples.last().map(|sample| sample.payload_digest.clone()),
        last_sample_observed_at: samples.last().map(|sample| sample.payload.observed_at),
        last_failure_code,
        failure_streak,
        missed_sampling_slots,
        store_bytes: generation_store_bytes(&generation.spec.sample_store)?,
        max_store_bytes: generation.spec.max_store_bytes,
        free_bytes: free_bytes(&generation.spec.sample_store)?,
        min_free_bytes: generation.spec.min_free_bytes,
        producer_issuer: generation.spec.producer_issuer.clone(),
        producer_key_id: generation.spec.producer_key_id.clone(),
        producer_public_key_digest: sha256_bytes(&public),
        key_not_before_unix_ms: generation.spec.key_not_before_unix_ms,
        key_retire_at_unix_ms: generation.spec.key_retire_at_unix_ms,
        capacity_context_id: generation.spec.capacity_context_id.clone(),
        retention_mode: generation.spec.retention_mode,
        previous_generation_id: generation.spec.previous_generation_id.clone(),
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<(T, Vec<u8>), Error> {
    require_absolute("operational document", path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_OPERATIONAL_DOCUMENT_BYTES as u64 {
        return Err(Error::Invalid(
            "operational document is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(MAX_OPERATIONAL_DOCUMENT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OPERATIONAL_DOCUMENT_BYTES {
        return Err(Error::Invalid("operational document exceeds bound".into()));
    }
    Ok((serde_json::from_slice(&bytes)?, bytes))
}

fn write_canonical_new<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), Error> {
    let bytes = canonical_json_bytes(value).map_err(|error| Error::Invalid(error.to_string()))?;
    write_bytes_new(path, &bytes, mode)
}

fn write_bytes_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    require_absolute("output", path)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("output has no parent".into()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
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

fn validate_reason(reason: &str) -> Result<(), Error> {
    if reason.is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "reason is not bounded printable text".into(),
        ));
    }
    Ok(())
}

fn free_bytes(path: &Path) -> Result<u64, Error> {
    let stats = nix::sys::statvfs::statvfs(path)
        .map_err(|error| Error::Io(std::io::Error::from_raw_os_error(error as i32)))?;
    Ok(stats
        .blocks_available()
        .saturating_mul(stats.fragment_size()))
}

fn generation_store_bytes(store: &Path) -> Result<u64, Error> {
    let mut total = store_bytes(store)?;
    let events = store.join(EVENT_DIRECTORY);
    if events.exists() {
        for entry in fs::read_dir(events)? {
            total = total.saturating_add(fs::symlink_metadata(entry?.path())?.len());
        }
    }
    Ok(total)
}

fn sleep_until(target_unix_ms: i64) {
    let remaining = target_unix_ms.saturating_sub(Utc::now().timestamp_millis());
    if let Ok(milliseconds) = u64::try_from(remaining.max(1)) {
        thread::sleep(StdDuration::from_millis(milliseconds));
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use ed25519_dalek::SigningKey;
    use nq_protocol::{
        ScopeBinding, ScopeKind, SubjectBinding, SubjectId, VantageBinding, VantageKind,
        canonical_json_bytes, semantic_digest, sha256_bytes,
    };
    use serde::Serialize;
    use serde_json::json;
    use tempfile::TempDir;

    use super::{
        GENERATION_SPEC_SCHEMA, GenerationEventKindV1, GenerationSampleActionV1,
        ObserverGenerationSpecV1, ObserverGenerationV1, OperationalPolicyV1, POLICY_SCHEMA,
        RetentionModeV1, SamplingStartupPolicyV1, decode_public_key, due_or_next_slot,
        executable_digest, generation_status, load_events, load_generation,
        load_generation_samples, materialize_generation, new_event, project_status,
        retire_generation, revoke_generation_key, sampling_slot,
    };
    use crate::capacity_context;

    struct Fixture {
        root: TempDir,
        policy_path: PathBuf,
        spec_path: PathBuf,
        generation_path: PathBuf,
        now: i64,
        binding: SubjectBinding,
        capacity_context_id: nq_protocol::Sha256Digest,
        public_hex: String,
    }

    impl Fixture {
        fn new(max_samples: u64) -> Self {
            let root = TempDir::new().expect("temporary root");
            let now = chrono::Utc::now().timestamp_millis();
            let policy_path = root.path().join("policy.json");
            let spec_path = root.path().join("spec.json");
            let generation_path = root.path().join("generation.json");
            let key_path = root.path().join("sample.key");
            let public_hex = write_key(&key_path, 41);
            let binding = SubjectBinding {
                subject: SubjectId::new("host:operational-fixture").unwrap(),
                scope: ScopeBinding {
                    kind: ScopeKind::new("host").unwrap(),
                    value: json!({"id": "operational-fixture"}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").unwrap(),
                    value: json!({}),
                },
            };
            let capacity_context_id = semantic_digest(&capacity_context().unwrap()).unwrap();
            write_json(&policy_path, &policy());
            let store = root.path().join("samples-g1");
            make_store(&store);
            let spec = generation_spec(
                "operator:g1",
                None,
                store,
                binding.clone(),
                now,
                max_samples,
                1_048_576,
                key_path.clone(),
                "fixture-key-g1",
                public_hex.clone(),
                capacity_context_id.clone(),
            );
            write_json(&spec_path, &spec);
            Self {
                root,
                policy_path,
                spec_path,
                generation_path,
                now,
                binding,
                capacity_context_id,
                public_hex,
            }
        }

        fn materialize(&self) -> ObserverGenerationV1 {
            materialize_generation(
                &self.policy_path,
                &self.spec_path,
                None,
                &self.generation_path,
            )
            .expect("materialize generation")
        }

        fn session(&self) -> super::GenerationSession {
            super::GenerationSession::open(&self.policy_path, &self.generation_path)
                .expect("open generation")
        }
    }

    fn policy() -> OperationalPolicyV1 {
        OperationalPolicyV1 {
            schema: POLICY_SCHEMA.into(),
            deployment_profile_ref: "fixture.passive-operational-policy:v1".into(),
            min_sampling_interval_ms: 100,
            max_sampling_interval_ms: 1_000,
            min_timer_granularity_ms: 10,
            max_scheduling_jitter_ms: 10,
            max_generation_duration_ms: 120_000,
            max_generation_samples: 16,
            max_active_store_bytes: 1_048_576,
            min_required_free_bytes: 1,
            max_consecutive_sample_failures: 3,
            max_sample_eligibility_age_ms: 5_000,
            max_key_overlap_ms: 2_000,
            allowed_startup_policies: [
                SamplingStartupPolicyV1::SampleCurrentSlot,
                SamplingStartupPolicyV1::WaitForNextSampleSlot,
            ]
            .into_iter()
            .collect(),
            allowed_retention_modes: [RetentionModeV1::RetainAll].into_iter().collect(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn generation_spec(
        operation: &str,
        previous_generation_id: Option<String>,
        store: PathBuf,
        binding: SubjectBinding,
        now: i64,
        max_samples: u64,
        max_store_bytes: u64,
        key_path: PathBuf,
        key_id: &str,
        public_hex: String,
        capacity_context_id: nq_protocol::Sha256Digest,
    ) -> ObserverGenerationSpecV1 {
        ObserverGenerationSpecV1 {
            schema: GENERATION_SPEC_SCHEMA.into(),
            operator_occurrence_id: operation.into(),
            previous_generation_id,
            sample_store: store,
            binding,
            sampling_anchor_unix_ms: now,
            sample_interval_ms: 100,
            startup_policy: SamplingStartupPolicyV1::SampleCurrentSlot,
            created_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            max_samples,
            max_store_bytes,
            min_free_bytes: 1,
            failure_pause_threshold: 2,
            retention_mode: RetentionModeV1::RetainAll,
            max_sample_eligibility_age_ms: 5_000,
            private_key_path: key_path,
            producer_issuer: "fixture.passive-observer".into(),
            producer_key_id: key_id.into(),
            producer_public_key_hex: public_hex,
            key_not_before_unix_ms: now,
            key_retire_at_unix_ms: now + 61_000,
            capacity_context_id,
        }
    }

    fn write_key(path: &Path, byte: u8) -> String {
        let secret = [byte; 32];
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&secret).unwrap();
        file.sync_all().unwrap();
        hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    fn write_json(path: &Path, value: &impl Serialize) {
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    fn make_store(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o750)).unwrap();
    }

    #[test]
    fn generation_is_finite_and_restart_cannot_reopen_exhaustion() {
        let fixture = Fixture::new(2);
        fixture.materialize();
        let mut session = fixture.session();
        let first = session.tick_at(fixture.now).unwrap();
        let second = session.tick_at(fixture.now + 100).unwrap();
        assert!(matches!(first, GenerationSampleActionV1::Sampled { .. }));
        assert!(matches!(second, GenerationSampleActionV1::Sampled { .. }));
        assert!(matches!(
            session.tick_at(fixture.now + 200).unwrap(),
            GenerationSampleActionV1::Exhausted { .. }
        ));
        drop(session);
        let mut reopened = fixture.session();
        assert!(matches!(
            reopened.tick_at(fixture.now + 300).unwrap(),
            GenerationSampleActionV1::Exhausted { .. }
        ));
        assert_eq!(
            generation_status(&fixture.policy_path, &fixture.generation_path)
                .unwrap()
                .samples_produced,
            2
        );
    }

    #[test]
    fn deterministic_slots_converge_and_missed_slots_remain_gaps() {
        let fixture = Fixture::new(4);
        let generation = fixture.materialize();
        let (_, id, _) = load_generation(&fixture.generation_path).unwrap();
        let slot = due_or_next_slot(&generation, &id, fixture.now)
            .unwrap()
            .unwrap();
        assert_eq!(slot, sampling_slot(&id, 0, fixture.now).unwrap());
        let mut session = fixture.session();
        let first = session.tick_at(fixture.now).unwrap();
        assert!(matches!(first, GenerationSampleActionV1::Sampled { .. }));
        assert!(matches!(
            session.tick_at(fixture.now).unwrap(),
            GenerationSampleActionV1::AlreadySampled { .. }
        ));
        assert!(matches!(
            session.tick_at(fixture.now + 300).unwrap(),
            GenerationSampleActionV1::Sampled { .. }
        ));
        let status = super::project_status(
            &session.generation,
            &session.generation_id,
            session.generation.deployment_policy_id.clone(),
            true,
            &session.samples,
            &session.events,
            fixture.now + 300,
        )
        .unwrap();
        assert_eq!(status.missed_sampling_slots, 2);
    }

    #[test]
    fn startup_wait_and_expiry_equality_are_explicit() {
        let fixture = Fixture::new(4);
        let mut spec: ObserverGenerationSpecV1 =
            serde_json::from_slice(&fs::read(&fixture.spec_path).unwrap()).unwrap();
        spec.startup_policy = SamplingStartupPolicyV1::WaitForNextSampleSlot;
        write_json(&fixture.spec_path, &spec);
        let generation = fixture.materialize();
        let (_, id, _) = load_generation(&fixture.generation_path).unwrap();
        let first = due_or_next_slot(&generation, &id, fixture.now)
            .unwrap()
            .unwrap();
        assert_eq!(first.slot_index, 1);
        let status = project_status(
            &generation,
            &id,
            generation.deployment_policy_id.clone(),
            true,
            &[],
            &[],
            generation.spec.expires_at_unix_ms,
        )
        .unwrap();
        assert_eq!(status.state, "exhausted");
    }

    #[test]
    fn policy_relations_refuse_impossible_coverage_and_tightening() {
        let fixture = Fixture::new(4);
        fixture.materialize();
        let mut tightened = policy();
        tightened.max_sampling_interval_ms = 50;
        tightened.min_sampling_interval_ms = 50;
        write_json(&fixture.policy_path, &tightened);
        let status = generation_status(&fixture.policy_path, &fixture.generation_path).unwrap();
        assert!(!status.current_policy_permits_generation);
        assert_eq!(status.state, "paused");

        let mut unsafe_policy = policy();
        unsafe_policy.max_sample_eligibility_age_ms = 100;
        write_json(&fixture.policy_path, &unsafe_policy);
        let error = generation_status(&fixture.policy_path, &fixture.generation_path).unwrap_err();
        assert!(error.to_string().contains("relational safety bounds"));
    }

    #[test]
    fn policy_broadening_does_not_enlarge_generation_budget() {
        let fixture = Fixture::new(1);
        fixture.materialize();
        let mut broad = policy();
        broad.max_generation_samples = 16;
        write_json(&fixture.policy_path, &broad);
        let mut session = fixture.session();
        assert!(matches!(
            session.tick_at(fixture.now).unwrap(),
            GenerationSampleActionV1::Sampled { .. }
        ));
        assert!(matches!(
            session.tick_at(fixture.now + 100).unwrap(),
            GenerationSampleActionV1::Exhausted { .. }
        ));
    }

    #[test]
    fn explicit_generation_renewal_rotates_key_without_rewriting_history() {
        let fixture = Fixture::new(2);
        let mut g1 = fixture.materialize();
        let mut s1 = fixture.session();
        assert!(matches!(
            s1.tick_at(fixture.now).unwrap(),
            GenerationSampleActionV1::Sampled { .. }
        ));
        let old_sample = s1.samples[0].clone();
        drop(s1);

        let (_, g1_id, _) = load_generation(&fixture.generation_path).unwrap();
        g1.spec.expires_at_unix_ms = fixture.now + 500;
        g1.spec.key_retire_at_unix_ms = fixture.now + 1_000;
        // Renewal uses the exact already materialized predecessor, so create a
        // second short predecessor fixture with those terms.
        let predecessor_path = fixture.root.path().join("predecessor-short.json");
        let mut predecessor_spec: ObserverGenerationSpecV1 =
            serde_json::from_slice(&fs::read(&fixture.spec_path).unwrap()).unwrap();
        predecessor_spec.expires_at_unix_ms = fixture.now + 500;
        predecessor_spec.key_retire_at_unix_ms = fixture.now + 1_000;
        let predecessor_spec_path = fixture.root.path().join("predecessor-spec.json");
        write_json(&predecessor_spec_path, &predecessor_spec);
        materialize_generation(
            &fixture.policy_path,
            &predecessor_spec_path,
            None,
            &predecessor_path,
        )
        .unwrap();
        let (_, predecessor_id, _) = load_generation(&predecessor_path).unwrap();

        let key2 = fixture.root.path().join("sample-g2.key");
        let public2 = write_key(&key2, 42);
        let store2 = fixture.root.path().join("samples-g2");
        make_store(&store2);
        let spec2 = generation_spec(
            "operator:g2",
            Some(predecessor_id.to_string()),
            store2,
            fixture.binding.clone(),
            fixture.now + 500,
            2,
            1_048_576,
            key2,
            "fixture-key-g2",
            public2,
            fixture.capacity_context_id.clone(),
        );
        let spec2_path = fixture.root.path().join("spec-g2.json");
        let generation2_path = fixture.root.path().join("generation-g2.json");
        write_json(&spec2_path, &spec2);
        materialize_generation(
            &fixture.policy_path,
            &spec2_path,
            Some(&predecessor_path),
            &generation2_path,
        )
        .unwrap();
        let mut s2 =
            super::GenerationSession::open(&fixture.policy_path, &generation2_path).unwrap();
        assert!(matches!(
            s2.tick_at(fixture.now + 500).unwrap(),
            GenerationSampleActionV1::Sampled { .. }
        ));
        assert_ne!(g1_id, s2.generation_id);
        assert_ne!(old_sample.producer_key_id, s2.samples[0].producer_key_id);

        let old_public = ed25519_dalek::VerifyingKey::from_bytes(
            &decode_public_key(&fixture.public_hex).unwrap(),
        )
        .unwrap();
        let old_samples = load_generation_samples(&g1, &g1_id, &old_public).unwrap();
        assert_eq!(old_samples[0].payload_digest, old_sample.payload_digest);
    }

    #[test]
    fn revocation_and_retirement_are_terminal_idempotent_events() {
        let fixture = Fixture::new(4);
        fixture.materialize();
        let first = revoke_generation_key(
            &fixture.generation_path,
            "operator:revoke",
            "bounded key revocation",
        )
        .unwrap();
        let duplicate = revoke_generation_key(
            &fixture.generation_path,
            "operator:revoke",
            "bounded key revocation",
        )
        .unwrap();
        assert_eq!(first, duplicate);
        let mut session = fixture.session();
        assert!(matches!(
            session.tick_at(fixture.now).unwrap(),
            GenerationSampleActionV1::Paused { .. }
        ));

        let other = Fixture::new(4);
        other.materialize();
        retire_generation(
            &other.generation_path,
            "operator:retire",
            "finite generation retired",
        )
        .unwrap();
        assert_eq!(
            generation_status(&other.policy_path, &other.generation_path)
                .unwrap()
                .state,
            "retired"
        );
    }

    #[test]
    fn failure_streak_and_storage_refusal_pause_without_deletion() {
        let fixture = Fixture::new(4);
        let generation = fixture.materialize();
        let (_, id, _) = load_generation(&fixture.generation_path).unwrap();
        let slot = sampling_slot(&id, 0, fixture.now).unwrap();
        let mut events = Vec::new();
        for index in 1..=2 {
            let event = new_event(
                &id,
                index,
                fixture.now + i64::try_from(index).unwrap(),
                GenerationEventKindV1::SampleFailed,
                Some(slot.clone()),
                None,
                None,
                "sample_source_failed".into(),
            )
            .unwrap();
            events.push(event);
        }
        let status = project_status(
            &generation,
            &id,
            generation.deployment_policy_id.clone(),
            true,
            &[],
            &events,
            fixture.now + 10,
        )
        .unwrap();
        assert_eq!(status.state, "paused");
        assert_eq!(status.failure_streak, 2);

        let constrained = Fixture::new(4);
        let mut spec: ObserverGenerationSpecV1 =
            serde_json::from_slice(&fs::read(&constrained.spec_path).unwrap()).unwrap();
        spec.max_store_bytes = 4_096;
        write_json(&constrained.spec_path, &spec);
        constrained.materialize();
        let mut session = constrained.session();
        let _ = session.tick_at(constrained.now);
        let status =
            generation_status(&constrained.policy_path, &constrained.generation_path).unwrap();
        assert!(status.samples_produced <= 1);
        assert!(status.store_bytes <= 8_192);
    }

    #[test]
    fn context_vantage_config_and_predecessor_substitution_refuse() {
        let fixture = Fixture::new(4);
        let mut spec: ObserverGenerationSpecV1 =
            serde_json::from_slice(&fs::read(&fixture.spec_path).unwrap()).unwrap();
        spec.binding.vantage.value = json!({"namespace": "other"});
        write_json(&fixture.spec_path, &spec);
        assert!(
            materialize_generation(
                &fixture.policy_path,
                &fixture.spec_path,
                None,
                &fixture.generation_path
            )
            .is_err()
        );

        let other = Fixture::new(4);
        let mut spec: ObserverGenerationSpecV1 =
            serde_json::from_slice(&fs::read(&other.spec_path).unwrap()).unwrap();
        spec.capacity_context_id = sha256_bytes(b"wrong-context");
        write_json(&other.spec_path, &spec);
        assert!(
            materialize_generation(
                &other.policy_path,
                &other.spec_path,
                None,
                &other.generation_path
            )
            .is_err()
        );
    }

    #[test]
    fn concurrent_start_has_one_writer_and_open_creates_no_sample() {
        let fixture = Fixture::new(4);
        fixture.materialize();
        let owner = fixture.session();
        assert!(owner.samples.is_empty());
        let Err(error) =
            super::GenerationSession::open(&fixture.policy_path, &fixture.generation_path)
        else {
            panic!("second observer unexpectedly acquired the generation");
        };
        assert!(
            error
                .to_string()
                .contains("another observer owns this store")
        );
    }

    #[test]
    fn malformed_partial_sample_never_becomes_selectable() {
        let fixture = Fixture::new(4);
        let generation = fixture.materialize();
        let (_, id, _) = load_generation(&fixture.generation_path).unwrap();
        fs::write(
            generation
                .spec
                .sample_store
                .join(format!("sample-{:020}-{}.json", 1, "0".repeat(64))),
            b"{",
        )
        .unwrap();
        let public = ed25519_dalek::VerifyingKey::from_bytes(
            &decode_public_key(&fixture.public_hex).unwrap(),
        )
        .unwrap();
        assert!(load_generation_samples(&generation, &id, &public).is_err());
    }

    #[test]
    fn event_substitution_and_sequence_gap_refuse() {
        let fixture = Fixture::new(4);
        fixture.materialize();
        retire_generation(
            &fixture.generation_path,
            "operator:retire",
            "retire exact generation",
        )
        .unwrap();
        let (_, id, _) = load_generation(&fixture.generation_path).unwrap();
        let mut events = load_events(&fixture.root.path().join("samples-g1"), &id).unwrap();
        events[0].reason_code = "substituted".into();
        assert!(super::validate_event(&events[0], &id).is_err());
    }

    #[test]
    fn executable_and_generation_bytes_are_content_bound() {
        let fixture = Fixture::new(4);
        let generation = fixture.materialize();
        assert_eq!(
            generation.observer_artifact_digest,
            executable_digest().unwrap()
        );
        let bytes = fs::read(&fixture.generation_path).unwrap();
        assert_eq!(bytes, canonical_json_bytes(&generation).unwrap());
        assert_eq!(
            sha256_bytes(&bytes),
            load_generation(&fixture.generation_path).unwrap().1
        );
    }

    #[test]
    fn success_event_recovery_preserves_sample_and_resets_failure_projection() {
        let fixture = Fixture::new(2);
        fixture.materialize();
        let mut session = fixture.session();
        session.tick_at(fixture.now).unwrap();
        let sample_id = session.samples[0].payload_digest.clone();
        let event_path = fixture.root.path().join("samples-g1/.observer-events");
        for entry in fs::read_dir(&event_path).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        drop(session);
        let reopened = fixture.session();
        assert_eq!(reopened.samples[0].payload_digest, sample_id);
        assert!(
            reopened
                .events
                .iter()
                .any(|event| event.kind == GenerationEventKindV1::SampleRecovered)
        );
    }

    #[test]
    fn no_module_dependency_can_create_recurrence_or_nightshift_authority() {
        let source = include_str!("operational.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["nq_store::", "nightshiftd::", "std::process::Command"] {
            assert!(!production.contains(forbidden));
        }
    }
}
