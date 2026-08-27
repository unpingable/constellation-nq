//! Finite passive-office delegation and transactional activation.
//!
//! This is deliberately a narrow local append-only ledger. It can delegate a
//! bounded number of ordinary observer generations and recurrence enrollments;
//! it cannot create samples, acquisitions, Nightshift cycles, or another
//! operating grant. A service-manager wakeup consults the durable activation
//! projection and is inert until the exact office bundle is armed.

#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value
)]

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use nq_core::PassiveWatcherSuccessionV1;
use nq_passive_load_helper::{ObserverGenerationV1, OperationalPolicyV1};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest};
use nq_store::recurrence::{RecurrenceEnrollmentV1, RecurringOfficePolicyV1};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const OPERATING_GRANT_SPEC_SCHEMA_V1: &str = "nq.passive_load_operating_grant_spec.v1";
pub const OPERATING_GRANT_SCHEMA_V1: &str = "nq.passive_load_operating_grant.v1";
pub const OPERATING_EVENT_SCHEMA_V1: &str = "nq.passive_load_operating_event.v1";
pub const CHILD_ISSUANCE_SCHEMA_V1: &str = "nq.passive_load_child_grant_issuance.v1";
pub const OFFICE_ACTIVATION_SPEC_SCHEMA_V1: &str = "nq.passive_load_office_activation_spec.v1";
pub const OFFICE_ACTIVATION_SCHEMA_V1: &str = "nq.passive_load_office_activation.v1";
pub const SUCCESSOR_HANDOFF_SPEC_SCHEMA_V1: &str = "nq.passive_load_successor_handoff_spec.v1";
pub const SUCCESSOR_HANDOFF_SCHEMA_V1: &str = "nq.passive_load_successor_handoff.v1";
const MAX_LEDGER_DOCUMENT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingGrantSpecV1 {
    pub schema: String,
    pub operator_occurrence_id: String,
    pub watcher_instance_id: String,
    pub watcher_semantic_digest: String,
    pub passive_provider_boundary_id: String,
    pub observer_profile: String,
    pub observer_artifact_digest: String,
    pub sample_schema: String,
    pub subject_binding_digest: String,
    pub capacity_context_id: String,
    pub sample_eligibility_profile_id: String,
    pub coordination_domain_id: String,
    pub sample_interval_ms: u64,
    pub acquisition_interval_ms: u64,
    pub recurrence_missed_slot_policy: String,
    pub recurrence_startup_policy: String,
    pub allowed_signing_key_ids: BTreeSet<String>,
    /// Exact historical G immediately preceding this H, if continuity already exists.
    /// It contributes no child or sampling authority inside H.
    pub observer_predecessor_generation_id: Option<String>,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub max_observer_generations: u16,
    pub max_recurrence_enrollments: u16,
    pub max_watcher_succession_edges: u16,
    pub allowed_watcher_succession_relation_ids: BTreeSet<String>,
    pub observer_generation_duration_ms: u64,
    pub observer_generation_max_samples: u64,
    pub recurrence_enrollment_duration_ms: u64,
    pub recurrence_enrollment_max_occurrences: u32,
    pub max_aggregate_samples: u64,
    pub max_aggregate_acquisitions: u64,
    pub observer_renewal_lead_ms: u64,
    pub recurrence_renewal_lead_slots: u16,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingGrantV1 {
    pub schema: String,
    pub grant_id: String,
    pub spec: OperatingGrantSpecV1,
    pub observer_deployment_policy_id: String,
    pub observer_deployment_policy: OperationalPolicyV1,
    pub recurrence_deployment_policy_id: String,
    pub recurrence_deployment_policy: RecurringOfficePolicyV1,
    pub created_at_unix_ms: i64,
    pub issuer: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildGrantKindV1 {
    ObserverGeneration,
    RecurrenceEnrollment,
}

impl ChildGrantKindV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::ObserverGeneration => "observer_generation",
            Self::RecurrenceEnrollment => "recurrence_enrollment",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildGrantIssuanceV1 {
    pub schema: String,
    pub issuance_id: String,
    pub grant_id: String,
    pub kind: ChildGrantKindV1,
    pub child_id: String,
    pub predecessor_child_id: Option<String>,
    pub starts_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub finite_authority_count: u64,
    pub semantic_snapshot_digest: String,
    pub exact_child_digest: String,
    pub operation_id: String,
    pub issued_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeActivationSpecV1 {
    pub schema: String,
    pub operation_id: String,
    pub grant_id: String,
    pub generation_id: String,
    pub generation_path: PathBuf,
    pub enrollment_id: String,
    pub watcher_instance_id: String,
    pub watcher_semantic_digest: String,
    pub admission_id: String,
    pub genesis_acquisition_id: String,
    pub provider_config_path: PathBuf,
    pub provider_config_digest: String,
    pub passive_provider_boundary_id: String,
    pub sample_store: PathBuf,
    pub capacity_context_id: String,
    /// Exact installed service-manager unit whose bytes invoke the gated tick.
    pub service_manager_deployment_path: PathBuf,
    pub service_manager_deployment_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeActivationV1 {
    pub schema: String,
    pub activation_id: String,
    pub spec: OfficeActivationSpecV1,
    pub staged_at_unix_ms: i64,
}

/// One pre-reviewed, finite procedure delegation between exact H children.
/// The object contains identities and validation inputs only. It is not an
/// admission, sample, acquisition, recurrence, or diagnostic grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorHandoffSpecV1 {
    pub schema: String,
    pub operation_id: String,
    pub grant_id: String,
    pub succession_relation_id: String,
    pub predecessor_activation_id: String,
    pub next_generation_id: String,
    pub next_generation_path: PathBuf,
    pub successor_watcher_instance_id: String,
    pub successor_watcher_semantic_digest: String,
    pub expected_admission_id: String,
    pub genesis_acquisition_id: String,
    pub expected_instance_id_sha256: String,
    pub origin_helper_path: PathBuf,
    pub origin_helper_sha256: String,
    pub origin_helper_account: String,
    pub origin_helper_public_key_path: PathBuf,
    pub next_enrollment_id: String,
    pub next_activation_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorHandoffV1 {
    pub schema: String,
    pub handoff_id: String,
    pub spec: SuccessorHandoffSpecV1,
    pub staged_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessorHandoffStateV1 {
    Staged,
    WaitingForSample,
    SampleReady,
    AdmissionStarted,
    AdmissionCompleted,
    GenesisStarted,
    GenesisCompleted,
    Validated,
    Armed,
    AdmissionRefused,
    GenesisRefused,
    OutcomeUnknown,
    Expired,
}

impl SuccessorHandoffStateV1 {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Armed
                | Self::AdmissionRefused
                | Self::GenesisRefused
                | Self::OutcomeUnknown
                | Self::Expired
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorHandoffStatusV1 {
    pub schema: String,
    pub handoff_id: String,
    pub grant_id: String,
    pub relation_id: String,
    pub next_generation_id: String,
    pub successor_watcher_instance_id: String,
    pub expected_admission_id: String,
    pub genesis_acquisition_id: String,
    pub next_enrollment_id: String,
    pub next_activation_id: String,
    pub state: SuccessorHandoffStateV1,
    pub timer_exposure: String,
    pub human_required: bool,
    pub last_event_id: String,
    pub last_event_detail: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStateV1 {
    Staging,
    Validated,
    Armed,
    Closing,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingEventV1 {
    pub schema: String,
    pub event_id: String,
    pub target_id: String,
    pub event_kind: String,
    pub operation_id: String,
    pub sequence: u64,
    pub occurred_at_unix_ms: i64,
    pub detail: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingGrantStatusV1 {
    pub schema: String,
    pub grant_id: String,
    pub active: bool,
    pub terminal_reason: Option<String>,
    pub expires_at_unix_ms: i64,
    pub observer_generations_issued: u16,
    pub observer_generations_remaining: u16,
    pub recurrence_enrollments_issued: u16,
    pub recurrence_enrollments_remaining: u16,
    pub watcher_succession_edges_issued: u16,
    pub watcher_succession_edges_remaining: u16,
    pub successor_handoffs_staged: u16,
    pub successor_handoffs_remaining: u16,
    pub aggregate_samples_issued: u64,
    pub aggregate_samples_remaining: u64,
    pub aggregate_acquisitions_issued: u64,
    pub aggregate_acquisitions_remaining: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeActivationStatusV1 {
    pub schema: String,
    pub activation_id: String,
    pub grant_id: String,
    pub generation_id: String,
    pub enrollment_id: String,
    pub state: ActivationStateV1,
    pub timer_exposure: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TickGateV1 {
    Inert {
        activation_id: String,
        state: ActivationStateV1,
        attempts_consumed: u8,
        reason: String,
    },
    Exposed {
        activation_id: String,
        enrollment_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum GrantTickGateV1 {
    Inert {
        grant_id: String,
        attempts_consumed: u8,
        reason: String,
    },
    Exposed {
        grant_id: String,
        activation_id: String,
        enrollment_id: String,
    },
}

pub struct OperatingLedger {
    root: PathBuf,
    _lock: Flock<File>,
}

impl OperatingGrantV1 {
    pub fn new(
        spec: OperatingGrantSpecV1,
        observer_policy: OperationalPolicyV1,
        recurrence_policy: RecurringOfficePolicyV1,
        created_at_unix_ms: i64,
        issuer: Value,
    ) -> Result<Self> {
        validate_grant_spec(
            &spec,
            &observer_policy,
            &recurrence_policy,
            created_at_unix_ms,
        )?;
        let observer_deployment_policy_id = semantic_digest(&observer_policy)?.to_string();
        let recurrence_deployment_policy_id = semantic_digest(&recurrence_policy)?.to_string();
        let preimage = json!({
            "schema": OPERATING_GRANT_SCHEMA_V1,
            "spec": spec,
            "observer_deployment_policy_id": observer_deployment_policy_id,
            "observer_deployment_policy": observer_policy,
            "recurrence_deployment_policy_id": recurrence_deployment_policy_id,
            "recurrence_deployment_policy": recurrence_policy,
            "created_at_unix_ms": created_at_unix_ms,
            "issuer": issuer,
        });
        let grant_id = semantic_digest(&preimage)?.to_string();
        Ok(Self {
            schema: OPERATING_GRANT_SCHEMA_V1.into(),
            grant_id,
            spec: serde_json::from_value(preimage["spec"].clone())?,
            observer_deployment_policy_id: preimage["observer_deployment_policy_id"]
                .as_str()
                .context("observer policy id")?
                .into(),
            observer_deployment_policy: serde_json::from_value(
                preimage["observer_deployment_policy"].clone(),
            )?,
            recurrence_deployment_policy_id: preimage["recurrence_deployment_policy_id"]
                .as_str()
                .context("recurrence policy id")?
                .into(),
            recurrence_deployment_policy: serde_json::from_value(
                preimage["recurrence_deployment_policy"].clone(),
            )?,
            created_at_unix_ms,
            issuer: preimage["issuer"].clone(),
        })
    }
}

impl OperatingLedger {
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            bail!("operating-office state directory must be absolute");
        }
        fs::create_dir_all(root)?;
        for child in [
            "grants",
            "grant-events",
            "children",
            "activations",
            "activation-events",
            "successions",
            "handoffs",
            "handoff-events",
        ] {
            fs::create_dir_all(root.join(child))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join(".operating-office.lock"))?;
        let lock = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| error)?;
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
        })
    }

    pub fn create_grant(&self, grant: &OperatingGrantV1) -> Result<String> {
        validate_materialized_grant(grant)?;
        for existing in read_dir_json::<OperatingGrantV1>(&self.root.join("grants"))? {
            validate_materialized_grant(&existing)?;
            if existing.spec.operator_occurrence_id == grant.spec.operator_occurrence_id {
                if same_grant_intent(&existing, grant) {
                    return Ok(existing.grant_id);
                }
                bail!("operating-grant operator occurrence was reused for different authority");
            }
        }
        write_canonical_idempotent(&self.grant_path(&grant.grant_id), grant)?;
        Ok(grant.grant_id.clone())
    }

    pub fn activate_grant(&self, grant_id: &str, operation_id: &str, now: i64) -> Result<String> {
        let grant = self.grant(grant_id)?;
        if now < grant.spec.not_before_unix_ms || now >= grant.spec.expires_at_unix_ms {
            bail!("operating grant is outside its finite activation interval");
        }
        self.append_event(
            "grant-events",
            grant_id,
            "activated",
            operation_id,
            now,
            json!({}),
        )
    }

    pub fn retire_grant(
        &self,
        grant_id: &str,
        operation_id: &str,
        now: i64,
        reason: &str,
    ) -> Result<String> {
        self.grant(grant_id)?;
        bounded(reason, "retirement reason")?;
        self.append_event(
            "grant-events",
            grant_id,
            "retired",
            operation_id,
            now,
            json!({"reason": reason}),
        )
    }

    pub fn issue_generation(
        &self,
        grant_id: &str,
        generation: &ObserverGenerationV1,
        generation_id: &str,
        operation_id: &str,
        now: i64,
    ) -> Result<ChildGrantIssuanceV1> {
        let grant = self.require_active_grant(grant_id, now)?;
        let expected_id = semantic_digest(generation)?.to_string();
        if expected_id != generation_id {
            bail!("observer generation identity differs from exact canonical bytes");
        }
        validate_generation_child(&grant, generation)?;
        let prior = self.child_issuances(grant_id, ChildGrantKindV1::ObserverGeneration)?;
        if let Some(existing) = prior.iter().find(|item| item.child_id == generation_id) {
            if existing.operation_id == operation_id && existing.exact_child_digest == expected_id {
                return Ok(existing.clone());
            }
            bail!("observer generation child identity was reused for different issuance semantics");
        }
        validate_child_budget(
            &grant,
            &prior,
            ChildGrantKindV1::ObserverGeneration,
            generation.spec.max_samples,
            generation.spec.not_before_unix_ms,
            generation.spec.expires_at_unix_ms,
            generation.spec.previous_generation_id.as_deref(),
            grant.spec.observer_predecessor_generation_id.as_deref(),
        )?;
        let semantic_snapshot_digest = generation_semantic_digest(generation)?;
        self.persist_issuance(ChildIssuanceInput {
            grant: &grant,
            kind: ChildGrantKindV1::ObserverGeneration,
            child_id: generation_id,
            predecessor: generation.spec.previous_generation_id.as_deref(),
            starts: generation.spec.not_before_unix_ms,
            expires: generation.spec.expires_at_unix_ms,
            count: generation.spec.max_samples,
            semantic_snapshot_digest: &semantic_snapshot_digest,
            exact_child_digest: &expected_id,
            operation_id,
            now,
        })
    }

    pub fn issue_enrollment(
        &self,
        grant_id: &str,
        enrollment: &RecurrenceEnrollmentV1,
        operation_id: &str,
        now: i64,
    ) -> Result<ChildGrantIssuanceV1> {
        let grant = self.require_active_grant(grant_id, now)?;
        if !self.watcher_digest_is_authorized(
            grant_id,
            &enrollment.spec.watcher_instance_id,
            &enrollment.watcher_semantic_digest,
        )? {
            bail!(
                "recurrence enrollment watcher is not reachable through H's issued succession chain"
            );
        }
        let expected_id = semantic_digest(enrollment)?.to_string();
        Sha256Digest::parse(enrollment.enrollment_id.clone())
            .context("recurrence enrollment has invalid content-derived identity")?;
        validate_enrollment_child(&grant, enrollment)?;
        let prior = self.child_issuances(grant_id, ChildGrantKindV1::RecurrenceEnrollment)?;
        if let Some(existing) = prior
            .iter()
            .find(|item| item.child_id == enrollment.enrollment_id)
        {
            if existing.operation_id == operation_id && existing.exact_child_digest == expected_id {
                return Ok(existing.clone());
            }
            bail!(
                "recurrence enrollment child identity was reused for different issuance semantics"
            );
        }
        let predecessor = prior.last().map(|item| item.child_id.as_str());
        validate_child_budget(
            &grant,
            &prior,
            ChildGrantKindV1::RecurrenceEnrollment,
            u64::from(enrollment.spec.max_acquisition_occurrences),
            enrollment.spec.anchor_unix_ms,
            enrollment.spec.expires_at_unix_ms,
            predecessor,
            None,
        )?;
        let semantic_snapshot_digest = enrollment_semantic_digest(enrollment)?;
        self.persist_issuance(ChildIssuanceInput {
            grant: &grant,
            kind: ChildGrantKindV1::RecurrenceEnrollment,
            child_id: &enrollment.enrollment_id,
            predecessor,
            starts: enrollment.spec.anchor_unix_ms,
            expires: enrollment.spec.expires_at_unix_ms,
            count: u64::from(enrollment.spec.max_acquisition_occurrences),
            semantic_snapshot_digest: &semantic_snapshot_digest,
            exact_child_digest: &expected_id,
            operation_id,
            now,
        })
    }

    /// Consume one finite H succession-edge allowance. The relation remains
    /// continuity evidence only; this operation creates no admission.
    pub fn issue_watcher_succession(
        &self,
        grant_id: &str,
        relation: &PassiveWatcherSuccessionV1,
        now: i64,
    ) -> Result<String> {
        let grant = self.require_active_grant(grant_id, now)?;
        relation.validate()?;
        if !grant
            .spec
            .allowed_watcher_succession_relation_ids
            .contains(&relation.relation_id)
        {
            bail!("watcher succession relation is not in H's exact closed set");
        }
        let prior = self.watcher_successions(grant_id)?;
        if let Some(existing) = prior
            .iter()
            .find(|existing| existing.relation_id == relation.relation_id)
        {
            if existing == relation {
                return Ok(relation.relation_id.clone());
            }
            bail!("watcher succession relation identity was substituted");
        }
        if prior.len() >= usize::from(grant.spec.max_watcher_succession_edges) {
            bail!("operating grant watcher succession budget is exhausted");
        }
        let predecessor_digest = relation.predecessor_digest()?;
        let expected_predecessor = prior
            .last()
            .map(PassiveWatcherSuccessionV1::successor_digest)
            .transpose()?
            .unwrap_or_else(|| grant.spec.watcher_semantic_digest.clone());
        let expected_instance = prior
            .last()
            .map_or(grant.spec.watcher_instance_id.as_str(), |edge| {
                edge.successor.instance_id.as_str()
            });
        if predecessor_digest != expected_predecessor
            || relation.predecessor.instance_id != expected_instance
        {
            bail!("watcher succession does not extend H's exact directed chain");
        }
        let successor_passive = relation
            .successor
            .passive_host_load_sample
            .as_ref()
            .context("successor is not passive load")?;
        if successor_passive.observer_profile != grant.spec.observer_profile
            || successor_passive.observer_artifact_digest != grant.spec.observer_artifact_digest
            || successor_passive.capacity_context_id != grant.spec.capacity_context_id
            || successor_passive.max_sample_age_ms
                != grant
                    .observer_deployment_policy
                    .max_sample_eligibility_age_ms
            || !grant
                .spec
                .allowed_signing_key_ids
                .contains(&successor_passive.producer_key_id)
        {
            bail!("watcher succession escapes H's exact semantic/key envelope");
        }
        let path = self
            .root
            .join("successions")
            .join(id_component(grant_id))
            .join(format!("{}.json", id_component(&relation.relation_id)));
        write_canonical_new(&path, relation)?;
        Ok(relation.relation_id.clone())
    }

    pub fn stage_activation(
        &self,
        spec: OfficeActivationSpecV1,
        now: i64,
    ) -> Result<OfficeActivationV1> {
        if spec.schema != OFFICE_ACTIVATION_SPEC_SCHEMA_V1 {
            bail!("unsupported activation spec");
        }
        for value in [
            &spec.operation_id,
            &spec.grant_id,
            &spec.generation_id,
            &spec.enrollment_id,
            &spec.watcher_instance_id,
            &spec.watcher_semantic_digest,
            &spec.admission_id,
            &spec.genesis_acquisition_id,
            &spec.provider_config_digest,
            &spec.passive_provider_boundary_id,
            &spec.capacity_context_id,
            &spec.service_manager_deployment_digest,
        ] {
            bounded(value, "activation identity")?;
        }
        if !spec.generation_path.is_absolute()
            || !spec.provider_config_path.is_absolute()
            || !spec.sample_store.is_absolute()
            || !spec.service_manager_deployment_path.is_absolute()
        {
            bail!("activation paths must be absolute");
        }
        let preimage = json!({"schema": OFFICE_ACTIVATION_SCHEMA_V1, "spec": spec,
            "staged_at_unix_ms": now});
        let activation_id = semantic_digest(&preimage)?.to_string();
        let activation = OfficeActivationV1 {
            schema: OFFICE_ACTIVATION_SCHEMA_V1.into(),
            activation_id: activation_id.clone(),
            spec: serde_json::from_value(preimage["spec"].clone())?,
            staged_at_unix_ms: now,
        };
        write_canonical_idempotent(&self.activation_path(&activation_id), &activation)?;
        self.append_event(
            "activation-events",
            &activation_id,
            "staged",
            &activation.spec.operation_id,
            now,
            json!({"timer_exposure": "inert"}),
        )?;
        Ok(activation)
    }

    #[allow(clippy::too_many_lines)]
    pub fn stage_successor_handoff(
        &self,
        spec: SuccessorHandoffSpecV1,
        now: i64,
    ) -> Result<SuccessorHandoffV1> {
        if spec.schema != SUCCESSOR_HANDOFF_SPEC_SCHEMA_V1 {
            bail!("unsupported successor handoff spec");
        }
        let grant = self.grant(&spec.grant_id)?;
        if !self.grant_permits_issued_child_runtime(&spec.grant_id, now)? {
            bail!("operating grant is not active for an issued successor handoff");
        }
        for value in [
            &spec.operation_id,
            &spec.grant_id,
            &spec.succession_relation_id,
            &spec.predecessor_activation_id,
            &spec.next_generation_id,
            &spec.successor_watcher_instance_id,
            &spec.successor_watcher_semantic_digest,
            &spec.expected_admission_id,
            &spec.genesis_acquisition_id,
            &spec.expected_instance_id_sha256,
            &spec.origin_helper_sha256,
            &spec.origin_helper_account,
            &spec.next_enrollment_id,
            &spec.next_activation_id,
        ] {
            bounded(value, "successor handoff identity")?;
        }
        uuid::Uuid::parse_str(&spec.expected_admission_id)
            .context("handoff expected admission identity must be a UUID")?;
        for digest in [
            &spec.successor_watcher_semantic_digest,
            &spec.expected_instance_id_sha256,
            &spec.origin_helper_sha256,
        ] {
            Sha256Digest::parse(digest.clone()).context("invalid handoff digest")?;
        }
        if !spec.next_generation_path.is_absolute()
            || !spec.origin_helper_path.is_absolute()
            || !spec.origin_helper_public_key_path.is_absolute()
        {
            bail!("successor handoff paths must be absolute");
        }
        let relation = self.watcher_succession(&spec.grant_id, &spec.succession_relation_id)?;
        if relation.successor.instance_id != spec.successor_watcher_instance_id
            || relation.successor_digest()? != spec.successor_watcher_semantic_digest
        {
            bail!("successor handoff substitutes the exact directed watcher relation");
        }
        let origin = grant
            .recurrence_deployment_policy
            .watcher_bindings
            .iter()
            .find(|binding| {
                binding.watcher_instance_id == spec.successor_watcher_instance_id
                    && binding.watcher_semantic_digest == spec.successor_watcher_semantic_digest
            })
            .context("successor handoff watcher lacks exact deployment origin policy")?;
        if origin.expected_instance_id_sha256 != spec.expected_instance_id_sha256
            || origin.origin_helper_path != spec.origin_helper_path
            || origin.origin_helper_sha256 != spec.origin_helper_sha256
            || origin.origin_helper_account != spec.origin_helper_account
            || origin.origin_helper_public_key_path != spec.origin_helper_public_key_path
            || origin.coordination_domain_id != grant.spec.coordination_domain_id
        {
            bail!("successor handoff origin or coordination policy is substituted");
        }
        let activation = self.activation(&spec.next_activation_id)?;
        if activation.spec.grant_id != spec.grant_id
            || activation.spec.generation_id != spec.next_generation_id
            || activation.spec.generation_path != spec.next_generation_path
            || activation.spec.enrollment_id != spec.next_enrollment_id
            || activation.spec.watcher_instance_id != spec.successor_watcher_instance_id
            || activation.spec.watcher_semantic_digest != spec.successor_watcher_semantic_digest
            || activation.spec.admission_id != spec.expected_admission_id
            || activation.spec.genesis_acquisition_id != spec.genesis_acquisition_id
            || activation.spec.provider_config_path
                != relation.successor_custody.provider_config_path
            || activation.spec.provider_config_digest
                != relation.successor_custody.provider_config_digest
            || activation.spec.sample_store != relation.successor_custody.sample_store
            || relation.successor_custody.observer_config_digest != spec.next_generation_id
            || activation.spec.passive_provider_boundary_id
                != grant.spec.passive_provider_boundary_id
        {
            bail!("successor handoff activation tuple is substituted");
        }
        let predecessor = self.activation(&spec.predecessor_activation_id)?;
        if predecessor.spec.grant_id != spec.grant_id
            || predecessor.spec.watcher_instance_id != relation.predecessor.instance_id
            || predecessor.spec.watcher_semantic_digest != relation.predecessor_digest()?
        {
            bail!("successor handoff predecessor activation is substituted");
        }
        let generations =
            self.child_issuances(&spec.grant_id, ChildGrantKindV1::ObserverGeneration)?;
        let enrollments =
            self.child_issuances(&spec.grant_id, ChildGrantKindV1::RecurrenceEnrollment)?;
        let generation_index = generations
            .iter()
            .position(|item| item.child_id == spec.next_generation_id)
            .context("handoff G child was not issued under H")?;
        let enrollment_index = enrollments
            .iter()
            .position(|item| item.child_id == spec.next_enrollment_id)
            .context("handoff E child was not issued under H")?;
        if generation_index == 0
            || generation_index != enrollment_index
            || generations[generation_index - 1].child_id != predecessor.spec.generation_id
            || enrollments[enrollment_index - 1].child_id != predecessor.spec.enrollment_id
        {
            bail!("handoff may only advance the next exact paired G/E child boundary");
        }
        let relations = self.watcher_successions(&spec.grant_id)?;
        if relations
            .get(generation_index - 1)
            .map(|edge| edge.relation_id.as_str())
            != Some(spec.succession_relation_id.as_str())
        {
            bail!("handoff may not skip or reorder H's closed succession chain");
        }
        let existing = self.handoffs(&spec.grant_id)?;
        if let Some(prior) = existing.iter().find(|item| item.spec == spec) {
            return Ok(prior.clone());
        }
        if existing.iter().any(|item| {
            item.spec.succession_relation_id == spec.succession_relation_id
                || item.spec.next_generation_id == spec.next_generation_id
                || item.spec.next_enrollment_id == spec.next_enrollment_id
                || item.spec.next_activation_id == spec.next_activation_id
        }) {
            bail!("an exact H successor boundary already has a handoff");
        }
        if existing.len() >= usize::from(grant.spec.max_watcher_succession_edges) {
            bail!("operating grant successor-handoff budget is exhausted");
        }
        let preimage = json!({"schema": SUCCESSOR_HANDOFF_SCHEMA_V1, "spec": spec,
            "staged_at_unix_ms": now});
        let handoff_id = semantic_digest(&preimage)?.to_string();
        let handoff = SuccessorHandoffV1 {
            schema: SUCCESSOR_HANDOFF_SCHEMA_V1.into(),
            handoff_id: handoff_id.clone(),
            spec: serde_json::from_value(preimage["spec"].clone())?,
            staged_at_unix_ms: now,
        };
        write_canonical_idempotent(&self.handoff_path(&handoff_id), &handoff)?;
        self.append_event(
            "handoff-events",
            &handoff_id,
            "staged",
            &handoff.spec.operation_id,
            now,
            json!({"procedure_authority": "finite_exact_validation_sequence", "timer_exposure": "inert"}),
        )?;
        Ok(handoff)
    }

    pub(crate) fn advance_handoff(
        &self,
        handoff_id: &str,
        next: SuccessorHandoffStateV1,
        operation_id: &str,
        now: i64,
        detail: Value,
    ) -> Result<String> {
        let current = self.handoff_status(handoff_id)?.state;
        if current == next {
            return self.append_event(
                "handoff-events",
                handoff_id,
                handoff_event_kind(next),
                operation_id,
                now,
                detail,
            );
        }
        if !valid_handoff_transition(current, next) {
            bail!("forbidden successor-handoff state transition {current:?} -> {next:?}");
        }
        self.append_event(
            "handoff-events",
            handoff_id,
            handoff_event_kind(next),
            operation_id,
            now,
            detail,
        )
    }

    /// Disarm the exact predecessor before exposing the successor activation.
    /// A crash between the two append-only transitions yields a safe real gap;
    /// restart can finish the same handoff and can never expose both E grants.
    pub(crate) fn arm_successor_handoff(
        &self,
        handoff_id: &str,
        operation_id: &str,
        now: i64,
    ) -> Result<Vec<String>> {
        let handoff = self.handoff(handoff_id)?;
        if self.handoff_status(handoff_id)?.state != SuccessorHandoffStateV1::Validated {
            bail!("only an exactly validated handoff may arm its successor");
        }
        let mut events = Vec::new();
        if self
            .activation_status(&handoff.spec.predecessor_activation_id)?
            .state
            != ActivationStateV1::Closed
        {
            events.extend(self.close_activation(
                &handoff.spec.predecessor_activation_id,
                &format!("{operation_id}:predecessor"),
                now,
                "exact successor handoff",
            )?);
        }
        let next_state = self
            .activation_status(&handoff.spec.next_activation_id)?
            .state;
        if next_state == ActivationStateV1::Validated {
            events.push(self.arm(
                &handoff.spec.next_activation_id,
                &format!("{operation_id}:activation"),
                now,
            )?);
        } else if next_state != ActivationStateV1::Armed {
            bail!("successor activation is not validated or already armed");
        }
        events.push(self.advance_handoff(
            handoff_id,
            SuccessorHandoffStateV1::Armed,
            &format!("{operation_id}:handoff"),
            now,
            json!({"next_activation_id": handoff.spec.next_activation_id,
                "timer_exposure": "finite_recurrence"}),
        )?);
        Ok(events)
    }

    pub fn handoff_status(&self, handoff_id: &str) -> Result<SuccessorHandoffStatusV1> {
        let handoff = self.handoff(handoff_id)?;
        let mut state = SuccessorHandoffStateV1::Staged;
        let events = self.events("handoff-events", handoff_id)?;
        for (index, event) in events.iter().enumerate() {
            let next = parse_handoff_event(&event.event_kind)?;
            if index == 0 {
                if next != SuccessorHandoffStateV1::Staged {
                    bail!("successor-handoff history does not begin staged");
                }
            } else if next != state && !valid_handoff_transition(state, next) {
                bail!("successor-handoff history contains a forbidden transition");
            }
            state = next;
        }
        let last = events
            .last()
            .context("successor handoff has no staged event")?;
        Ok(SuccessorHandoffStatusV1 {
            schema: "nq.passive_load_successor_handoff_status.v1".into(),
            handoff_id: handoff_id.into(),
            grant_id: handoff.spec.grant_id,
            relation_id: handoff.spec.succession_relation_id,
            next_generation_id: handoff.spec.next_generation_id,
            successor_watcher_instance_id: handoff.spec.successor_watcher_instance_id,
            expected_admission_id: handoff.spec.expected_admission_id,
            genesis_acquisition_id: handoff.spec.genesis_acquisition_id,
            next_enrollment_id: handoff.spec.next_enrollment_id,
            next_activation_id: handoff.spec.next_activation_id,
            state,
            timer_exposure: if state == SuccessorHandoffStateV1::Armed {
                "finite_recurrence"
            } else {
                "inert"
            }
            .into(),
            human_required: matches!(
                state,
                SuccessorHandoffStateV1::AdmissionRefused
                    | SuccessorHandoffStateV1::GenesisRefused
                    | SuccessorHandoffStateV1::OutcomeUnknown
                    | SuccessorHandoffStateV1::Expired
            ),
            last_event_id: last.event_id.clone(),
            last_event_detail: last.detail.clone(),
        })
    }

    pub fn handoff(&self, handoff_id: &str) -> Result<SuccessorHandoffV1> {
        let handoff: SuccessorHandoffV1 = read_json(&self.handoff_path(handoff_id))?;
        if semantic_digest(&json!({"schema": handoff.schema, "spec": handoff.spec,
            "staged_at_unix_ms": handoff.staged_at_unix_ms}))?
        .as_str()
            != handoff.handoff_id
        {
            bail!("successor handoff identity differs from exact canonical bytes");
        }
        Ok(handoff)
    }

    pub fn mark_validated(
        &self,
        activation_id: &str,
        operation_id: &str,
        now: i64,
        readiness: Value,
    ) -> Result<String> {
        if self.activation_status(activation_id)?.state != ActivationStateV1::Staging {
            bail!("only a staging activation may become validated");
        }
        self.append_event(
            "activation-events",
            activation_id,
            "validated",
            operation_id,
            now,
            readiness,
        )
    }

    pub fn arm(&self, activation_id: &str, operation_id: &str, now: i64) -> Result<String> {
        let activation = self.activation(activation_id)?;
        if self.activation_status(activation_id)?.state != ActivationStateV1::Validated {
            bail!("only an exactly validated activation may become armed");
        }
        if !self.grant_permits_issued_child_runtime(&activation.spec.grant_id, now)? {
            bail!("operating grant is not active for issued child runtime");
        }
        self.append_event("activation-events", activation_id, "armed", operation_id, now,
            json!({"enrollment_id": activation.spec.enrollment_id, "timer_exposure": "finite_recurrence"}))
    }

    pub fn close_activation(
        &self,
        activation_id: &str,
        operation_id: &str,
        now: i64,
        reason: &str,
    ) -> Result<Vec<String>> {
        bounded(reason, "closeout reason")?;
        let state = self.activation_status(activation_id)?.state;
        if state == ActivationStateV1::Closed {
            return Ok(Vec::new());
        }
        let first = self.append_event(
            "activation-events",
            activation_id,
            "closing",
            &format!("{operation_id}:closing"),
            now,
            json!({"reason": reason, "timer_exposure": "inert"}),
        )?;
        let second = self.append_event(
            "activation-events",
            activation_id,
            "closed",
            &format!("{operation_id}:closed"),
            now,
            json!({"reason": reason, "timer_exposure": "inert"}),
        )?;
        Ok(vec![first, second])
    }

    pub fn tick_gate(&self, activation_id: &str, now: i64) -> Result<TickGateV1> {
        let activation = self.activation(activation_id)?;
        let status = self.activation_status(activation_id)?;
        if status.state != ActivationStateV1::Armed {
            return Ok(TickGateV1::Inert {
                activation_id: activation_id.into(),
                state: status.state,
                attempts_consumed: 0,
                reason: "office_not_canonically_armed".into(),
            });
        }
        let grant_status = self.grant_status(&activation.spec.grant_id, now)?;
        if !Self::status_permits_issued_child_runtime(&grant_status) {
            return Ok(TickGateV1::Inert {
                activation_id: activation_id.into(),
                state: status.state,
                attempts_consumed: 0,
                reason: grant_status
                    .terminal_reason
                    .unwrap_or_else(|| "operating_grant_inactive".into()),
            });
        }
        Ok(TickGateV1::Exposed {
            activation_id: activation_id.into(),
            enrollment_id: activation.spec.enrollment_id,
        })
    }

    /// Project the sole Armed activation under one exact finite H. The
    /// service-manager can wake this gate without knowing child activation
    /// identities; it still creates no authority and multiple Armed children
    /// fail closed.
    pub fn grant_tick_gate(&self, grant_id: &str, now: i64) -> Result<GrantTickGateV1> {
        self.grant(grant_id)?;
        let mut armed = Vec::new();
        for activation in read_dir_json::<OfficeActivationV1>(&self.root.join("activations"))?
            .into_iter()
            .filter(|activation| activation.spec.grant_id == grant_id)
        {
            let status = self.activation_status(&activation.activation_id)?;
            if status.state == ActivationStateV1::Armed {
                armed.push(status);
            }
        }
        armed.sort_by(|left, right| left.activation_id.cmp(&right.activation_id));
        match armed.as_slice() {
            [] => Ok(GrantTickGateV1::Inert {
                grant_id: grant_id.into(),
                attempts_consumed: 0,
                reason: "no_canonically_armed_activation".into(),
            }),
            [status] => match self.tick_gate(&status.activation_id, now)? {
                TickGateV1::Inert { reason, .. } => Ok(GrantTickGateV1::Inert {
                    grant_id: grant_id.into(),
                    attempts_consumed: 0,
                    reason,
                }),
                TickGateV1::Exposed {
                    activation_id,
                    enrollment_id,
                } => Ok(GrantTickGateV1::Exposed {
                    grant_id: grant_id.into(),
                    activation_id,
                    enrollment_id,
                }),
            },
            _ => bail!("operating grant has multiple canonically Armed activations"),
        }
    }

    /// H exhaustion ends further child issuance; it does not revoke an exact
    /// already-issued child. Retirement, expiry, and absence of activation do.
    pub fn grant_permits_issued_child_runtime(&self, grant_id: &str, now: i64) -> Result<bool> {
        Ok(Self::status_permits_issued_child_runtime(
            &self.grant_status(grant_id, now)?,
        ))
    }

    fn status_permits_issued_child_runtime(status: &OperatingGrantStatusV1) -> bool {
        status.active || status.terminal_reason.as_deref() == Some("child_budgets_exhausted")
    }

    pub fn grant_status(&self, grant_id: &str, now: i64) -> Result<OperatingGrantStatusV1> {
        let grant = self.grant(grant_id)?;
        let events = self.events("grant-events", grant_id)?;
        let activated = events.iter().any(|event| event.event_kind == "activated");
        let retired = events.iter().any(|event| event.event_kind == "retired");
        let generations = self.child_issuances(grant_id, ChildGrantKindV1::ObserverGeneration)?;
        let enrollments = self.child_issuances(grant_id, ChildGrantKindV1::RecurrenceEnrollment)?;
        let successions = self.watcher_successions(grant_id)?;
        let handoffs = self.handoffs(grant_id)?;
        let samples = generations
            .iter()
            .map(|item| item.finite_authority_count)
            .sum::<u64>();
        let acquisitions = enrollments
            .iter()
            .map(|item| item.finite_authority_count)
            .sum::<u64>();
        let expired = now >= grant.spec.expires_at_unix_ms;
        let exhausted = generations.len() >= usize::from(grant.spec.max_observer_generations)
            && enrollments.len() >= usize::from(grant.spec.max_recurrence_enrollments);
        let active = activated && !retired && !expired && !exhausted;
        let terminal_reason = if retired {
            Some("retired".into())
        } else if expired {
            Some("expired".into())
        } else if exhausted {
            Some("child_budgets_exhausted".into())
        } else if !activated {
            Some("not_activated".into())
        } else {
            None
        };
        Ok(OperatingGrantStatusV1 {
            schema: "nq.passive_load_operating_grant_status.v1".into(),
            grant_id: grant_id.into(),
            active,
            terminal_reason,
            expires_at_unix_ms: grant.spec.expires_at_unix_ms,
            observer_generations_issued: generations.len().try_into().unwrap_or(u16::MAX),
            observer_generations_remaining: grant
                .spec
                .max_observer_generations
                .saturating_sub(generations.len().try_into().unwrap_or(u16::MAX)),
            recurrence_enrollments_issued: enrollments.len().try_into().unwrap_or(u16::MAX),
            recurrence_enrollments_remaining: grant
                .spec
                .max_recurrence_enrollments
                .saturating_sub(enrollments.len().try_into().unwrap_or(u16::MAX)),
            watcher_succession_edges_issued: successions.len().try_into().unwrap_or(u16::MAX),
            watcher_succession_edges_remaining: grant
                .spec
                .max_watcher_succession_edges
                .saturating_sub(successions.len().try_into().unwrap_or(u16::MAX)),
            successor_handoffs_staged: handoffs.len().try_into().unwrap_or(u16::MAX),
            successor_handoffs_remaining: grant
                .spec
                .max_watcher_succession_edges
                .saturating_sub(handoffs.len().try_into().unwrap_or(u16::MAX)),
            aggregate_samples_issued: samples,
            aggregate_samples_remaining: grant.spec.max_aggregate_samples.saturating_sub(samples),
            aggregate_acquisitions_issued: acquisitions,
            aggregate_acquisitions_remaining: grant
                .spec
                .max_aggregate_acquisitions
                .saturating_sub(acquisitions),
        })
    }

    pub fn activation_status(&self, activation_id: &str) -> Result<OfficeActivationStatusV1> {
        let activation = self.activation(activation_id)?;
        let events = self.events("activation-events", activation_id)?;
        let mut state = ActivationStateV1::Staging;
        for event in events {
            state = match event.event_kind.as_str() {
                "staged" => ActivationStateV1::Staging,
                "validated" => ActivationStateV1::Validated,
                "armed" => ActivationStateV1::Armed,
                "closing" => ActivationStateV1::Closing,
                "closed" => ActivationStateV1::Closed,
                other => bail!("unknown activation event {other}"),
            };
        }
        Ok(OfficeActivationStatusV1 {
            schema: "nq.passive_load_office_activation_status.v1".into(),
            activation_id: activation_id.into(),
            grant_id: activation.spec.grant_id,
            generation_id: activation.spec.generation_id,
            enrollment_id: activation.spec.enrollment_id,
            state,
            timer_exposure: if state == ActivationStateV1::Armed {
                "finite_recurrence"
            } else {
                "inert"
            }
            .into(),
        })
    }

    pub fn grant(&self, grant_id: &str) -> Result<OperatingGrantV1> {
        let grant: OperatingGrantV1 = read_json(&self.grant_path(grant_id))?;
        validate_materialized_grant(&grant)?;
        Ok(grant)
    }

    pub fn activation(&self, activation_id: &str) -> Result<OfficeActivationV1> {
        let activation: OfficeActivationV1 = read_json(&self.activation_path(activation_id))?;
        if semantic_digest(
            &json!({"schema": activation.schema, "spec": activation.spec,
            "staged_at_unix_ms": activation.staged_at_unix_ms}),
        )?
        .as_str()
            != activation.activation_id
        {
            bail!("activation identity differs from exact canonical bytes");
        }
        Ok(activation)
    }

    pub fn has_child_issuance(
        &self,
        grant_id: &str,
        kind: ChildGrantKindV1,
        child_id: &str,
    ) -> Result<bool> {
        Ok(self
            .child_issuances(grant_id, kind)?
            .iter()
            .any(|item| item.child_id == child_id))
    }

    pub fn watcher_succession(
        &self,
        grant_id: &str,
        relation_id: &str,
    ) -> Result<PassiveWatcherSuccessionV1> {
        let relation: PassiveWatcherSuccessionV1 = read_json(
            &self
                .root
                .join("successions")
                .join(id_component(grant_id))
                .join(format!("{}.json", id_component(relation_id))),
        )?;
        relation.validate()?;
        Ok(relation)
    }

    pub fn watcher_digest_is_authorized(
        &self,
        grant_id: &str,
        instance_id: &str,
        watcher_digest: &str,
    ) -> Result<bool> {
        let grant = self.grant(grant_id)?;
        if grant.spec.watcher_instance_id == instance_id
            && grant.spec.watcher_semantic_digest == watcher_digest
        {
            return Ok(true);
        }
        let mut expected_instance = grant.spec.watcher_instance_id.clone();
        let mut expected_digest = grant.spec.watcher_semantic_digest.clone();
        for edge in self.watcher_successions(grant_id)? {
            if edge.predecessor.instance_id != expected_instance
                || edge.predecessor_digest()? != expected_digest
            {
                bail!("operating grant watcher succession ledger is not one exact directed chain");
            }
            expected_instance.clone_from(&edge.successor.instance_id);
            expected_digest = edge.successor_digest()?;
            if expected_instance == instance_id && expected_digest == watcher_digest {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn require_active_grant(&self, grant_id: &str, now: i64) -> Result<OperatingGrantV1> {
        let grant = self.grant(grant_id)?;
        if !self.grant_status(grant_id, now)?.active {
            bail!("operating grant is not active");
        }
        Ok(grant)
    }

    fn persist_issuance(&self, input: ChildIssuanceInput<'_>) -> Result<ChildGrantIssuanceV1> {
        bounded(input.operation_id, "child issuance operation")?;
        let preimage = json!({"schema": CHILD_ISSUANCE_SCHEMA_V1, "grant_id": input.grant.grant_id,
            "kind": input.kind, "child_id": input.child_id, "predecessor_child_id": input.predecessor,
            "starts_at_unix_ms": input.starts, "expires_at_unix_ms": input.expires,
            "finite_authority_count": input.count, "semantic_snapshot_digest": input.semantic_snapshot_digest,
            "exact_child_digest": input.exact_child_digest, "operation_id": input.operation_id,
            "issued_at_unix_ms": input.now});
        let issuance_id = semantic_digest(&preimage)?.to_string();
        let issuance = ChildGrantIssuanceV1 {
            schema: CHILD_ISSUANCE_SCHEMA_V1.into(),
            issuance_id,
            grant_id: input.grant.grant_id.clone(),
            kind: input.kind,
            child_id: input.child_id.into(),
            predecessor_child_id: input.predecessor.map(str::to_owned),
            starts_at_unix_ms: input.starts,
            expires_at_unix_ms: input.expires,
            finite_authority_count: input.count,
            semantic_snapshot_digest: input.semantic_snapshot_digest.into(),
            exact_child_digest: input.exact_child_digest.into(),
            operation_id: input.operation_id.into(),
            issued_at_unix_ms: input.now,
        };
        let dir = self
            .root
            .join("children")
            .join(id_component(&input.grant.grant_id));
        fs::create_dir_all(&dir)?;
        for existing in read_dir_json::<ChildGrantIssuanceV1>(&dir)? {
            if existing.operation_id == issuance.operation_id
                || existing.child_id == issuance.child_id
            {
                if existing == issuance {
                    return Ok(existing);
                }
                bail!(
                    "child issuance operation or child identity was reused for different semantics"
                );
            }
        }
        write_canonical_new(
            &dir.join(format!(
                "{}-{}.json",
                input.kind.label(),
                id_component(&issuance.issuance_id)
            )),
            &issuance,
        )?;
        Ok(issuance)
    }

    fn child_issuances(
        &self,
        grant_id: &str,
        kind: ChildGrantKindV1,
    ) -> Result<Vec<ChildGrantIssuanceV1>> {
        let mut items = read_dir_json::<ChildGrantIssuanceV1>(
            &self.root.join("children").join(id_component(grant_id)),
        )?
        .into_iter()
        .filter(|item| item.kind == kind)
        .collect::<Vec<_>>();
        items.sort_by_key(|item| (item.starts_at_unix_ms, item.issuance_id.clone()));
        Ok(items)
    }

    fn watcher_successions(&self, grant_id: &str) -> Result<Vec<PassiveWatcherSuccessionV1>> {
        let mut items = read_dir_json::<PassiveWatcherSuccessionV1>(
            &self.root.join("successions").join(id_component(grant_id)),
        )?;
        for item in &items {
            item.validate()?;
        }
        items.sort_by_key(|item| (item.created_at_unix_ms, item.relation_id.clone()));
        for pair in items.windows(2) {
            if pair[0].created_at_unix_ms >= pair[1].created_at_unix_ms
                || pair[0].successor != pair[1].predecessor
            {
                bail!("watcher succession records are not one strictly ordered directed chain");
            }
        }
        Ok(items)
    }

    fn append_event(
        &self,
        namespace: &str,
        target_id: &str,
        kind: &str,
        operation_id: &str,
        now: i64,
        detail: Value,
    ) -> Result<String> {
        bounded(target_id, "event target")?;
        bounded(kind, "event kind")?;
        bounded(operation_id, "operation id")?;
        let dir = self.root.join(namespace).join(id_component(target_id));
        fs::create_dir_all(&dir)?;
        let existing_events = read_dir_json::<OperatingEventV1>(&dir)?;
        for existing in &existing_events {
            if existing.operation_id == operation_id {
                if existing.event_kind == kind && existing.detail == detail {
                    return Ok(existing.event_id.clone());
                }
                bail!("operation identity was reused for a different event");
            }
        }
        let sequence = u64::try_from(existing_events.len()).context("event sequence overflow")?;
        let preimage = json!({"schema": OPERATING_EVENT_SCHEMA_V1, "target_id": target_id,
            "event_kind": kind, "operation_id": operation_id, "sequence": sequence,
            "occurred_at_unix_ms": now, "detail": detail});
        let event_id = semantic_digest(&preimage)?.to_string();
        let event = OperatingEventV1 {
            schema: OPERATING_EVENT_SCHEMA_V1.into(),
            event_id: event_id.clone(),
            target_id: target_id.into(),
            event_kind: kind.into(),
            operation_id: operation_id.into(),
            sequence,
            occurred_at_unix_ms: now,
            detail: preimage["detail"].clone(),
        };
        write_canonical_new(
            &dir.join(format!("{}.json", id_component(&event_id))),
            &event,
        )?;
        Ok(event_id)
    }

    fn events(&self, namespace: &str, target_id: &str) -> Result<Vec<OperatingEventV1>> {
        let mut events = read_dir_json::<OperatingEventV1>(
            &self.root.join(namespace).join(id_component(target_id)),
        )?;
        events.sort_by_key(|event| event.sequence);
        for (expected, event) in events.iter().enumerate() {
            if event.sequence != u64::try_from(expected).unwrap_or(u64::MAX) {
                bail!("operating-office event sequence is corrupt or incomplete");
            }
        }
        Ok(events)
    }

    fn grant_path(&self, id: &str) -> PathBuf {
        self.root
            .join("grants")
            .join(format!("{}.json", id_component(id)))
    }
    fn activation_path(&self, id: &str) -> PathBuf {
        self.root
            .join("activations")
            .join(format!("{}.json", id_component(id)))
    }
    fn handoff_path(&self, id: &str) -> PathBuf {
        self.root
            .join("handoffs")
            .join(format!("{}.json", id_component(id)))
    }

    fn handoffs(&self, grant_id: &str) -> Result<Vec<SuccessorHandoffV1>> {
        let mut items = read_dir_json::<SuccessorHandoffV1>(&self.root.join("handoffs"))?
            .into_iter()
            .filter(|item| item.spec.grant_id == grant_id)
            .collect::<Vec<_>>();
        items.sort_by_key(|item| (item.staged_at_unix_ms, item.handoff_id.clone()));
        Ok(items)
    }
}

fn same_grant_intent(left: &OperatingGrantV1, right: &OperatingGrantV1) -> bool {
    left.schema == right.schema
        && left.spec == right.spec
        && left.observer_deployment_policy_id == right.observer_deployment_policy_id
        && left.observer_deployment_policy == right.observer_deployment_policy
        && left.recurrence_deployment_policy_id == right.recurrence_deployment_policy_id
        && left.recurrence_deployment_policy == right.recurrence_deployment_policy
        && left.issuer == right.issuer
}

const fn handoff_event_kind(state: SuccessorHandoffStateV1) -> &'static str {
    match state {
        SuccessorHandoffStateV1::Staged => "staged",
        SuccessorHandoffStateV1::WaitingForSample => "waiting_for_sample",
        SuccessorHandoffStateV1::SampleReady => "sample_ready",
        SuccessorHandoffStateV1::AdmissionStarted => "admission_started",
        SuccessorHandoffStateV1::AdmissionCompleted => "admission_completed",
        SuccessorHandoffStateV1::GenesisStarted => "genesis_started",
        SuccessorHandoffStateV1::GenesisCompleted => "genesis_completed",
        SuccessorHandoffStateV1::Validated => "validated",
        SuccessorHandoffStateV1::Armed => "armed",
        SuccessorHandoffStateV1::AdmissionRefused => "admission_refused",
        SuccessorHandoffStateV1::GenesisRefused => "genesis_refused",
        SuccessorHandoffStateV1::OutcomeUnknown => "outcome_unknown",
        SuccessorHandoffStateV1::Expired => "expired",
    }
}

fn parse_handoff_event(kind: &str) -> Result<SuccessorHandoffStateV1> {
    match kind {
        "staged" => Ok(SuccessorHandoffStateV1::Staged),
        "waiting_for_sample" => Ok(SuccessorHandoffStateV1::WaitingForSample),
        "sample_ready" => Ok(SuccessorHandoffStateV1::SampleReady),
        "admission_started" => Ok(SuccessorHandoffStateV1::AdmissionStarted),
        "admission_completed" => Ok(SuccessorHandoffStateV1::AdmissionCompleted),
        "genesis_started" => Ok(SuccessorHandoffStateV1::GenesisStarted),
        "genesis_completed" => Ok(SuccessorHandoffStateV1::GenesisCompleted),
        "validated" => Ok(SuccessorHandoffStateV1::Validated),
        "armed" => Ok(SuccessorHandoffStateV1::Armed),
        "admission_refused" => Ok(SuccessorHandoffStateV1::AdmissionRefused),
        "genesis_refused" => Ok(SuccessorHandoffStateV1::GenesisRefused),
        "outcome_unknown" => Ok(SuccessorHandoffStateV1::OutcomeUnknown),
        "expired" => Ok(SuccessorHandoffStateV1::Expired),
        other => bail!("unknown successor-handoff event {other}"),
    }
}

fn valid_handoff_transition(
    current: SuccessorHandoffStateV1,
    next: SuccessorHandoffStateV1,
) -> bool {
    if next == SuccessorHandoffStateV1::Expired && !current.is_terminal() {
        return true;
    }
    matches!(
        (current, next),
        (
            SuccessorHandoffStateV1::Staged | SuccessorHandoffStateV1::WaitingForSample,
            SuccessorHandoffStateV1::WaitingForSample | SuccessorHandoffStateV1::SampleReady
        ) | (
            SuccessorHandoffStateV1::SampleReady,
            SuccessorHandoffStateV1::AdmissionStarted
        ) | (
            SuccessorHandoffStateV1::AdmissionStarted,
            SuccessorHandoffStateV1::AdmissionCompleted
                | SuccessorHandoffStateV1::AdmissionRefused
                | SuccessorHandoffStateV1::OutcomeUnknown
        ) | (
            SuccessorHandoffStateV1::AdmissionCompleted,
            SuccessorHandoffStateV1::GenesisStarted
        ) | (
            SuccessorHandoffStateV1::GenesisStarted,
            SuccessorHandoffStateV1::GenesisCompleted
                | SuccessorHandoffStateV1::GenesisRefused
                | SuccessorHandoffStateV1::OutcomeUnknown
        ) | (
            SuccessorHandoffStateV1::GenesisCompleted,
            SuccessorHandoffStateV1::Validated
        ) | (
            SuccessorHandoffStateV1::Validated,
            SuccessorHandoffStateV1::Armed
        )
    )
}

struct ChildIssuanceInput<'a> {
    grant: &'a OperatingGrantV1,
    kind: ChildGrantKindV1,
    child_id: &'a str,
    predecessor: Option<&'a str>,
    starts: i64,
    expires: i64,
    count: u64,
    semantic_snapshot_digest: &'a str,
    exact_child_digest: &'a str,
    operation_id: &'a str,
    now: i64,
}

fn validate_grant_spec(
    spec: &OperatingGrantSpecV1,
    observer: &OperationalPolicyV1,
    recurrence: &RecurringOfficePolicyV1,
    now: i64,
) -> Result<()> {
    if spec.schema != OPERATING_GRANT_SPEC_SCHEMA_V1
        || spec.not_before_unix_ms < now
        || spec.expires_at_unix_ms <= spec.not_before_unix_ms
        || spec.max_observer_generations == 0
        || spec.max_recurrence_enrollments == 0
        || spec.observer_generation_duration_ms == 0
        || spec.recurrence_enrollment_duration_ms == 0
        || spec.observer_generation_max_samples == 0
        || spec.recurrence_enrollment_max_occurrences == 0
        || spec.allowed_signing_key_ids.is_empty()
    {
        bail!("operating grant must contain exact positive finite bounds");
    }
    if usize::from(spec.max_watcher_succession_edges)
        != spec.allowed_watcher_succession_relation_ids.len()
        || spec.max_watcher_succession_edges
            > spec
                .max_observer_generations
                .min(spec.max_recurrence_enrollments)
                .saturating_sub(1)
    {
        bail!("operating grant succession authority must be an exact finite closed set");
    }
    for relation_id in &spec.allowed_watcher_succession_relation_ids {
        Sha256Digest::parse(relation_id.clone()).context("invalid succession relation identity")?;
    }
    if let Some(predecessor) = &spec.observer_predecessor_generation_id {
        Sha256Digest::parse(predecessor.clone())
            .context("invalid historical observer predecessor identity")?;
    }
    for value in [
        &spec.operator_occurrence_id,
        &spec.watcher_instance_id,
        &spec.watcher_semantic_digest,
        &spec.passive_provider_boundary_id,
        &spec.observer_profile,
        &spec.observer_artifact_digest,
        &spec.sample_schema,
        &spec.subject_binding_digest,
        &spec.capacity_context_id,
        &spec.sample_eligibility_profile_id,
        &spec.coordination_domain_id,
    ] {
        bounded(value, "grant identity")?;
    }
    let duration =
        u64::try_from(spec.expires_at_unix_ms - spec.not_before_unix_ms).unwrap_or(u64::MAX);
    let expected_duration_g = spec
        .observer_generation_duration_ms
        .checked_mul(u64::from(spec.max_observer_generations))
        .context("G duration overflow")?;
    let expected_duration_e = spec
        .recurrence_enrollment_duration_ms
        .checked_mul(u64::from(spec.max_recurrence_enrollments))
        .context("E duration overflow")?;
    let aggregate_samples = spec
        .observer_generation_max_samples
        .checked_mul(u64::from(spec.max_observer_generations))
        .context("sample authority overflow")?;
    let aggregate_acquisitions = u64::from(spec.recurrence_enrollment_max_occurrences)
        .checked_mul(u64::from(spec.max_recurrence_enrollments))
        .context("acquisition authority overflow")?;
    if duration != expected_duration_g
        || duration != expected_duration_e
        || aggregate_samples != spec.max_aggregate_samples
        || aggregate_acquisitions != spec.max_aggregate_acquisitions
        || spec.sample_interval_ms < observer.min_sampling_interval_ms
        || spec.sample_interval_ms > observer.max_sampling_interval_ms
        || spec.observer_generation_duration_ms > observer.max_generation_duration_ms
        || spec.observer_generation_max_samples > observer.max_generation_samples
        || spec.acquisition_interval_ms < recurrence.min_interval_ms
        || spec.acquisition_interval_ms > recurrence.max_interval_ms
        || spec.recurrence_enrollment_duration_ms > recurrence.max_enrollment_lifetime_ms
        || spec.recurrence_enrollment_max_occurrences > recurrence.max_acquisition_occurrences
        || spec.observer_generation_duration_ms / spec.sample_interval_ms
            != spec.observer_generation_max_samples
        || spec.recurrence_enrollment_duration_ms / spec.acquisition_interval_ms
            != u64::from(spec.recurrence_enrollment_max_occurrences)
        || !spec
            .observer_generation_duration_ms
            .is_multiple_of(spec.sample_interval_ms)
        || !spec
            .recurrence_enrollment_duration_ms
            .is_multiple_of(spec.acquisition_interval_ms)
    {
        bail!(
            "operating grant is not an exact finite subset of deployment policy or its slot counts are incoherent"
        );
    }
    Ok(())
}

fn validate_materialized_grant(grant: &OperatingGrantV1) -> Result<()> {
    if grant.schema != OPERATING_GRANT_SCHEMA_V1
        || semantic_digest(&grant.observer_deployment_policy)?.as_str()
            != grant.observer_deployment_policy_id
        || semantic_digest(&grant.recurrence_deployment_policy)?.as_str()
            != grant.recurrence_deployment_policy_id
    {
        bail!("operating grant policy identity is substituted");
    }
    validate_grant_spec(
        &grant.spec,
        &grant.observer_deployment_policy,
        &grant.recurrence_deployment_policy,
        grant.created_at_unix_ms,
    )?;
    let preimage = json!({"schema": grant.schema, "spec": grant.spec,
        "observer_deployment_policy_id": grant.observer_deployment_policy_id,
        "observer_deployment_policy": grant.observer_deployment_policy,
        "recurrence_deployment_policy_id": grant.recurrence_deployment_policy_id,
        "recurrence_deployment_policy": grant.recurrence_deployment_policy,
        "created_at_unix_ms": grant.created_at_unix_ms, "issuer": grant.issuer});
    if semantic_digest(&preimage)?.as_str() != grant.grant_id {
        bail!("operating grant identity mismatch");
    }
    Ok(())
}

fn validate_generation_child(
    grant: &OperatingGrantV1,
    generation: &ObserverGenerationV1,
) -> Result<()> {
    if generation.deployment_policy_id.as_str() != grant.observer_deployment_policy_id
        || generation.observer_profile != grant.spec.observer_profile
        || generation.observer_artifact_digest.as_str() != grant.spec.observer_artifact_digest
        || generation.spec.sample_interval_ms != grant.spec.sample_interval_ms
        || generation.spec.capacity_context_id.as_str() != grant.spec.capacity_context_id
        || generation.spec.max_samples != grant.spec.observer_generation_max_samples
        || u64::try_from(generation.spec.expires_at_unix_ms - generation.spec.not_before_unix_ms)
            .unwrap_or(u64::MAX)
            != grant.spec.observer_generation_duration_ms
        || semantic_digest(&generation.spec.binding)?.as_str() != grant.spec.subject_binding_digest
        || !grant
            .spec
            .allowed_signing_key_ids
            .contains(&generation.spec.producer_key_id)
    {
        bail!("observer generation changed H-bound semantics or bounds");
    }
    Ok(())
}

fn validate_enrollment_child(
    grant: &OperatingGrantV1,
    enrollment: &RecurrenceEnrollmentV1,
) -> Result<()> {
    let watcher_declared = grant
        .recurrence_deployment_policy
        .watcher_bindings
        .iter()
        .any(|binding| {
            binding.watcher_instance_id == enrollment.spec.watcher_instance_id
                && binding.watcher_semantic_digest == enrollment.watcher_semantic_digest
                && binding.coordination_domain_id == grant.spec.coordination_domain_id
        });
    let initial_watcher = enrollment.spec.watcher_instance_id == grant.spec.watcher_instance_id
        && enrollment.watcher_semantic_digest == grant.spec.watcher_semantic_digest;
    if enrollment.spec.policy_id != grant.recurrence_deployment_policy_id
        || (!initial_watcher && !watcher_declared)
        || enrollment.coordination_domain_id != grant.spec.coordination_domain_id
        || enrollment.spec.interval_ms != grant.spec.acquisition_interval_ms
        || enrollment.spec.max_acquisition_occurrences
            != grant.spec.recurrence_enrollment_max_occurrences
        || serde_json::to_value(enrollment.spec.missed_slot_policy)?.as_str()
            != Some(grant.spec.recurrence_missed_slot_policy.as_str())
        || serde_json::to_value(enrollment.spec.startup_policy)?.as_str()
            != Some(grant.spec.recurrence_startup_policy.as_str())
        || u64::try_from(enrollment.spec.expires_at_unix_ms - enrollment.spec.anchor_unix_ms)
            .unwrap_or(u64::MAX)
            != grant.spec.recurrence_enrollment_duration_ms
    {
        bail!("recurrence enrollment changed H-bound semantics or bounds");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_child_budget(
    grant: &OperatingGrantV1,
    prior: &[ChildGrantIssuanceV1],
    kind: ChildGrantKindV1,
    next_count: u64,
    starts: i64,
    expires: i64,
    predecessor: Option<&str>,
    initial_predecessor: Option<&str>,
) -> Result<()> {
    let (max_children, max_aggregate) = match kind {
        ChildGrantKindV1::ObserverGeneration => (
            usize::from(grant.spec.max_observer_generations),
            grant.spec.max_aggregate_samples,
        ),
        ChildGrantKindV1::RecurrenceEnrollment => (
            usize::from(grant.spec.max_recurrence_enrollments),
            grant.spec.max_aggregate_acquisitions,
        ),
    };
    if prior.len() >= max_children
        || prior
            .iter()
            .map(|x| x.finite_authority_count)
            .sum::<u64>()
            .saturating_add(next_count)
            > max_aggregate
        || starts < grant.spec.not_before_unix_ms
        || expires > grant.spec.expires_at_unix_ms
        || expires <= starts
    {
        bail!("child issuance exceeds finite operating-grant bounds");
    }
    if let Some(last) = prior.last() {
        if starts != last.expires_at_unix_ms || predecessor != Some(last.child_id.as_str()) {
            bail!("successor child must use the exact exclusive predecessor boundary and identity");
        }
    } else if predecessor != initial_predecessor {
        bail!("first H child must name H's exact historical predecessor, if any");
    }
    Ok(())
}

fn generation_semantic_digest(g: &ObserverGenerationV1) -> Result<String> {
    Ok(semantic_digest(&json!({"binding": g.spec.binding, "capacity_context_id": g.spec.capacity_context_id,
        "observer_profile": g.observer_profile, "observer_artifact_digest": g.observer_artifact_digest,
        "sample_interval_ms": g.spec.sample_interval_ms, "retention_mode": g.spec.retention_mode,
        "eligibility_ms": g.spec.max_sample_eligibility_age_ms}))?.to_string())
}

fn enrollment_semantic_digest(e: &RecurrenceEnrollmentV1) -> Result<String> {
    Ok(semantic_digest(&json!({"watcher_instance_id": e.spec.watcher_instance_id,
        "watcher_semantic_digest": e.watcher_semantic_digest, "coordination_domain_id": e.coordination_domain_id,
        "policy_id": e.spec.policy_id, "interval_ms": e.spec.interval_ms,
        "missed_slot_policy": e.spec.missed_slot_policy, "startup_policy": e.spec.startup_policy,
        "failure_pause_threshold": e.spec.failure_pause_threshold}))?.to_string())
}

fn bounded(value: &str, name: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("{name} is not bounded");
    }
    Ok(())
}

fn id_component(id: &str) -> String {
    id.strip_prefix("sha256:")
        .unwrap_or(id)
        .replace(['/', ':'], "_")
}

fn write_canonical_idempotent<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = canonical_json_bytes(value)?;
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
        bail!("immutable operating-office record already exists with different bytes");
    }
    write_new(path, &bytes)
}

fn write_canonical_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_new(path, &canonical_json_bytes(value)?)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_LEDGER_DOCUMENT_BYTES {
        bail!("operating-office record exceeds bounded size");
    }
    let parent = path.parent().context("ledger record has no parent")?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o440)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de> + Serialize>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > MAX_LEDGER_DOCUMENT_BYTES {
        bail!("ledger document exceeds bounded size");
    }
    let value: T = serde_json::from_slice(&bytes)?;
    if canonical_json_bytes(&value)? != bytes {
        bail!("ledger document is not exact canonical JSON");
    }
    Ok(value)
}

fn read_dir_json<T: for<'de> Deserialize<'de> + Serialize>(dir: &Path) -> Result<Vec<T>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.extension().is_some_and(|ext| ext == "json"));
    paths.sort();
    paths.iter().map(|path| read_json(path)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_core::{PassiveProviderCustodyV1, PassiveWatcherSuccessionV1, WatcherConfig};
    use nq_passive_load_helper::{RetentionModeV1, SamplingStartupPolicyV1};
    use nq_store::recurrence::{MissedSlotPolicyV1, StartupPolicyV1};

    const HOUR: u64 = 3_600_000;

    fn observer_policy() -> OperationalPolicyV1 {
        OperationalPolicyV1 {
            schema: "nq.passive_load_operational_policy.v1".into(),
            deployment_profile_ref: "deployment:test".into(),
            min_sampling_interval_ms: 5_000,
            max_sampling_interval_ms: 20_000,
            min_timer_granularity_ms: 1_000,
            max_scheduling_jitter_ms: 1_000,
            max_generation_duration_ms: 6 * HOUR,
            max_generation_samples: 1_440,
            max_active_store_bytes: 4 * 1024 * 1024,
            min_required_free_bytes: 1024,
            max_consecutive_sample_failures: 2,
            max_sample_eligibility_age_ms: 30_000,
            max_key_overlap_ms: HOUR,
            allowed_startup_policies: BTreeSet::from([
                SamplingStartupPolicyV1::WaitForNextSampleSlot,
                SamplingStartupPolicyV1::SampleCurrentSlot,
            ]),
            allowed_retention_modes: BTreeSet::from([RetentionModeV1::RetainAll]),
        }
    }

    fn recurrence_policy() -> RecurringOfficePolicyV1 {
        RecurringOfficePolicyV1 {
            schema: "nq.recurring_office_policy.v1".into(),
            deployment_profile_ref: "deployment:test".into(),
            min_interval_ms: 60_000,
            max_interval_ms: 600_000,
            min_timer_granularity_ms: 1_000,
            max_enrollment_lifetime_ms: 6 * HOUR,
            max_acquisition_occurrences: 72,
            allowed_missed_slot_policies: BTreeSet::from([MissedSlotPolicyV1::LatestOnly]),
            allowed_startup_policies: BTreeSet::from([StartupPolicyV1::EvaluateCurrentSlot]),
            max_pre_provider_attempts: 2,
            min_pre_provider_backoff_ms: 0,
            max_pre_provider_backoff_ms: 30_000,
            max_consecutive_failure_threshold: 2,
            max_in_flight_per_watcher: 1,
            provider_timeout_ceiling_ms: 30_000,
            max_store_bytes: 64 * 1024 * 1024,
            min_free_bytes: 1024,
            allowed_acquisition_reasons: BTreeSet::from(["diagnostic_recurrence".into()]),
            coordination_domains: Vec::new(),
            watcher_bindings: Vec::new(),
        }
    }

    fn grant_spec(start: i64) -> OperatingGrantSpecV1 {
        OperatingGrantSpecV1 {
            schema: OPERATING_GRANT_SPEC_SCHEMA_V1.into(),
            operator_occurrence_id: "operator:h1".into(),
            watcher_instance_id: "passive-watcher".into(),
            watcher_semantic_digest: format!("sha256:{}", "1".repeat(64)),
            passive_provider_boundary_id: "nq.passive.load-pressure:v1".into(),
            observer_profile: "nq.host_load_passive_sampler.v1".into(),
            observer_artifact_digest: format!("sha256:{}", "2".repeat(64)),
            sample_schema: "nq.passive_host_load_sample.v1".into(),
            subject_binding_digest: format!("sha256:{}", "3".repeat(64)),
            capacity_context_id: format!("sha256:{}", "4".repeat(64)),
            sample_eligibility_profile_id: "passive-load:max-age-30s:v1".into(),
            coordination_domain_id: "passive:host".into(),
            sample_interval_ms: 15_000,
            acquisition_interval_ms: 300_000,
            recurrence_missed_slot_policy: "latest_only".into(),
            recurrence_startup_policy: "evaluate_current_slot".into(),
            allowed_signing_key_ids: BTreeSet::from(["key:1".into()]),
            observer_predecessor_generation_id: None,
            not_before_unix_ms: start,
            expires_at_unix_ms: start + i64::try_from(24 * HOUR).unwrap(),
            max_observer_generations: 4,
            max_recurrence_enrollments: 4,
            max_watcher_succession_edges: 0,
            allowed_watcher_succession_relation_ids: BTreeSet::new(),
            observer_generation_duration_ms: 6 * HOUR,
            observer_generation_max_samples: 1_440,
            recurrence_enrollment_duration_ms: 6 * HOUR,
            recurrence_enrollment_max_occurrences: 72,
            max_aggregate_samples: 5_760,
            max_aggregate_acquisitions: 288,
            observer_renewal_lead_ms: 900_000,
            recurrence_renewal_lead_slots: 2,
        }
    }

    fn activation_spec(grant_id: &str) -> OfficeActivationSpecV1 {
        OfficeActivationSpecV1 {
            schema: OFFICE_ACTIVATION_SPEC_SCHEMA_V1.into(),
            operation_id: "stage:1".into(),
            grant_id: grant_id.into(),
            generation_id: format!("sha256:{}", "5".repeat(64)),
            generation_path: PathBuf::from("/tmp/generation.json"),
            enrollment_id: format!("sha256:{}", "6".repeat(64)),
            watcher_instance_id: "passive-watcher".into(),
            watcher_semantic_digest: format!("sha256:{}", "1".repeat(64)),
            admission_id: "admission:1".into(),
            genesis_acquisition_id: "genesis:1".into(),
            provider_config_path: PathBuf::from("/tmp/provider.json"),
            provider_config_digest: format!("sha256:{}", "7".repeat(64)),
            passive_provider_boundary_id: "nq.passive.load-pressure:v1".into(),
            sample_store: PathBuf::from("/tmp/samples"),
            capacity_context_id: format!("sha256:{}", "4".repeat(64)),
            service_manager_deployment_path: PathBuf::from(
                "/etc/systemd/system/nq-recurring-office.service",
            ),
            service_manager_deployment_digest: format!("sha256:{}", "8".repeat(64)),
        }
    }

    fn generation(
        grant: &OperatingGrantV1,
        start: i64,
        previous: Option<String>,
        suffix: &str,
    ) -> ObserverGenerationV1 {
        let binding = serde_json::from_value(json!({
            "subject": "host:test",
            "scope": {"kind": "host", "value": {"id": "test"}},
            "vantage": {"kind": "local", "value": {}}
        }))
        .unwrap();
        ObserverGenerationV1 {
            schema: "nq.passive_load_observer_generation.v1".into(),
            deployment_policy_id: Sha256Digest::parse(grant.observer_deployment_policy_id.clone())
                .unwrap(),
            deployment_policy: grant.observer_deployment_policy.clone(),
            observer_profile: grant.spec.observer_profile.clone(),
            observer_artifact_digest: Sha256Digest::parse(
                grant.spec.observer_artifact_digest.clone(),
            )
            .unwrap(),
            spec: nq_passive_load_helper::ObserverGenerationSpecV1 {
                schema: "nq.passive_load_observer_generation_spec.v1".into(),
                operator_occurrence_id: format!("generation:{suffix}"),
                previous_generation_id: previous,
                sample_store: PathBuf::from(format!("/tmp/samples-{suffix}")),
                binding,
                sampling_anchor_unix_ms: start,
                sample_interval_ms: grant.spec.sample_interval_ms,
                startup_policy: SamplingStartupPolicyV1::SampleCurrentSlot,
                created_at_unix_ms: start,
                not_before_unix_ms: start,
                expires_at_unix_ms: start + i64::try_from(6 * HOUR).unwrap(),
                max_samples: 1_440,
                max_store_bytes: 4 * 1024 * 1024,
                min_free_bytes: 1024,
                failure_pause_threshold: 2,
                retention_mode: RetentionModeV1::RetainAll,
                max_sample_eligibility_age_ms: 30_000,
                private_key_path: PathBuf::from("/tmp/key"),
                producer_issuer: "observer:test".into(),
                producer_key_id: "key:1".into(),
                producer_public_key_hex: "00".repeat(32),
                key_not_before_unix_ms: start,
                key_retire_at_unix_ms: start + i64::try_from(6 * HOUR).unwrap(),
                capacity_context_id: Sha256Digest::parse(grant.spec.capacity_context_id.clone())
                    .unwrap(),
            },
        }
    }

    fn enrollment(grant: &OperatingGrantV1, start: i64, suffix: char) -> RecurrenceEnrollmentV1 {
        RecurrenceEnrollmentV1 {
            schema: "nq.recurrence_enrollment.v1".into(),
            enrollment_id: format!("sha256:{}", suffix.to_string().repeat(64)),
            spec: nq_store::recurrence::RecurrenceEnrollmentSpecV1 {
                schema: "nq.recurrence_enrollment_spec.v1".into(),
                operator_occurrence_id: format!("enrollment:{suffix}"),
                policy_id: grant.recurrence_deployment_policy_id.clone(),
                watcher_instance_id: grant.spec.watcher_instance_id.clone(),
                anchor_unix_ms: start,
                interval_ms: 300_000,
                max_acquisition_occurrences: 72,
                expires_at_unix_ms: start + i64::try_from(6 * HOUR).unwrap(),
                missed_slot_policy: MissedSlotPolicyV1::LatestOnly,
                startup_policy: StartupPolicyV1::EvaluateCurrentSlot,
                max_pre_provider_attempts: 2,
                pre_provider_backoff_ms: 1_000,
                failure_pause_threshold: 2,
                requested_domain_concurrency: 1,
                acquisition_reason: "diagnostic_recurrence".into(),
            },
            watcher_semantic_digest: grant.spec.watcher_semantic_digest.clone(),
            coordination_domain_id: grant.spec.coordination_domain_id.clone(),
            first_eligible_slot: 0,
            created_at_unix_ms: start,
        }
    }

    fn succession_watchers() -> (WatcherConfig, WatcherConfig, PassiveWatcherSuccessionV1) {
        fn watcher(instance: &str, generation: char) -> WatcherConfig {
            serde_json::from_value(json!({
                "instance_id": instance,
                "command": {"executable": "/opt/nq/passive", "args": ["serve-stdio",
                    format!("/etc/nq/provider-{generation}.toml")], "env": {},
                    "execution_account": "nq", "working_directory": "/var/empty"},
                "profile": {"id": "nq.host", "version": 1},
                "subject": "host:test",
                "scope": {"kind": "host", "value": {"id": "test"}},
                "vantage": {"kind": "local", "value": {}},
                "capability_ceiling": ["read_procfs", "read_system_info"],
                "passive_host_load_sample": {
                    "schema": "nq.passive_host_load_provider_config.v1",
                    "max_sample_age_ms": 30000,
                    "observer_profile": "nq.host_load_passive_sampler.v1",
                    "observer_artifact_digest": format!("sha256:{}", "2".repeat(64)),
                    "observer_config_digest": format!("sha256:{}", generation.to_string().repeat(64)),
                    "producer_issuer": "observer:test", "producer_key_id": "key:1",
                    "producer_public_key_hex": "00".repeat(32),
                    "capacity_context_id": format!("sha256:{}", "4".repeat(64))
                }
            })).unwrap()
        }
        fn custody(watcher: &WatcherConfig, generation: char) -> PassiveProviderCustodyV1 {
            let passive = watcher.passive_host_load_sample.as_ref().unwrap();
            PassiveProviderCustodyV1 {
                provider_config_path: PathBuf::from(format!("/etc/nq/provider-{generation}.toml")),
                provider_config_digest: format!("sha256:{}", generation.to_string().repeat(64)),
                sample_store: PathBuf::from(format!("/tmp/samples-{generation}")),
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
        let predecessor = watcher("passive-watcher-g1", '1');
        let successor = watcher("passive-watcher-g2", '2');
        let relation = PassiveWatcherSuccessionV1::new(
            predecessor.clone(),
            successor.clone(),
            custody(&predecessor, '1'),
            custody(&successor, '2'),
            "operator:succession".into(),
            1_000,
        )
        .unwrap();
        (predecessor, successor, relation)
    }

    #[test]
    fn timer_is_inert_until_armed_and_closeout_is_terminal() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let grant = OperatingGrantV1::new(
            grant_spec(2_000),
            observer_policy(),
            recurrence_policy(),
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
        ledger.create_grant(&grant).unwrap();
        ledger
            .activate_grant(&grant.grant_id, "activate:1", 2_000)
            .unwrap();
        let activation = ledger
            .stage_activation(activation_spec(&grant.grant_id), 2_000)
            .unwrap();
        assert!(matches!(
            ledger.tick_gate(&activation.activation_id, 2_000).unwrap(),
            TickGateV1::Inert {
                attempts_consumed: 0,
                ..
            }
        ));
        ledger
            .mark_validated(
                &activation.activation_id,
                "validate:1",
                2_001,
                json!({"prerequisites": "ready"}),
            )
            .unwrap();
        assert!(matches!(
            ledger.tick_gate(&activation.activation_id, 2_001).unwrap(),
            TickGateV1::Inert {
                state: ActivationStateV1::Validated,
                attempts_consumed: 0,
                ..
            }
        ));
        ledger
            .arm(&activation.activation_id, "arm:1", 2_002)
            .unwrap();
        assert!(matches!(
            ledger.tick_gate(&activation.activation_id, 2_002).unwrap(),
            TickGateV1::Exposed { .. }
        ));
        ledger
            .close_activation(
                &activation.activation_id,
                "close:1",
                2_003,
                "bounded test close",
            )
            .unwrap();
        assert!(matches!(
            ledger.tick_gate(&activation.activation_id, 2_003).unwrap(),
            TickGateV1::Inert {
                state: ActivationStateV1::Closed,
                attempts_consumed: 0,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_grant_creation_converges_on_first_exact_operator_occurrence() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let first = OperatingGrantV1::new(
            grant_spec(2_000),
            observer_policy(),
            recurrence_policy(),
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
        let duplicate = OperatingGrantV1::new(
            grant_spec(2_000),
            observer_policy(),
            recurrence_policy(),
            1_001,
            json!({"operator": "test"}),
        )
        .unwrap();
        assert_ne!(first.grant_id, duplicate.grant_id);
        assert_eq!(ledger.create_grant(&first).unwrap(), first.grant_id);
        assert_eq!(ledger.create_grant(&duplicate).unwrap(), first.grant_id);
        assert_eq!(
            read_dir_json::<OperatingGrantV1>(&root.path().join("grants"))
                .unwrap()
                .len(),
            1
        );

        let mut drifted_spec = grant_spec(2_000);
        drifted_spec.observer_renewal_lead_ms += 1;
        let drifted = OperatingGrantV1::new(
            drifted_spec,
            observer_policy(),
            recurrence_policy(),
            1_002,
            json!({"operator": "test"}),
        )
        .unwrap();
        assert!(ledger.create_grant(&drifted).is_err());
    }

    #[test]
    fn expiry_and_retirement_make_armed_tick_inert_without_reopening() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let grant = OperatingGrantV1::new(
            grant_spec(2_000),
            observer_policy(),
            recurrence_policy(),
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
        ledger.create_grant(&grant).unwrap();
        ledger
            .activate_grant(&grant.grant_id, "activate:1", 2_000)
            .unwrap();
        let activation = ledger
            .stage_activation(activation_spec(&grant.grant_id), 2_000)
            .unwrap();
        ledger
            .mark_validated(&activation.activation_id, "validate:1", 2_001, json!({}))
            .unwrap();
        ledger
            .arm(&activation.activation_id, "arm:1", 2_002)
            .unwrap();
        ledger
            .retire_grant(&grant.grant_id, "retire:1", 2_003, "operator close")
            .unwrap();
        assert!(
            matches!(ledger.tick_gate(&activation.activation_id, 2_004).unwrap(),
            TickGateV1::Inert { reason, .. } if reason == "retired")
        );
        assert!(
            !ledger
                .grant_status(&grant.grant_id, grant.spec.expires_at_unix_ms)
                .unwrap()
                .active
        );
    }

    #[test]
    fn candidate_profile_has_exact_exclusive_slot_counts() {
        let spec = grant_spec(2_000);
        assert_eq!(
            spec.observer_generation_duration_ms / spec.sample_interval_ms,
            1_440
        );
        assert_eq!(
            spec.recurrence_enrollment_duration_ms / spec.acquisition_interval_ms,
            72
        );
        assert_eq!(spec.max_aggregate_samples, 4 * 1_440);
        assert_eq!(spec.max_aggregate_acquisitions, 4 * 72);
        OperatingGrantV1::new(
            spec,
            observer_policy(),
            recurrence_policy(),
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ordinary_g_and_e_children_consume_finite_h_budgets_append_only() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let mut spec = grant_spec(2_000);
        let binding: nq_protocol::SubjectBinding = serde_json::from_value(json!({
            "subject": "host:test", "scope": {"kind": "host", "value": {"id": "test"}},
            "vantage": {"kind": "local", "value": {}}
        }))
        .unwrap();
        spec.subject_binding_digest = semantic_digest(&binding).unwrap().to_string();
        let grant = OperatingGrantV1::new(
            spec,
            observer_policy(),
            recurrence_policy(),
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
        ledger.create_grant(&grant).unwrap();
        ledger
            .activate_grant(&grant.grant_id, "activate:1", 2_000)
            .unwrap();

        let g1 = generation(&grant, 2_000, None, "g1");
        let g1_id = semantic_digest(&g1).unwrap().to_string();
        let first = ledger
            .issue_generation(&grant.grant_id, &g1, &g1_id, "issue:g1", 2_001)
            .unwrap();
        assert_eq!(first.finite_authority_count, 1_440);
        assert_eq!(
            ledger
                .issue_generation(&grant.grant_id, &g1, &g1_id, "issue:g1", 2_001)
                .unwrap(),
            first
        );
        let g2 = generation(
            &grant,
            g1.spec.expires_at_unix_ms,
            Some(g1_id.clone()),
            "g2",
        );
        let g2_id = semantic_digest(&g2).unwrap().to_string();
        ledger
            .issue_generation(&grant.grant_id, &g2, &g2_id, "issue:g2", 2_002)
            .unwrap();
        let g3 = generation(
            &grant,
            g2.spec.expires_at_unix_ms,
            Some(g2_id.clone()),
            "g3",
        );
        let g3_id = semantic_digest(&g3).unwrap().to_string();
        ledger
            .issue_generation(&grant.grant_id, &g3, &g3_id, "issue:g3", 2_002)
            .unwrap();
        let g4 = generation(&grant, g3.spec.expires_at_unix_ms, Some(g3_id), "g4");
        let g4_id = semantic_digest(&g4).unwrap().to_string();
        ledger
            .issue_generation(&grant.grant_id, &g4, &g4_id, "issue:g4", 2_002)
            .unwrap();

        let e1 = enrollment(&grant, 2_000, 'a');
        ledger
            .issue_enrollment(&grant.grant_id, &e1, "issue:e1", 2_003)
            .unwrap();
        let e2 = enrollment(&grant, e1.spec.expires_at_unix_ms, 'b');
        ledger
            .issue_enrollment(&grant.grant_id, &e2, "issue:e2", 2_004)
            .unwrap();
        let e3 = enrollment(&grant, e2.spec.expires_at_unix_ms, 'c');
        ledger
            .issue_enrollment(&grant.grant_id, &e3, "issue:e3", 2_004)
            .unwrap();
        let e4 = enrollment(&grant, e3.spec.expires_at_unix_ms, 'd');
        ledger
            .issue_enrollment(&grant.grant_id, &e4, "issue:e4", 2_004)
            .unwrap();
        let status = ledger.grant_status(&grant.grant_id, 2_005).unwrap();
        assert!(!status.active);
        assert_eq!(
            status.terminal_reason.as_deref(),
            Some("child_budgets_exhausted")
        );
        assert!(
            ledger
                .grant_permits_issued_child_runtime(&grant.grant_id, 2_005)
                .unwrap()
        );
        let activation = ledger
            .stage_activation(activation_spec(&grant.grant_id), 2_005)
            .unwrap();
        ledger
            .mark_validated(
                &activation.activation_id,
                "validate:exhausted",
                2_005,
                json!({}),
            )
            .unwrap();
        ledger
            .arm(&activation.activation_id, "arm:exhausted", 2_005)
            .unwrap();
        assert!(matches!(
            ledger.tick_gate(&activation.activation_id, 2_005).unwrap(),
            TickGateV1::Exposed { .. }
        ));
        assert_eq!(status.observer_generations_issued, 4);
        assert_eq!(status.recurrence_enrollments_issued, 4);
        assert_eq!(status.aggregate_samples_issued, 5_760);
        assert_eq!(status.aggregate_acquisitions_issued, 288);

        let mut drift = g2.clone();
        drift.spec.sample_interval_ms = 10_000;
        let drift_id = semantic_digest(&drift).unwrap().to_string();
        assert!(
            ledger
                .issue_generation(&grant.grant_id, &drift, &drift_id, "issue:drift", 2_005)
                .is_err()
        );
    }

    #[test]
    fn unsafe_or_incoherent_h_bounds_refuse() {
        let mut spec = grant_spec(2_000);
        spec.max_aggregate_samples += 1;
        assert!(
            OperatingGrantV1::new(
                spec,
                observer_policy(),
                recurrence_policy(),
                1_000,
                json!({"operator": "test"})
            )
            .is_err()
        );
        let mut spec = grant_spec(2_000);
        spec.expires_at_unix_ms += 1;
        assert!(
            OperatingGrantV1::new(
                spec,
                observer_policy(),
                recurrence_policy(),
                1_000,
                json!({"operator": "test"})
            )
            .is_err()
        );
    }

    #[test]
    fn first_h_generation_may_bind_exact_history_without_importing_child_authority() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let mut spec = grant_spec(2_000);
        let binding: nq_protocol::SubjectBinding = serde_json::from_value(json!({
            "subject": "host:test", "scope": {"kind": "host", "value": {"id": "test"}},
            "vantage": {"kind": "local", "value": {}}
        }))
        .unwrap();
        spec.subject_binding_digest = semantic_digest(&binding).unwrap().to_string();
        spec.observer_predecessor_generation_id = Some(format!("sha256:{}", "9".repeat(64)));
        let grant = OperatingGrantV1::new(
            spec,
            observer_policy(),
            recurrence_policy(),
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
        ledger.create_grant(&grant).unwrap();
        ledger
            .activate_grant(&grant.grant_id, "activate", 2_000)
            .unwrap();
        let first = generation(
            &grant,
            2_000,
            grant.spec.observer_predecessor_generation_id.clone(),
            "g1",
        );
        let first_id = semantic_digest(&first).unwrap().to_string();
        ledger
            .issue_generation(&grant.grant_id, &first, &first_id, "issue:first", 2_001)
            .unwrap();
        let status = ledger.grant_status(&grant.grant_id, 2_002).unwrap();
        assert_eq!(status.observer_generations_issued, 1);
        assert_eq!(status.aggregate_samples_issued, 1_440);
    }

    #[test]
    fn finite_h_edge_authorizes_distinct_successor_enrollment_without_identity_equivalence() {
        use nq_store::recurrence::WatcherCoordinationBindingV1;
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let (predecessor, successor, relation) = succession_watchers();
        let predecessor_digest = semantic_digest(&predecessor).unwrap().to_string();
        let successor_digest = semantic_digest(&successor).unwrap().to_string();
        assert_ne!(predecessor_digest, successor_digest);

        let mut spec = grant_spec(2_000);
        spec.watcher_instance_id = predecessor.instance_id.clone();
        spec.watcher_semantic_digest = predecessor_digest;
        spec.max_watcher_succession_edges = 1;
        spec.allowed_watcher_succession_relation_ids =
            BTreeSet::from([relation.relation_id.clone()]);
        let mut recurrence = recurrence_policy();
        recurrence
            .watcher_bindings
            .push(WatcherCoordinationBindingV1 {
                watcher_instance_id: successor.instance_id.clone(),
                watcher_semantic_digest: successor_digest.clone(),
                coordination_domain_id: spec.coordination_domain_id.clone(),
                origin_profile: "nq.substrate_origin.linode_instance_metadata.v1".into(),
                expected_instance_id_sha256: "1".repeat(64),
                origin_helper_path: "/opt/nq/origin".into(),
                origin_helper_sha256: "2".repeat(64),
                origin_helper_account: "nq-origin".into(),
                origin_helper_public_key_path: "/etc/nq/origin.pub".into(),
                origin_helper_issuer: "origin:test".into(),
                origin_helper_key_id: "origin-key:test".into(),
            });
        let grant = OperatingGrantV1::new(
            spec,
            observer_policy(),
            recurrence,
            1_000,
            json!({"operator": "test"}),
        )
        .unwrap();
        ledger.create_grant(&grant).unwrap();
        ledger
            .activate_grant(&grant.grant_id, "activate", 2_000)
            .unwrap();
        ledger
            .issue_watcher_succession(&grant.grant_id, &relation, 2_001)
            .unwrap();
        assert!(
            ledger
                .watcher_digest_is_authorized(
                    &grant.grant_id,
                    &successor.instance_id,
                    &successor_digest
                )
                .unwrap()
        );
        let status = ledger.grant_status(&grant.grant_id, 2_002).unwrap();
        assert_eq!(status.watcher_succession_edges_issued, 1);
        assert_eq!(status.watcher_succession_edges_remaining, 0);

        let mut successor_enrollment = enrollment(&grant, 2_000, 'b');
        successor_enrollment.spec.watcher_instance_id = successor.instance_id;
        successor_enrollment.watcher_semantic_digest = successor_digest;
        ledger
            .issue_enrollment(
                &grant.grant_id,
                &successor_enrollment,
                "issue:successor-e",
                2_003,
            )
            .unwrap();
        let mut drift = relation.clone();
        drift.successor.subject = "host:other".into();
        drift.relation_id = semantic_digest(&(
            drift.schema.as_str(),
            &drift.predecessor,
            &drift.successor,
            &drift.predecessor_custody,
            &drift.successor_custody,
            &drift.deltas,
            &drift.operator_occurrence_id,
            drift.created_at_unix_ms,
        ))
        .unwrap()
        .to_string();
        assert!(
            ledger
                .issue_watcher_succession(&grant.grant_id, &drift, 2_004)
                .is_err()
        );
    }

    #[allow(clippy::too_many_lines)]
    fn handoff_fixture(
        ledger: &OperatingLedger,
        start: i64,
    ) -> (
        OperatingGrantV1,
        OfficeActivationV1,
        OfficeActivationV1,
        SuccessorHandoffSpecV1,
    ) {
        use nq_store::recurrence::WatcherCoordinationBindingV1;

        let observer = observer_policy();
        let recurrence_base = recurrence_policy();
        let provisional = OperatingGrantV1::new(
            grant_spec(start),
            observer.clone(),
            recurrence_base.clone(),
            start - 1,
            json!({"operator": "provisional"}),
        )
        .unwrap();
        let g1 = generation(&provisional, start, None, "1");
        let g1_id = semantic_digest(&g1).unwrap().to_string();
        let g2 = generation(
            &provisional,
            start + i64::try_from(6 * HOUR).unwrap(),
            Some(g1_id.clone()),
            "2",
        );
        let g2_id = semantic_digest(&g2).unwrap().to_string();

        let (mut predecessor, mut successor, _) = succession_watchers();
        predecessor
            .passive_host_load_sample
            .as_mut()
            .unwrap()
            .observer_config_digest
            .clone_from(&g1_id);
        successor
            .passive_host_load_sample
            .as_mut()
            .unwrap()
            .observer_config_digest
            .clone_from(&g2_id);
        let predecessor_custody = PassiveProviderCustodyV1 {
            provider_config_path: PathBuf::from("/etc/nq/provider-1.toml"),
            provider_config_digest: format!("sha256:{}", "1".repeat(64)),
            sample_store: PathBuf::from("/tmp/samples-1"),
            max_sample_age_ms: 30_000,
            observer_profile: "nq.host_load_passive_sampler.v1".into(),
            observer_artifact_digest: format!("sha256:{}", "2".repeat(64)),
            observer_config_digest: g1_id.clone(),
            producer_issuer: "observer:test".into(),
            producer_key_id: "key:1".into(),
            producer_public_key_hex: "00".repeat(32),
            capacity_context_id: format!("sha256:{}", "4".repeat(64)),
        };
        let mut successor_custody = predecessor_custody.clone();
        successor_custody.provider_config_path = PathBuf::from("/etc/nq/provider-2.toml");
        successor_custody.provider_config_digest = format!("sha256:{}", "2".repeat(64));
        successor_custody.sample_store = PathBuf::from("/tmp/samples-2");
        successor_custody.observer_config_digest = g2_id.clone();
        let relation = PassiveWatcherSuccessionV1::new(
            predecessor.clone(),
            successor.clone(),
            predecessor_custody,
            successor_custody,
            "operator:handoff-relation".into(),
            start - 1,
        )
        .unwrap();

        let predecessor_digest = semantic_digest(&predecessor).unwrap().to_string();
        let successor_digest = semantic_digest(&successor).unwrap().to_string();
        let mut spec = grant_spec(start);
        spec.watcher_instance_id = predecessor.instance_id.clone();
        spec.watcher_semantic_digest = predecessor_digest.clone();
        spec.max_watcher_succession_edges = 1;
        spec.allowed_watcher_succession_relation_ids =
            BTreeSet::from([relation.relation_id.clone()]);
        let binding = g1.spec.binding.clone();
        spec.subject_binding_digest = semantic_digest(&binding).unwrap().to_string();
        let mut recurrence = recurrence_base;
        for (watcher, digest) in [
            (&predecessor, predecessor_digest.clone()),
            (&successor, successor_digest.clone()),
        ] {
            recurrence
                .watcher_bindings
                .push(WatcherCoordinationBindingV1 {
                    watcher_instance_id: watcher.instance_id.clone(),
                    watcher_semantic_digest: digest,
                    coordination_domain_id: spec.coordination_domain_id.clone(),
                    origin_profile: "linode_instance_metadata_v1".into(),
                    expected_instance_id_sha256: format!("sha256:{}", "a".repeat(64)),
                    origin_helper_path: "/opt/nq/origin".into(),
                    origin_helper_sha256: format!("sha256:{}", "b".repeat(64)),
                    origin_helper_account: "nq-origin".into(),
                    origin_helper_public_key_path: "/etc/nq/origin.pub".into(),
                    origin_helper_issuer: "origin:test".into(),
                    origin_helper_key_id: "origin-key:test".into(),
                });
        }
        let grant = OperatingGrantV1::new(
            spec,
            observer,
            recurrence,
            start - 1,
            json!({"operator": "test"}),
        )
        .unwrap();
        ledger.create_grant(&grant).unwrap();
        ledger
            .activate_grant(&grant.grant_id, "activate:handoff", start)
            .unwrap();
        ledger
            .issue_watcher_succession(&grant.grant_id, &relation, start)
            .unwrap();
        ledger
            .issue_generation(&grant.grant_id, &g1, &g1_id, "issue:g1", start)
            .unwrap();
        ledger
            .issue_generation(&grant.grant_id, &g2, &g2_id, "issue:g2", start)
            .unwrap();
        let e1 = enrollment(&grant, start, 'a');
        let mut e2 = enrollment(&grant, start + i64::try_from(6 * HOUR).unwrap(), 'b');
        e2.spec.watcher_instance_id = successor.instance_id.clone();
        e2.watcher_semantic_digest = successor_digest.clone();
        ledger
            .issue_enrollment(&grant.grant_id, &e1, "issue:e1", start)
            .unwrap();
        ledger
            .issue_enrollment(&grant.grant_id, &e2, "issue:e2", start)
            .unwrap();

        let mut a1_spec = activation_spec(&grant.grant_id);
        a1_spec.operation_id = "stage:a1".into();
        a1_spec.generation_id = g1_id;
        a1_spec.generation_path = PathBuf::from("/tmp/g1.json");
        a1_spec.enrollment_id = e1.enrollment_id;
        a1_spec.watcher_instance_id = predecessor.instance_id;
        a1_spec.watcher_semantic_digest = predecessor_digest;
        a1_spec.provider_config_path = PathBuf::from("/etc/nq/provider-1.toml");
        a1_spec.provider_config_digest = format!("sha256:{}", "1".repeat(64));
        a1_spec.sample_store = PathBuf::from("/tmp/samples-1");
        let a1 = ledger.stage_activation(a1_spec, start).unwrap();
        ledger
            .mark_validated(&a1.activation_id, "validate:a1", start, json!({}))
            .unwrap();
        ledger.arm(&a1.activation_id, "arm:a1", start).unwrap();

        let admission_id = "4dbead7e-b1a9-4d20-9890-cf16b6c7dfa1";
        let mut a2_spec = activation_spec(&grant.grant_id);
        a2_spec.operation_id = "stage:a2".into();
        a2_spec.generation_id = g2_id.clone();
        a2_spec.generation_path = PathBuf::from("/tmp/g2.json");
        a2_spec.enrollment_id = e2.enrollment_id.clone();
        a2_spec.watcher_instance_id = successor.instance_id.clone();
        a2_spec.watcher_semantic_digest = successor_digest.clone();
        a2_spec.admission_id = admission_id.into();
        a2_spec.genesis_acquisition_id = "genesis:g2".into();
        a2_spec.provider_config_path = PathBuf::from("/etc/nq/provider-2.toml");
        a2_spec.provider_config_digest = format!("sha256:{}", "2".repeat(64));
        a2_spec.sample_store = PathBuf::from("/tmp/samples-2");
        let a2 = ledger.stage_activation(a2_spec, start).unwrap();
        let handoff = SuccessorHandoffSpecV1 {
            schema: SUCCESSOR_HANDOFF_SPEC_SCHEMA_V1.into(),
            operation_id: "stage:handoff".into(),
            grant_id: grant.grant_id.clone(),
            succession_relation_id: relation.relation_id,
            predecessor_activation_id: a1.activation_id.clone(),
            next_generation_id: g2_id,
            next_generation_path: PathBuf::from("/tmp/g2.json"),
            successor_watcher_instance_id: successor.instance_id,
            successor_watcher_semantic_digest: successor_digest,
            expected_admission_id: admission_id.into(),
            genesis_acquisition_id: "genesis:g2".into(),
            expected_instance_id_sha256: format!("sha256:{}", "a".repeat(64)),
            origin_helper_path: PathBuf::from("/opt/nq/origin"),
            origin_helper_sha256: format!("sha256:{}", "b".repeat(64)),
            origin_helper_account: "nq-origin".into(),
            origin_helper_public_key_path: PathBuf::from("/etc/nq/origin.pub"),
            next_enrollment_id: e2.enrollment_id,
            next_activation_id: a2.activation_id.clone(),
        };
        (grant, a1, a2, handoff)
    }

    #[test]
    fn exact_handoff_is_restart_safe_inert_until_arm_and_closes_predecessor_first() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let (grant, predecessor, successor, spec) = handoff_fixture(&ledger, 2_000);
        let handoff = ledger.stage_successor_handoff(spec.clone(), 2_001).unwrap();
        assert_eq!(
            ledger
                .stage_successor_handoff(spec, 2_002)
                .unwrap()
                .handoff_id,
            handoff.handoff_id
        );
        assert!(matches!(
            ledger.tick_gate(&successor.activation_id, 2_002).unwrap(),
            TickGateV1::Inert {
                attempts_consumed: 0,
                ..
            }
        ));
        assert!(matches!(
            ledger.grant_tick_gate(&grant.grant_id, 2_002).unwrap(),
            GrantTickGateV1::Exposed { activation_id, .. }
                if activation_id == predecessor.activation_id
        ));
        assert!(
            ledger
                .advance_handoff(
                    &handoff.handoff_id,
                    SuccessorHandoffStateV1::GenesisStarted,
                    "skip",
                    2_002,
                    json!({})
                )
                .is_err()
        );
        for (state, operation) in [
            (SuccessorHandoffStateV1::WaitingForSample, "wait:1"),
            (SuccessorHandoffStateV1::SampleReady, "sample:1"),
            (SuccessorHandoffStateV1::AdmissionStarted, "admit:start"),
            (SuccessorHandoffStateV1::AdmissionCompleted, "admit:done"),
            (SuccessorHandoffStateV1::GenesisStarted, "genesis:start"),
            (SuccessorHandoffStateV1::GenesisCompleted, "genesis:done"),
        ] {
            ledger
                .advance_handoff(&handoff.handoff_id, state, operation, 2_003, json!({}))
                .unwrap();
        }
        ledger
            .mark_validated(&successor.activation_id, "validate:a2", 2_004, json!({}))
            .unwrap();
        ledger
            .advance_handoff(
                &handoff.handoff_id,
                SuccessorHandoffStateV1::Validated,
                "handoff:validated",
                2_004,
                json!({}),
            )
            .unwrap();
        ledger
            .arm_successor_handoff(&handoff.handoff_id, "handoff:arm", 2_005)
            .unwrap();
        assert_eq!(
            ledger
                .activation_status(&predecessor.activation_id)
                .unwrap()
                .state,
            ActivationStateV1::Closed
        );
        assert_eq!(
            ledger
                .activation_status(&successor.activation_id)
                .unwrap()
                .state,
            ActivationStateV1::Armed
        );
        assert_eq!(
            ledger.handoff_status(&handoff.handoff_id).unwrap().state,
            SuccessorHandoffStateV1::Armed
        );
        assert!(matches!(
            ledger.grant_tick_gate(&grant.grant_id, 2_006).unwrap(),
            GrantTickGateV1::Exposed { activation_id, .. }
                if activation_id == successor.activation_id
        ));
    }

    #[test]
    fn handoff_substitution_and_semantic_refusal_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let (_grant, _predecessor, successor, mut spec) = handoff_fixture(&ledger, 2_000);
        let exact = spec.clone();
        spec.next_activation_id = successor.activation_id.clone();
        spec.successor_watcher_instance_id = "substituted-watcher".into();
        assert!(ledger.stage_successor_handoff(spec, 2_001).is_err());
        let handoff = ledger.stage_successor_handoff(exact, 2_001).unwrap();
        ledger
            .advance_handoff(
                &handoff.handoff_id,
                SuccessorHandoffStateV1::SampleReady,
                "sample",
                2_002,
                json!({}),
            )
            .unwrap();
        ledger
            .advance_handoff(
                &handoff.handoff_id,
                SuccessorHandoffStateV1::AdmissionStarted,
                "admit:start",
                2_002,
                json!({}),
            )
            .unwrap();
        ledger
            .advance_handoff(
                &handoff.handoff_id,
                SuccessorHandoffStateV1::AdmissionRefused,
                "admit:refused",
                2_003,
                json!({"human_required": true}),
            )
            .unwrap();
        assert!(
            ledger
                .advance_handoff(
                    &handoff.handoff_id,
                    SuccessorHandoffStateV1::AdmissionCompleted,
                    "admit:retry",
                    2_004,
                    json!({})
                )
                .is_err()
        );
        let status = ledger.handoff_status(&handoff.handoff_id).unwrap();
        assert!(status.human_required);
        assert_eq!(status.timer_exposure, "inert");
    }

    #[test]
    fn handoff_duplicate_delivery_and_crash_terminal_cuts_converge() {
        for terminal in [
            SuccessorHandoffStateV1::OutcomeUnknown,
            SuccessorHandoffStateV1::AdmissionRefused,
        ] {
            let root = tempfile::tempdir().unwrap();
            let ledger = OperatingLedger::open(root.path()).unwrap();
            let (_grant, _predecessor, _successor, spec) = handoff_fixture(&ledger, 2_000);
            let handoff = ledger.stage_successor_handoff(spec, 2_001).unwrap();
            let first = ledger
                .advance_handoff(
                    &handoff.handoff_id,
                    SuccessorHandoffStateV1::SampleReady,
                    "sample:duplicate",
                    2_002,
                    json!({"sample": "exact"}),
                )
                .unwrap();
            let duplicate = ledger
                .advance_handoff(
                    &handoff.handoff_id,
                    SuccessorHandoffStateV1::SampleReady,
                    "sample:duplicate",
                    2_002,
                    json!({"sample": "exact"}),
                )
                .unwrap();
            assert_eq!(first, duplicate);
            ledger
                .advance_handoff(
                    &handoff.handoff_id,
                    SuccessorHandoffStateV1::AdmissionStarted,
                    "admission:start",
                    2_003,
                    json!({}),
                )
                .unwrap();
            ledger
                .advance_handoff(
                    &handoff.handoff_id,
                    terminal,
                    "admission:terminal",
                    2_004,
                    json!({"human_required": true}),
                )
                .unwrap();
            assert_eq!(
                ledger.handoff_status(&handoff.handoff_id).unwrap().state,
                terminal
            );
            assert!(
                ledger
                    .advance_handoff(
                        &handoff.handoff_id,
                        SuccessorHandoffStateV1::AdmissionCompleted,
                        "admission:late",
                        2_005,
                        json!({})
                    )
                    .is_err()
            );
        }

        let root = tempfile::tempdir().unwrap();
        let ledger = OperatingLedger::open(root.path()).unwrap();
        let (_grant, _predecessor, _successor, spec) = handoff_fixture(&ledger, 2_000);
        let handoff = ledger.stage_successor_handoff(spec, 2_001).unwrap();
        for (state, operation) in [
            (SuccessorHandoffStateV1::SampleReady, "sample"),
            (SuccessorHandoffStateV1::AdmissionStarted, "admission:start"),
            (
                SuccessorHandoffStateV1::AdmissionCompleted,
                "admission:done",
            ),
            (SuccessorHandoffStateV1::GenesisStarted, "genesis:start"),
            (SuccessorHandoffStateV1::OutcomeUnknown, "genesis:unknown"),
        ] {
            ledger
                .advance_handoff(&handoff.handoff_id, state, operation, 2_003, json!({}))
                .unwrap();
        }
        assert_eq!(
            ledger.handoff_status(&handoff.handoff_id).unwrap().state,
            SuccessorHandoffStateV1::OutcomeUnknown
        );
    }

    #[test]
    fn schema_has_no_infinite_or_recursive_authority_field() {
        let fields = serde_json::to_value(OperatingGrantSpecV1 {
            schema: OPERATING_GRANT_SPEC_SCHEMA_V1.into(),
            operator_occurrence_id: "op".into(),
            watcher_instance_id: "w".into(),
            watcher_semantic_digest: "sha256:x".into(),
            passive_provider_boundary_id: "p".into(),
            observer_profile: "o".into(),
            observer_artifact_digest: "sha256:a".into(),
            sample_schema: "s".into(),
            subject_binding_digest: "sha256:b".into(),
            capacity_context_id: "sha256:c".into(),
            sample_eligibility_profile_id: "e".into(),
            coordination_domain_id: "d".into(),
            sample_interval_ms: 15_000,
            acquisition_interval_ms: 300_000,
            recurrence_missed_slot_policy: "latestonly".into(),
            recurrence_startup_policy: "evaluatecurrentslot".into(),
            allowed_signing_key_ids: BTreeSet::from(["k".into()]),
            observer_predecessor_generation_id: None,
            not_before_unix_ms: 1,
            expires_at_unix_ms: 2,
            max_observer_generations: 1,
            max_recurrence_enrollments: 1,
            max_watcher_succession_edges: 0,
            allowed_watcher_succession_relation_ids: BTreeSet::new(),
            observer_generation_duration_ms: 1,
            observer_generation_max_samples: 1,
            recurrence_enrollment_duration_ms: 1,
            recurrence_enrollment_max_occurrences: 1,
            max_aggregate_samples: 1,
            max_aggregate_acquisitions: 1,
            observer_renewal_lead_ms: 1,
            recurrence_renewal_lead_slots: 1,
        })
        .unwrap();
        let text = fields.to_string();
        assert!(!text.contains("infinite"));
        assert!(!text.contains("successor_operating_grant"));
    }
}
