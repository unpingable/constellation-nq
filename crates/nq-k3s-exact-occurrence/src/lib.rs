//! TURNSTILE's pure exact-occurrence preparation and transition law.
//!
//! This crate grants no authority and invokes no execution substrate. It binds
//! one NQ occurrence to immutable work, origin/capacity facts, custody, and a
//! closed transition history that AG and Docket may independently govern.

use std::collections::BTreeMap;

/// Immutable OCI identity and external evidence-custody law.
pub mod artifact_evidence;
/// Mechanics-separated exact execute/reconcile boundary.
pub mod executor;
/// Portable Kubernetes origin and capacity fact law.
pub mod origin_capacity;

use nq_protocol::{CanonicalizationError, Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Human campaign name retained in every TURNSTILE plan.
pub const CAMPAIGN_NAME: &str = "TURNSTILE";
/// Canonical campaign slug retained in every TURNSTILE plan.
pub const CAMPAIGN_SLUG: &str = "k3s-ag-exact-occurrence-adapter-v1";
/// Immutable prepared-plan schema.
pub const PREPARED_PLAN_SCHEMA_V1: &str = "nq.k3s_exact_occurrence_execution_plan.v1";
/// Content-bound prepared-occurrence wrapper schema.
pub const PREPARED_OCCURRENCE_SCHEMA_V1: &str = "nq.k3s_prepared_exact_occurrence.v1";
/// Docket executor work schema selected by TURNSTILE.
pub const EXECUTOR_WORK_SCHEMA_V1: &str = "nq.k3s_exact_occurrence_work.v1";
/// Largest exactly representable unsigned integer in I-JSON.
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_CONFIG_BINDINGS: usize = 256;

/// Failure to construct or advance an exact occurrence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OccurrenceError {
    /// A closed schema or campaign identity was changed.
    #[error("closed identity mismatch: {0}")]
    ClosedIdentity(&'static str),
    /// A bounded textual identity was malformed.
    #[error("invalid bounded identity: {0}")]
    InvalidIdentity(&'static str),
    /// A plan violated a semantic invariant.
    #[error("invalid plan: {0}")]
    InvalidPlan(&'static str),
    /// A transition was requested from the wrong durable state.
    #[error("invalid transition from {state} to {requested}")]
    InvalidTransition {
        /// Current durable state.
        state: &'static str,
        /// Requested transition.
        requested: &'static str,
    },
    /// A replay reused an identity with different exact content.
    #[error("replay substituted {0}")]
    ReplayConflict(&'static str),
    /// A consequence-time transition occurred outside the immutable lifetime.
    #[error("prepared occurrence is outside its exact lifetime")]
    OutsideLifetime,
    /// Canonical identity construction failed.
    #[error("canonical identity failure: {0}")]
    Canonical(String),
}

impl From<CanonicalizationError> for OccurrenceError {
    fn from(value: CanonicalizationError) -> Self {
        Self::Canonical(value.to_string())
    }
}

fn validate_token(value: &str, field: &'static str) -> Result<(), OccurrenceError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(OccurrenceError::InvalidIdentity(field));
    }
    Ok(())
}

fn validate_git_commit(value: &str) -> Result<(), OccurrenceError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OccurrenceError::InvalidIdentity("source commit"));
    }
    Ok(())
}

/// Exact NQ authority and recurrence graph selected before AG evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqAuthorityBindingV1 {
    /// Content-derived exact NQ occurrence/acquisition identity.
    pub occurrence_id: Sha256Digest,
    /// Finite H identity.
    pub h_grant_id: String,
    /// Finite observer-generation G identity.
    pub g_grant_id: String,
    /// Finite recurrence-enrollment E identity.
    pub e_grant_id: String,
    /// Exact watcher instance.
    pub watcher_id: String,
    /// Exact watcher admission.
    pub admission_id: String,
    /// Exact recurrence enrollment.
    pub enrollment_id: Sha256Digest,
    /// Optional predecessor-to-successor relation used by this occurrence.
    pub succession_relation_id: Option<Sha256Digest>,
    /// Deterministic recurrence slot.
    pub recurrence_slot: u64,
    /// Exact selected canonical sample.
    pub selected_sample_id: Sha256Digest,
    /// Immutable selected-sample document digest.
    pub selected_sample_digest: Sha256Digest,
}

impl NqAuthorityBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        for (value, field) in [
            (&self.h_grant_id, "H grant"),
            (&self.g_grant_id, "G grant"),
            (&self.e_grant_id, "E grant"),
            (&self.watcher_id, "watcher"),
            (&self.admission_id, "admission"),
        ] {
            validate_token(value, field)?;
        }
        if self.recurrence_slot > MAX_SAFE_JSON_INTEGER {
            return Err(OccurrenceError::InvalidPlan(
                "recurrence slot exceeds I-JSON",
            ));
        }
        Ok(())
    }
}

/// Immutable executable, OCI, helper, and configuration identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBindingV1 {
    /// Exact qualified NQ source commit.
    pub source_commit: String,
    /// Immutable OCI manifest-list or image-manifest digest.
    pub oci_manifest_digest: Sha256Digest,
    /// Exact NQ executable digest inside that image.
    pub nq_executable_digest: Sha256Digest,
    /// Exact passive helper digest inside that image.
    pub passive_helper_digest: Sha256Digest,
    /// Content identities for every authority-relevant configuration object.
    pub configuration_digests: BTreeMap<String, Sha256Digest>,
}

impl ArtifactBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        validate_git_commit(&self.source_commit)?;
        if self.configuration_digests.is_empty()
            || self.configuration_digests.len() > MAX_CONFIG_BINDINGS
        {
            return Err(OccurrenceError::InvalidPlan(
                "configuration binding cardinality",
            ));
        }
        for key in self.configuration_digests.keys() {
            validate_token(key, "configuration name")?;
        }
        Ok(())
    }
}

/// Portable origin, placement, and capacity fact identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginCapacityBindingV1 {
    /// Versioned origin profile whose semantics are evaluated by NQ.
    pub origin_profile: String,
    /// Exact subject identity.
    pub subject: Sha256Digest,
    /// Exact scope identity.
    pub scope: Sha256Digest,
    /// Exact vantage identity.
    pub vantage: Sha256Digest,
    /// Cluster identity obtained from a separately qualified fact source.
    pub cluster: Sha256Digest,
    /// Namespace UID, not merely a namespace name.
    pub namespace_uid: Sha256Digest,
    /// Service-account UID, not merely a service-account name.
    pub service_account_uid: Sha256Digest,
    /// Exact admitted placement constraints.
    pub placement_digest: Sha256Digest,
    /// Exact resource requests, limits, and runtime-class facts.
    pub resource_envelope_digest: Sha256Digest,
    /// Reconstructible effective CPU/memory/cgroup capacity facts.
    pub capacity_context_digest: Sha256Digest,
}

impl OriginCapacityBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        validate_token(&self.origin_profile, "origin profile")
    }
}

/// Coordination domain and provider-spacing bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationBindingV1 {
    /// Exact NQ coordination domain.
    pub domain_id: String,
    /// Expected provider fencing epoch allocated by NQ preparation.
    pub fencing_epoch: u64,
    /// Minimum provider-safe spacing carried into consequence-time recheck.
    pub provider_safe_spacing_ms: u64,
}

impl CoordinationBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        validate_token(&self.domain_id, "coordination domain")?;
        if self.fencing_epoch == 0
            || self.fencing_epoch > MAX_SAFE_JSON_INTEGER
            || self.provider_safe_spacing_ms > MAX_SAFE_JSON_INTEGER
        {
            return Err(OccurrenceError::InvalidPlan("coordination bound"));
        }
        Ok(())
    }
}

/// External canonical and append-only evidence destinations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBindingV1 {
    /// Persistent NQ retain-all custody identity.
    pub canonical_custody_id: Sha256Digest,
    /// Immutable bounded-selection manifest contract identity.
    pub selection_contract_digest: Sha256Digest,
    /// External adapter journal identity.
    pub external_journal_id: Sha256Digest,
    /// External terminal receipt destination identity.
    pub receipt_destination_id: Sha256Digest,
    /// Required free bytes before occurrence claim.
    pub required_free_bytes: u64,
    /// Closed retention mode; V1 accepts only `retain_all`.
    pub retention_mode: String,
}

impl EvidenceBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        if self.retention_mode != "retain_all" {
            return Err(OccurrenceError::InvalidPlan(
                "retention mode is not retain_all",
            ));
        }
        if self.required_free_bytes == 0 || self.required_free_bytes > MAX_SAFE_JSON_INTEGER {
            return Err(OccurrenceError::InvalidPlan("free-space guard"));
        }
        Ok(())
    }
}

/// Exact preparation and execution lifetime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifetimeBindingV1 {
    /// Inclusive earliest authorization time.
    pub not_before_unix_ms: u64,
    /// Exclusive preparation expiry.
    pub expires_at_unix_ms: u64,
    /// Maximum runtime duration after execution begins.
    pub max_runtime_ms: u64,
}

impl LifetimeBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        if self.not_before_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms > MAX_SAFE_JSON_INTEGER
            || self.max_runtime_ms == 0
            || self.max_runtime_ms > MAX_SAFE_JSON_INTEGER
        {
            return Err(OccurrenceError::InvalidPlan("lifetime"));
        }
        Ok(())
    }

    fn contains(&self, at_unix_ms: u64) -> bool {
        (self.not_before_unix_ms..self.expires_at_unix_ms).contains(&at_unix_ms)
    }
}

/// Closed exact-occurrence cardinality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardinalityBindingV1 {
    /// Maximum AG authorization spends represented by this plan.
    pub max_authorizations: u8,
    /// Maximum Docket attempts represented by this plan.
    pub max_docket_attempts: u8,
    /// Maximum runtime instances represented by this plan.
    pub max_runtime_instances: u8,
    /// Maximum terminal results represented by this plan.
    pub max_terminal_results: u8,
}

impl CardinalityBindingV1 {
    fn validate(&self) -> Result<(), OccurrenceError> {
        if self.max_authorizations != 1
            || self.max_docket_attempts != 1
            || self.max_runtime_instances != 1
            || self.max_terminal_results != 1
        {
            return Err(OccurrenceError::InvalidPlan(
                "V1 cardinality must be exactly one",
            ));
        }
        Ok(())
    }
}

/// Immutable content whose digest is AG's exact work identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOccurrencePlanV1 {
    /// Closed schema.
    pub schema: String,
    /// Required campaign name.
    pub campaign: String,
    /// Required campaign slug.
    pub campaign_slug: String,
    /// Executor work schema expected in Docket dispatch.
    pub work_schema: String,
    /// NQ occurrence and authority graph.
    pub nq: NqAuthorityBindingV1,
    /// Artifact and configuration identities.
    pub artifact: ArtifactBindingV1,
    /// Origin, placement, and capacity facts.
    pub origin_capacity: OriginCapacityBindingV1,
    /// Coordination domain and fencing facts.
    pub coordination: CoordinationBindingV1,
    /// Durable evidence destinations.
    pub evidence: EvidenceBindingV1,
    /// Exact preparation/runtime lifetime.
    pub lifetime: LifetimeBindingV1,
    /// Exact one-occurrence cardinality.
    pub cardinality: CardinalityBindingV1,
}

impl PreparedOccurrencePlanV1 {
    /// Validates the closed immutable plan.
    ///
    /// # Errors
    ///
    /// Returns [`OccurrenceError`] for any changed schema, malformed identity,
    /// unsafe lifetime, widened cardinality, or unsupported evidence law.
    pub fn validate(&self) -> Result<(), OccurrenceError> {
        if self.schema != PREPARED_PLAN_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("prepared plan schema"));
        }
        if self.campaign != CAMPAIGN_NAME {
            return Err(OccurrenceError::ClosedIdentity("campaign name"));
        }
        if self.campaign_slug != CAMPAIGN_SLUG {
            return Err(OccurrenceError::ClosedIdentity("campaign slug"));
        }
        if self.work_schema != EXECUTOR_WORK_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("work schema"));
        }
        self.nq.validate()?;
        self.artifact.validate()?;
        self.origin_capacity.validate()?;
        self.coordination.validate()?;
        self.evidence.validate()?;
        self.lifetime.validate()?;
        self.cardinality.validate()
    }
}

/// Content-bound prepared object. Possession creates no authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOccurrenceV1 {
    /// Closed wrapper schema.
    pub schema: String,
    /// JCS SHA-256 identity of `plan`.
    pub plan_id: Sha256Digest,
    /// Exact immutable plan.
    pub plan: PreparedOccurrencePlanV1,
}

impl PreparedOccurrenceV1 {
    /// Constructs one content-bound prepared object.
    ///
    /// # Errors
    ///
    /// Returns [`OccurrenceError`] if plan validation or canonical identity
    /// construction fails.
    pub fn new(plan: PreparedOccurrencePlanV1) -> Result<Self, OccurrenceError> {
        plan.validate()?;
        let plan_id = semantic_digest(&plan)?;
        Ok(Self {
            schema: PREPARED_OCCURRENCE_SCHEMA_V1.to_owned(),
            plan_id,
            plan,
        })
    }

    /// Revalidates wrapper identity and exact plan content.
    ///
    /// # Errors
    ///
    /// Returns [`OccurrenceError`] for schema or content substitution.
    pub fn validate(&self) -> Result<(), OccurrenceError> {
        if self.schema != PREPARED_OCCURRENCE_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity(
                "prepared occurrence schema",
            ));
        }
        self.plan.validate()?;
        if semantic_digest(&self.plan)? != self.plan_id {
            return Err(OccurrenceError::ReplayConflict("prepared plan content"));
        }
        Ok(())
    }
}

/// Exact spent-AG and Docket-attempt binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationBindingV1 {
    /// AG campaign identity.
    pub ag_campaign: Sha256Digest,
    /// AG occurrence identity.
    pub ag_occurrence: Sha256Digest,
    /// Exact signed issuance identity.
    pub ag_issuance: Sha256Digest,
    /// AG work digest; must equal the prepared plan identity.
    pub ag_work: Sha256Digest,
    /// Docket attempt identity.
    pub docket_attempt: Sha256Digest,
    /// Docket executor marker.
    pub docket_marker: Sha256Digest,
    /// Exact work schema repeated by Docket.
    pub work_schema: String,
    /// Subject repeated by Docket.
    pub subject: Sha256Digest,
    /// Scope repeated by Docket.
    pub scope: Sha256Digest,
    /// Time at which Docket custody made the occurrence executable.
    pub authorized_at_unix_ms: u64,
}

/// Exact coordination claim retained before mechanics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBindingV1 {
    /// Content-derived claim record identity.
    pub claim_id: Sha256Digest,
    /// Exact NQ occurrence.
    pub nq_occurrence: Sha256Digest,
    /// Exact prepared plan.
    pub plan_id: Sha256Digest,
    /// Exact Docket attempt.
    pub docket_attempt: Sha256Digest,
    /// Exact Docket marker.
    pub docket_marker: Sha256Digest,
    /// Exact NQ fencing epoch.
    pub fencing_epoch: u64,
    /// Consequence-time selected sample identity.
    pub selected_sample_id: Sha256Digest,
    /// Consequence-time claim timestamp.
    pub claimed_at_unix_ms: u64,
}

/// One runtime instance selected only after exact claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingV1 {
    /// Substrate-assigned runtime identity.
    pub runtime_instance_id: Sha256Digest,
    /// Exact artifact identity observed at launch.
    pub oci_manifest_digest: Sha256Digest,
    /// Exact execution-plan identity observed at launch.
    pub plan_id: Sha256Digest,
    /// Time mechanics began.
    pub started_at_unix_ms: u64,
}

/// Definite terminal result class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalClassV1 {
    /// Exact qualified effect completed.
    Success,
    /// Exact qualified evidence proves a terminal failure.
    Failure,
    /// Exact pre-effect evidence proves a terminal refusal.
    Refused,
}

/// Exact definite terminal evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalBindingV1 {
    /// Definite outcome class.
    pub class: TerminalClassV1,
    /// External immutable mechanics/NQ receipt.
    pub receipt: Sha256Digest,
    /// Final external evidence-chain head.
    pub evidence_head: Sha256Digest,
    /// Terminal time.
    pub terminal_at_unix_ms: u64,
}

/// Exact evidence establishing that no definite result is knowable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeUnknownBindingV1 {
    /// Immutable uncertainty evidence.
    pub evidence: Sha256Digest,
    /// Final external evidence-chain head.
    pub evidence_head: Sha256Digest,
    /// Time uncertainty became terminal.
    pub terminal_at_unix_ms: u64,
}

/// Durable exact-occurrence state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OccurrenceStateV1 {
    /// Prepared content exists but has no AG/Docket authorization.
    Prepared,
    /// One exact AG issuance and Docket attempt are bound.
    Authorized {
        /// Exact authorization binding.
        authorization: AuthorizationBindingV1,
    },
    /// NQ coordination/sample/provider boundary is claimed durably.
    Claimed {
        /// Exact authorization binding.
        authorization: AuthorizationBindingV1,
        /// Exact claim binding.
        claim: ClaimBindingV1,
    },
    /// One runtime instance may be executing.
    Executing {
        /// Exact authorization binding.
        authorization: AuthorizationBindingV1,
        /// Exact claim binding.
        claim: ClaimBindingV1,
        /// Exact runtime instance.
        runtime: RuntimeBindingV1,
    },
    /// One definite terminal result is retained.
    Terminal {
        /// Exact authorization binding.
        authorization: AuthorizationBindingV1,
        /// Exact claim binding.
        claim: ClaimBindingV1,
        /// Optional runtime when refusal occurred before mechanics.
        runtime: Option<RuntimeBindingV1>,
        /// Definite result.
        terminal: TerminalBindingV1,
    },
    /// Exact outcome cannot be established; replay and replacement stay fenced.
    OutcomeUnknown {
        /// Exact authorization binding.
        authorization: AuthorizationBindingV1,
        /// Exact claim binding.
        claim: ClaimBindingV1,
        /// Optional last known runtime identity.
        runtime: Option<RuntimeBindingV1>,
        /// Uncertainty evidence.
        unknown: OutcomeUnknownBindingV1,
    },
}

impl OccurrenceStateV1 {
    /// Stable state label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Authorized { .. } => "authorized",
            Self::Claimed { .. } => "claimed",
            Self::Executing { .. } => "executing",
            Self::Terminal { .. } => "terminal",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
        }
    }
}

/// Whether a transition appended a new fact or accepted an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionEffectV1 {
    /// A new durable transition was applied.
    Applied,
    /// Exact replay converged without another semantic occurrence.
    IdempotentReplay,
}

/// Pure TURNSTILE state machine. It performs no I/O and grants no authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactOccurrenceMachineV1 {
    /// Immutable prepared object.
    pub prepared: PreparedOccurrenceV1,
    /// Current durable state retaining all predecessor bindings.
    pub state: OccurrenceStateV1,
}

impl ExactOccurrenceMachineV1 {
    /// Opens a new authority-empty prepared object.
    ///
    /// # Errors
    ///
    /// Returns [`OccurrenceError`] if the prepared object is invalid.
    pub fn prepare(prepared: PreparedOccurrenceV1) -> Result<Self, OccurrenceError> {
        prepared.validate()?;
        Ok(Self {
            prepared,
            state: OccurrenceStateV1::Prepared,
        })
    }

    /// Reopens and validates serialized state without advancing it.
    ///
    /// # Errors
    ///
    /// Returns [`OccurrenceError`] if any retained transition binding conflicts.
    pub fn reopen(
        prepared: PreparedOccurrenceV1,
        state: OccurrenceStateV1,
    ) -> Result<Self, OccurrenceError> {
        let machine = Self { prepared, state };
        machine.validate_state()?;
        Ok(machine)
    }

    /// Binds one spent AG issuance and one Docket attempt.
    ///
    /// # Errors
    ///
    /// Refuses substitution, replay conflict, expiry, or transition from a
    /// terminally different history.
    pub fn authorize(
        &mut self,
        binding: AuthorizationBindingV1,
    ) -> Result<TransitionEffectV1, OccurrenceError> {
        self.validate_authorization(&binding)?;
        if let Some(existing) = self.authorization() {
            return if existing == &binding {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("authorization"))
            };
        }
        if !matches!(self.state, OccurrenceStateV1::Prepared) {
            return Err(self.invalid_transition("authorized"));
        }
        self.state = OccurrenceStateV1::Authorized {
            authorization: binding,
        };
        Ok(TransitionEffectV1::Applied)
    }

    /// Claims the exact NQ occurrence and fencing epoch before mechanics.
    ///
    /// # Errors
    ///
    /// Refuses a substituted dispatch, sample, epoch, lifetime, or second claim.
    pub fn claim(&mut self, claim: ClaimBindingV1) -> Result<TransitionEffectV1, OccurrenceError> {
        self.validate_claim(&claim)?;
        if let Some(existing) = self.claim_binding() {
            return if existing == &claim {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("claim"))
            };
        }
        let OccurrenceStateV1::Authorized { authorization } = &self.state else {
            return Err(self.invalid_transition("claimed"));
        };
        self.state = OccurrenceStateV1::Claimed {
            authorization: authorization.clone(),
            claim,
        };
        Ok(TransitionEffectV1::Applied)
    }

    /// Records the sole permitted runtime instance.
    ///
    /// # Errors
    ///
    /// Refuses artifact/plan substitution, expiry, a second runtime, or a
    /// runtime created before durable claim.
    pub fn begin_execution(
        &mut self,
        runtime: RuntimeBindingV1,
    ) -> Result<TransitionEffectV1, OccurrenceError> {
        self.validate_runtime(&runtime)?;
        if let Some(existing) = self.runtime_binding() {
            return if existing == &runtime {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("runtime instance"))
            };
        }
        let OccurrenceStateV1::Claimed {
            authorization,
            claim,
        } = &self.state
        else {
            return Err(self.invalid_transition("executing"));
        };
        self.state = OccurrenceStateV1::Executing {
            authorization: authorization.clone(),
            claim: claim.clone(),
            runtime,
        };
        Ok(TransitionEffectV1::Applied)
    }

    /// Records one definite terminal result.
    ///
    /// # Errors
    ///
    /// Refuses a second or substituted terminal result and success before a
    /// runtime instance was retained.
    pub fn finish(
        &mut self,
        terminal: TerminalBindingV1,
    ) -> Result<TransitionEffectV1, OccurrenceError> {
        if let Some(existing) = self.terminal_binding() {
            return if existing == &terminal {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("terminal result"))
            };
        }
        let (authorization, claim, runtime) = match &self.state {
            OccurrenceStateV1::Claimed {
                authorization,
                claim,
            } if terminal.class == TerminalClassV1::Refused => {
                (authorization.clone(), claim.clone(), None)
            }
            OccurrenceStateV1::Executing {
                authorization,
                claim,
                runtime,
            } => (authorization.clone(), claim.clone(), Some(runtime.clone())),
            _ => return Err(self.invalid_transition("terminal")),
        };
        self.validate_terminal_time(terminal.terminal_at_unix_ms, runtime.as_ref())?;
        self.state = OccurrenceStateV1::Terminal {
            authorization,
            claim,
            runtime,
            terminal,
        };
        Ok(TransitionEffectV1::Applied)
    }

    /// Closes a claimed or executing occurrence as outcome unknown.
    ///
    /// # Errors
    ///
    /// Refuses a second/substituted result or uncertainty before claim.
    pub fn mark_outcome_unknown(
        &mut self,
        unknown: OutcomeUnknownBindingV1,
    ) -> Result<TransitionEffectV1, OccurrenceError> {
        if let Some(existing) = self.unknown_binding() {
            return if existing == &unknown {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("outcome-unknown result"))
            };
        }
        let (authorization, claim, runtime) = match &self.state {
            OccurrenceStateV1::Claimed {
                authorization,
                claim,
            } => (authorization.clone(), claim.clone(), None),
            OccurrenceStateV1::Executing {
                authorization,
                claim,
                runtime,
            } => (authorization.clone(), claim.clone(), Some(runtime.clone())),
            _ => return Err(self.invalid_transition("outcome_unknown")),
        };
        self.validate_terminal_time(unknown.terminal_at_unix_ms, runtime.as_ref())?;
        self.state = OccurrenceStateV1::OutcomeUnknown {
            authorization,
            claim,
            runtime,
            unknown,
        };
        Ok(TransitionEffectV1::Applied)
    }

    /// Settles an outcome-unknown occurrence from later exact read-only evidence.
    ///
    /// This transition never permits another execution. It only replaces an
    /// uncertainty projection with a definite result for the same retained
    /// authorization, claim, and optional runtime identity.
    ///
    /// # Errors
    ///
    /// Refuses unless the current state is `outcome_unknown`, or when a
    /// terminal replay substitutes retained exact evidence.
    pub fn settle_outcome_unknown(
        &mut self,
        terminal: TerminalBindingV1,
    ) -> Result<TransitionEffectV1, OccurrenceError> {
        if let Some(existing) = self.terminal_binding() {
            return if existing == &terminal {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("terminal result"))
            };
        }
        let OccurrenceStateV1::OutcomeUnknown {
            authorization,
            claim,
            runtime,
            ..
        } = &self.state
        else {
            return Err(self.invalid_transition("terminal_from_reconciliation"));
        };
        if terminal.class != TerminalClassV1::Refused && runtime.is_none() {
            return Err(OccurrenceError::InvalidPlan(
                "reconciled terminal effect lacks runtime",
            ));
        }
        self.validate_terminal_time(terminal.terminal_at_unix_ms, runtime.as_ref())?;
        self.state = OccurrenceStateV1::Terminal {
            authorization: authorization.clone(),
            claim: claim.clone(),
            runtime: runtime.clone(),
            terminal,
        };
        Ok(TransitionEffectV1::Applied)
    }

    fn validate_state(&self) -> Result<(), OccurrenceError> {
        self.prepared.validate()?;
        if let Some(authorization) = self.authorization() {
            self.validate_authorization(authorization)?;
        }
        if let Some(claim) = self.claim_binding() {
            self.validate_claim(claim)?;
        }
        if let Some(runtime) = self.runtime_binding() {
            self.validate_runtime(runtime)?;
        }
        if let Some(terminal) = self.terminal_binding() {
            self.validate_terminal_time(terminal.terminal_at_unix_ms, self.runtime_binding())?;
            if terminal.class != TerminalClassV1::Refused && self.runtime_binding().is_none() {
                return Err(OccurrenceError::InvalidPlan(
                    "terminal effect lacks runtime",
                ));
            }
        }
        if let Some(unknown) = self.unknown_binding() {
            self.validate_terminal_time(unknown.terminal_at_unix_ms, self.runtime_binding())?;
        }
        Ok(())
    }

    fn validate_authorization(
        &self,
        binding: &AuthorizationBindingV1,
    ) -> Result<(), OccurrenceError> {
        if binding.ag_work != self.prepared.plan_id
            || binding.work_schema != self.prepared.plan.work_schema
            || binding.subject != self.prepared.plan.origin_capacity.subject
            || binding.scope != self.prepared.plan.origin_capacity.scope
        {
            return Err(OccurrenceError::ReplayConflict("AG/Docket work binding"));
        }
        if !self
            .prepared
            .plan
            .lifetime
            .contains(binding.authorized_at_unix_ms)
        {
            return Err(OccurrenceError::OutsideLifetime);
        }
        Ok(())
    }

    fn validate_claim(&self, claim: &ClaimBindingV1) -> Result<(), OccurrenceError> {
        let authorization = self
            .authorization()
            .ok_or_else(|| self.invalid_transition("claimed"))?;
        if claim.nq_occurrence != self.prepared.plan.nq.occurrence_id
            || claim.plan_id != self.prepared.plan_id
            || claim.docket_attempt != authorization.docket_attempt
            || claim.docket_marker != authorization.docket_marker
            || claim.fencing_epoch != self.prepared.plan.coordination.fencing_epoch
            || claim.selected_sample_id != self.prepared.plan.nq.selected_sample_id
        {
            return Err(OccurrenceError::ReplayConflict("claim binding"));
        }
        if !self
            .prepared
            .plan
            .lifetime
            .contains(claim.claimed_at_unix_ms)
            || claim.claimed_at_unix_ms < authorization.authorized_at_unix_ms
        {
            return Err(OccurrenceError::OutsideLifetime);
        }
        Ok(())
    }

    fn validate_runtime(&self, runtime: &RuntimeBindingV1) -> Result<(), OccurrenceError> {
        let claim = self
            .claim_binding()
            .ok_or_else(|| self.invalid_transition("executing"))?;
        if runtime.plan_id != self.prepared.plan_id
            || runtime.oci_manifest_digest != self.prepared.plan.artifact.oci_manifest_digest
        {
            return Err(OccurrenceError::ReplayConflict("runtime binding"));
        }
        if !self
            .prepared
            .plan
            .lifetime
            .contains(runtime.started_at_unix_ms)
            || runtime.started_at_unix_ms < claim.claimed_at_unix_ms
        {
            return Err(OccurrenceError::OutsideLifetime);
        }
        Ok(())
    }

    fn validate_terminal_time(
        &self,
        terminal_at_unix_ms: u64,
        runtime: Option<&RuntimeBindingV1>,
    ) -> Result<(), OccurrenceError> {
        let claim = self
            .claim_binding()
            .ok_or_else(|| self.invalid_transition("terminal"))?;
        let lower = runtime.map_or(claim.claimed_at_unix_ms, |value| value.started_at_unix_ms);
        let latest = runtime
            .map(|value| {
                value
                    .started_at_unix_ms
                    .saturating_add(self.prepared.plan.lifetime.max_runtime_ms)
            })
            .unwrap_or(self.prepared.plan.lifetime.expires_at_unix_ms);
        if terminal_at_unix_ms < lower || terminal_at_unix_ms > latest {
            return Err(OccurrenceError::OutsideLifetime);
        }
        Ok(())
    }

    fn authorization(&self) -> Option<&AuthorizationBindingV1> {
        match &self.state {
            OccurrenceStateV1::Prepared => None,
            OccurrenceStateV1::Authorized { authorization }
            | OccurrenceStateV1::Claimed { authorization, .. }
            | OccurrenceStateV1::Executing { authorization, .. }
            | OccurrenceStateV1::Terminal { authorization, .. }
            | OccurrenceStateV1::OutcomeUnknown { authorization, .. } => Some(authorization),
        }
    }

    fn claim_binding(&self) -> Option<&ClaimBindingV1> {
        match &self.state {
            OccurrenceStateV1::Claimed { claim, .. }
            | OccurrenceStateV1::Executing { claim, .. }
            | OccurrenceStateV1::Terminal { claim, .. }
            | OccurrenceStateV1::OutcomeUnknown { claim, .. } => Some(claim),
            OccurrenceStateV1::Prepared | OccurrenceStateV1::Authorized { .. } => None,
        }
    }

    fn runtime_binding(&self) -> Option<&RuntimeBindingV1> {
        match &self.state {
            OccurrenceStateV1::Executing { runtime, .. } => Some(runtime),
            OccurrenceStateV1::Terminal { runtime, .. }
            | OccurrenceStateV1::OutcomeUnknown { runtime, .. } => runtime.as_ref(),
            OccurrenceStateV1::Prepared
            | OccurrenceStateV1::Authorized { .. }
            | OccurrenceStateV1::Claimed { .. } => None,
        }
    }

    fn terminal_binding(&self) -> Option<&TerminalBindingV1> {
        match &self.state {
            OccurrenceStateV1::Terminal { terminal, .. } => Some(terminal),
            _ => None,
        }
    }

    fn unknown_binding(&self) -> Option<&OutcomeUnknownBindingV1> {
        match &self.state {
            OccurrenceStateV1::OutcomeUnknown { unknown, .. } => Some(unknown),
            _ => None,
        }
    }

    fn invalid_transition(&self, requested: &'static str) -> OccurrenceError {
        OccurrenceError::InvalidTransition {
            state: self.state.label(),
            requested,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        nq_protocol::sha256_bytes(label.as_bytes())
    }

    fn plan() -> PreparedOccurrencePlanV1 {
        PreparedOccurrencePlanV1 {
            schema: PREPARED_PLAN_SCHEMA_V1.to_owned(),
            campaign: CAMPAIGN_NAME.to_owned(),
            campaign_slug: CAMPAIGN_SLUG.to_owned(),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            nq: NqAuthorityBindingV1 {
                occurrence_id: digest("nq-occurrence"),
                h_grant_id: "turnstile-h-1".to_owned(),
                g_grant_id: "turnstile-g-1".to_owned(),
                e_grant_id: "turnstile-e-1".to_owned(),
                watcher_id: "turnstile-watcher-1".to_owned(),
                admission_id: "turnstile-admission-1".to_owned(),
                enrollment_id: digest("enrollment"),
                succession_relation_id: None,
                recurrence_slot: 7,
                selected_sample_id: digest("sample"),
                selected_sample_digest: digest("sample-doc"),
            },
            artifact: ArtifactBindingV1 {
                source_commit: "675e247e85d8e2e1f2801c06445bf863f82b3a5b".to_owned(),
                oci_manifest_digest: digest("oci"),
                nq_executable_digest: digest("nq"),
                passive_helper_digest: digest("helper"),
                configuration_digests: BTreeMap::from([("nq.toml".to_owned(), digest("config"))]),
            },
            origin_capacity: OriginCapacityBindingV1 {
                origin_profile: "nq.kubernetes.pod-origin/v1".to_owned(),
                subject: digest("subject"),
                scope: digest("scope"),
                vantage: digest("vantage"),
                cluster: digest("cluster"),
                namespace_uid: digest("namespace"),
                service_account_uid: digest("service-account"),
                placement_digest: digest("placement"),
                resource_envelope_digest: digest("resources"),
                capacity_context_digest: digest("capacity"),
            },
            coordination: CoordinationBindingV1 {
                domain_id: "turnstile:cluster:subject".to_owned(),
                fencing_epoch: 1,
                provider_safe_spacing_ms: 30_000,
            },
            evidence: EvidenceBindingV1 {
                canonical_custody_id: digest("custody"),
                selection_contract_digest: digest("selection-contract"),
                external_journal_id: digest("journal"),
                receipt_destination_id: digest("receipts"),
                required_free_bytes: 10 * 1024 * 1024 * 1024,
                retention_mode: "retain_all".to_owned(),
            },
            lifetime: LifetimeBindingV1 {
                not_before_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
                max_runtime_ms: 500,
            },
            cardinality: CardinalityBindingV1 {
                max_authorizations: 1,
                max_docket_attempts: 1,
                max_runtime_instances: 1,
                max_terminal_results: 1,
            },
        }
    }

    fn authorization(prepared: &PreparedOccurrenceV1) -> AuthorizationBindingV1 {
        AuthorizationBindingV1 {
            ag_campaign: digest("ag-campaign"),
            ag_occurrence: digest("ag-occurrence"),
            ag_issuance: digest("ag-issuance"),
            ag_work: prepared.plan_id.clone(),
            docket_attempt: digest("docket-attempt"),
            docket_marker: digest("docket-marker"),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            subject: prepared.plan.origin_capacity.subject.clone(),
            scope: prepared.plan.origin_capacity.scope.clone(),
            authorized_at_unix_ms: 1_100,
        }
    }

    fn claim(prepared: &PreparedOccurrenceV1, auth: &AuthorizationBindingV1) -> ClaimBindingV1 {
        ClaimBindingV1 {
            claim_id: digest("claim"),
            nq_occurrence: prepared.plan.nq.occurrence_id.clone(),
            plan_id: prepared.plan_id.clone(),
            docket_attempt: auth.docket_attempt.clone(),
            docket_marker: auth.docket_marker.clone(),
            fencing_epoch: prepared.plan.coordination.fencing_epoch,
            selected_sample_id: prepared.plan.nq.selected_sample_id.clone(),
            claimed_at_unix_ms: 1_200,
        }
    }

    fn runtime(prepared: &PreparedOccurrenceV1) -> RuntimeBindingV1 {
        RuntimeBindingV1 {
            runtime_instance_id: digest("runtime"),
            oci_manifest_digest: prepared.plan.artifact.oci_manifest_digest.clone(),
            plan_id: prepared.plan_id.clone(),
            started_at_unix_ms: 1_300,
        }
    }

    #[test]
    fn content_mutation_changes_plan_identity_and_stale_wrapper_refuses() {
        let prepared = PreparedOccurrenceV1::new(plan()).unwrap();
        let mut changed = prepared.clone();
        changed.plan.nq.recurrence_slot += 1;
        assert_ne!(semantic_digest(&changed.plan).unwrap(), prepared.plan_id);
        assert!(matches!(
            changed.validate(),
            Err(OccurrenceError::ReplayConflict("prepared plan content"))
        ));
    }

    #[test]
    fn exact_authorized_claimed_executing_terminal_path_is_single_use() {
        let prepared = PreparedOccurrenceV1::new(plan()).unwrap();
        let auth = authorization(&prepared);
        let exact_claim = claim(&prepared, &auth);
        let exact_runtime = runtime(&prepared);
        let mut machine = ExactOccurrenceMachineV1::prepare(prepared).unwrap();
        assert_eq!(
            machine.authorize(auth.clone()).unwrap(),
            TransitionEffectV1::Applied
        );
        assert_eq!(
            machine.authorize(auth).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        assert_eq!(
            machine.claim(exact_claim.clone()).unwrap(),
            TransitionEffectV1::Applied
        );
        assert_eq!(
            machine.claim(exact_claim).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        assert_eq!(
            machine.begin_execution(exact_runtime.clone()).unwrap(),
            TransitionEffectV1::Applied
        );
        assert_eq!(
            machine.begin_execution(exact_runtime).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        let terminal = TerminalBindingV1 {
            class: TerminalClassV1::Success,
            receipt: digest("receipt"),
            evidence_head: digest("evidence-head"),
            terminal_at_unix_ms: 1_400,
        };
        assert_eq!(
            machine.finish(terminal.clone()).unwrap(),
            TransitionEffectV1::Applied
        );
        assert_eq!(
            machine.finish(terminal).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        assert_eq!(machine.state.label(), "terminal");
        ExactOccurrenceMachineV1::reopen(machine.prepared, machine.state).unwrap();
    }

    #[test]
    fn substitution_and_second_runtime_refuse_without_state_change() {
        let prepared = PreparedOccurrenceV1::new(plan()).unwrap();
        let auth = authorization(&prepared);
        let exact_claim = claim(&prepared, &auth);
        let exact_runtime = runtime(&prepared);
        let mut machine = ExactOccurrenceMachineV1::prepare(prepared).unwrap();
        machine.authorize(auth).unwrap();
        machine.claim(exact_claim).unwrap();
        machine.begin_execution(exact_runtime).unwrap();
        let before = machine.clone();
        let mut second = runtime(&machine.prepared);
        second.runtime_instance_id = digest("second-runtime");
        assert!(matches!(
            machine.begin_execution(second),
            Err(OccurrenceError::ReplayConflict("runtime instance"))
        ));
        assert_eq!(machine, before);
    }

    #[test]
    fn outcome_unknown_is_terminal_and_never_becomes_retry_authority() {
        let prepared = PreparedOccurrenceV1::new(plan()).unwrap();
        let auth = authorization(&prepared);
        let exact_claim = claim(&prepared, &auth);
        let mut machine = ExactOccurrenceMachineV1::prepare(prepared).unwrap();
        machine.authorize(auth.clone()).unwrap();
        machine.claim(exact_claim).unwrap();
        let unknown = OutcomeUnknownBindingV1 {
            evidence: digest("missing-result"),
            evidence_head: digest("evidence-head"),
            terminal_at_unix_ms: 1_250,
        };
        machine.mark_outcome_unknown(unknown.clone()).unwrap();
        assert_eq!(
            machine.mark_outcome_unknown(unknown).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        assert!(matches!(
            machine.begin_execution(runtime(&machine.prepared)),
            Err(OccurrenceError::InvalidTransition {
                state: "outcome_unknown",
                requested: "executing"
            })
        ));
        assert!(matches!(
            machine.authorize(auth),
            Ok(TransitionEffectV1::IdempotentReplay)
        ));
    }

    #[test]
    fn widened_cardinality_and_expired_authorization_refuse() {
        let mut invalid = plan();
        invalid.cardinality.max_runtime_instances = 2;
        assert!(matches!(
            PreparedOccurrenceV1::new(invalid),
            Err(OccurrenceError::InvalidPlan(
                "V1 cardinality must be exactly one"
            ))
        ));
        let prepared = PreparedOccurrenceV1::new(plan()).unwrap();
        let mut expired = authorization(&prepared);
        expired.authorized_at_unix_ms = prepared.plan.lifetime.expires_at_unix_ms;
        let mut machine = ExactOccurrenceMachineV1::prepare(prepared).unwrap();
        assert_eq!(
            machine.authorize(expired),
            Err(OccurrenceError::OutsideLifetime)
        );
        assert_eq!(machine.state, OccurrenceStateV1::Prepared);
    }

    #[test]
    fn unknown_json_members_refuse() {
        let prepared = PreparedOccurrenceV1::new(plan()).unwrap();
        let mut value = serde_json::to_value(&prepared).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("authority".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<PreparedOccurrenceV1>(value).is_err());
    }
}
