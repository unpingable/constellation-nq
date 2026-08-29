//! BEDROCK one-shot pre-runtime node observation and deferred-capacity law.
//!
//! The observer reports node OS, procfs, cgroup-v2, and retained-filesystem
//! facts. It cannot authorize NQ work, create a Kubernetes object, or claim
//! that a future workload's consequence-time cgroup facts already exist.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use nix::sys::statvfs::{FsFlags, statvfs};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::origin_capacity::{ClusterFactsV1, NamedUidV1, PlacementFactsV1, ResourceEnvelopeV1};
use crate::{
    AuthorizationBindingV1, ClaimBindingV1, ExactOccurrenceMachineV1, MAX_SAFE_JSON_INTEGER,
    OccurrenceError, OccurrenceStateV1, PreparedOccurrenceV1, RuntimeBindingV1, TransitionEffectV1,
    validate_token,
};

/// Closed acquisition-contract schema.
pub const CONTRACT_SCHEMA_V1: &str = "nq.bedrock_node_observation_contract.v1";
/// Closed acquisition-basis schema.
pub const BASIS_SCHEMA_V1: &str = "nq.bedrock_node_observation_basis.v1";
/// Closed signed-content schema.
pub const OBSERVATION_SCHEMA_V1: &str = "nq.bedrock_node_observation.v1";
/// Closed signed-wrapper schema.
pub const SIGNED_SCHEMA_V1: &str = "nq.bedrock_signed_node_observation.v1";
/// Closed pre-runtime context schema.
pub const PRE_RUNTIME_SCHEMA_V1: &str = "nq.bedrock_pre_runtime_origin_capacity.v1";
/// Closed deferred runtime obligation schema.
pub const DEFERRED_SCHEMA_V1: &str = "nq.bedrock_deferred_runtime_capacity.v1";
/// Closed exact runtime-capacity recheck schema.
pub const RUNTIME_RECHECK_SCHEMA_V1: &str = "nq.bedrock_runtime_capacity_recheck.v1";
/// Closed inert bootstrap identity schema.
pub const BOOTSTRAP_SCHEMA_V1: &str = "nq.bedrock_inert_bootstrap.v1";
/// Closed origin profile for mandatory deferred runtime facts.
pub const DEFERRED_ORIGIN_PROFILE_V1: &str = "nq.kubernetes_node_host_deferred_runtime_origin.v1";
/// Closed one-use release schema.
pub const RELEASE_SCHEMA_V1: &str = "nq.bedrock_exact_execution_release.v1";
/// Closed projection law. V1 deliberately admits no CPU limit.
pub const PROJECTION_SCHEMA_V1: &str = "nq.bedrock_unlimited_cpu_runtime_projection.v1";
/// Fixed node-local key path.
pub const SIGNING_KEY_PATH: &str = "/var/lib/nq-bedrock-observer/signing-key.hex";
/// Maximum exact input.
pub const MAX_BASIS_BYTES: usize = 64 * 1024;
/// Maximum signed observation lifetime.
pub const MAX_LIFETIME_MS: u64 = 120_000;

/// Pinned one-shot collector/verifier contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeObservationContractV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact observer executable identity.
    pub observer_executable_digest: Sha256Digest,
    /// Exact verifier source commit.
    pub verifier_source_commit: String,
    /// Exact node observer public-key identity.
    pub observer_key_digest: Sha256Digest,
    /// Fixed procfs source.
    pub procfs_mount_point: String,
    /// Fixed cgroup-v2 source.
    pub cgroup_mount_point: String,
    /// Closed pre-runtime projection law.
    pub projection_schema: String,
    /// Maximum signed-fact lifetime.
    pub maximum_lifetime_ms: u64,
}

/// Kubernetes API observation independently supplied by the controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeApiFactsV1 {
    /// Node name.
    pub name: String,
    /// Immutable node UID.
    pub uid: String,
    /// Provider ID.
    pub provider_id: String,
    /// Kubernetes-reported machine ID.
    pub machine_id: String,
    /// Kubernetes-reported boot ID.
    pub boot_id: String,
    /// Kubernetes-reported kernel version.
    pub kernel_version: String,
    /// Kubernetes-reported runtime version.
    pub container_runtime_version: String,
}

/// Exact request presented to one node observer invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeObservationBasisV1 {
    /// Closed schema.
    pub schema: String,
    /// Unique acquisition identity.
    pub acquisition_id: String,
    /// Controller challenge identity.
    pub challenge_digest: Sha256Digest,
    /// Exact acquisition contract.
    pub acquisition_contract_digest: Sha256Digest,
    /// Exact cluster API coordinate.
    pub cluster: ClusterFactsV1,
    /// Exact node API coordinate.
    pub node: NodeApiFactsV1,
    /// Exact namespace.
    pub namespace: NamedUidV1,
    /// Exact service account.
    pub service_account: NamedUidV1,
    /// Exact inert-bootstrap mechanics policy.
    pub mechanics_policy_digest: Sha256Digest,
    /// Exact fixed placement.
    pub placement: PlacementFactsV1,
    /// Exact requested future resource envelope.
    pub resources: ResourceEnvelopeV1,
    /// Existing campaign-owned retained-evidence directory.
    pub evidence_path: String,
    /// Inclusive request time.
    pub requested_at_unix_ms: u64,
    /// Exclusive expiry.
    pub valid_until_unix_ms: u64,
}

/// Mount identity from `/proc/self/mountinfo`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountSourceV1 {
    /// Mount ID.
    pub mount_id: u64,
    /// Parent mount ID.
    pub parent_mount_id: u64,
    /// Kernel device major:minor.
    pub device: String,
    /// Exact mount point.
    pub mount_point: String,
    /// Filesystem type.
    pub filesystem_type: String,
    /// Mount source.
    pub source: String,
}

/// Node observer procfs source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcfsObservationV1 {
    /// Exact mount identity.
    pub mount: MountSourceV1,
    /// Observer's effective CPU allowance.
    pub cpus_allowed_list: String,
}

/// Node observer cgroup-v2 source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupObservationV1 {
    /// Exact cgroup-v2 mount identity.
    pub mount: MountSourceV1,
    /// Observer's cgroup membership.
    pub observer_cgroup_path: String,
    /// Effective observer `cpu.max`.
    pub cpu_max: Option<String>,
    /// Effective observer cpuset.
    pub cpuset_cpus_effective: Option<String>,
    /// Effective observer memory ceiling.
    pub memory_max: Option<String>,
}

/// Retained evidence filesystem observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageObservationV1 {
    /// Exact required path.
    pub path: String,
    /// Containing mount.
    pub mount: MountSourceV1,
    /// Total bytes.
    pub total_bytes: u64,
    /// Bytes available to an unprivileged process.
    pub available_bytes: u64,
    /// Read-only mount flag.
    pub read_only: bool,
}

/// Canonical signed node observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeObservationV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact acquisition identity.
    pub acquisition_id: String,
    /// Canonical basis identity.
    pub basis_digest: Sha256Digest,
    /// OS-reported hostname.
    pub reported_hostname: String,
    /// Node machine ID.
    pub machine_id: String,
    /// Node boot ID.
    pub boot_id: String,
    /// Running kernel release.
    pub kernel_release: String,
    /// Procfs facts.
    pub procfs: ProcfsObservationV1,
    /// cgroup-v2 facts.
    pub cgroup: CgroupObservationV1,
    /// Retained-storage facts.
    pub storage: StorageObservationV1,
    /// Node observer's Rust capacity result.
    pub available_parallelism: u32,
    /// Observation time.
    pub observed_at_unix_ms: u64,
    /// Exclusive expiry.
    pub valid_until_unix_ms: u64,
}

/// Signed observation envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNodeObservationV1 {
    /// Closed schema.
    pub schema: String,
    /// Canonical observation identity.
    pub observation_digest: Sha256Digest,
    /// Lowercase Ed25519 signature.
    pub signature_hex: String,
    /// Exact signed content.
    pub observation: NodeObservationV1,
}

/// Mandatory facts that cannot exist before the exact Pod/container exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredRuntimeCapacityV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact pre-runtime context.
    pub pre_runtime_context_digest: Sha256Digest,
    /// Exact placement link.
    pub placement_digest: Sha256Digest,
    /// Exact resource-envelope link.
    pub resource_envelope_digest: Sha256Digest,
    /// Exact admitted node UID.
    pub node_uid: String,
    /// Future exact Pod UID is mandatory.
    pub require_pod_uid: bool,
    /// Future first container ID is mandatory.
    pub require_container_id: bool,
    /// Future in-container procfs fact is mandatory.
    pub require_procfs_recheck: bool,
    /// Future in-container cgroup-v2 fact is mandatory.
    pub require_cgroup_recheck: bool,
    /// Future in-container `available_parallelism` is mandatory.
    pub require_available_parallelism_recheck: bool,
    /// NQ claim/fence must precede exactly one execution release.
    pub require_claim_fence_before_release: bool,
}

/// Qualified pre-runtime plan. It is not consequence-time capacity evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedPreRuntimeContextV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact contract identity.
    pub acquisition_contract_digest: Sha256Digest,
    /// Exact signed observation identity.
    pub signed_observation_digest: Sha256Digest,
    /// Exact API cluster identity.
    pub cluster_digest: Sha256Digest,
    /// Exact API node identity.
    pub node_api_digest: Sha256Digest,
    /// Exact namespace-UID identity.
    pub namespace_uid_digest: Sha256Digest,
    /// Exact service-account-UID identity.
    pub service_account_uid_digest: Sha256Digest,
    /// Exact procfs source identity.
    pub procfs_source_digest: Sha256Digest,
    /// Exact cgroup source identity.
    pub cgroup_source_digest: Sha256Digest,
    /// Exact retained storage identity.
    pub storage_digest: Sha256Digest,
    /// Exact placement identity.
    pub placement_digest: Sha256Digest,
    /// Exact resource intent identity.
    pub resource_envelope_digest: Sha256Digest,
    /// Exact mechanics identity.
    pub mechanics_policy_digest: Sha256Digest,
    /// Observation expiry.
    pub valid_until_unix_ms: u64,
}

/// Exact inert Kubernetes runtime identity. Existence is not NQ execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InertBootstrapIdentityV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact prepared plan.
    pub plan_id: Sha256Digest,
    /// Deterministic Pod name.
    pub pod_name: String,
    /// Kubernetes-assigned Pod UID.
    pub pod_uid: String,
    /// First container ID, still blocked on the release gate.
    pub container_id: String,
    /// Exact admitted node UID.
    pub node_uid: String,
    /// Time the inert bootstrap identity became exact.
    pub observed_at_unix_ms: u64,
}

/// Exact consequence-time facts observed from the inert container context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapacityRecheckV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact prepared plan.
    pub plan_id: Sha256Digest,
    /// Exact pre-runtime context.
    pub pre_runtime_context_digest: Sha256Digest,
    /// Exact deferred obligation.
    pub deferred_obligation_digest: Sha256Digest,
    /// Exact inert bootstrap identity.
    pub bootstrap_digest: Sha256Digest,
    /// In-container procfs source and CPU allowance.
    pub procfs: ProcfsObservationV1,
    /// In-container cgroup-v2 source and limits.
    pub cgroup: CgroupObservationV1,
    /// In-container Rust capacity result.
    pub available_parallelism: u32,
    /// Exact placement link.
    pub placement_digest: Sha256Digest,
    /// Exact resource-intent link.
    pub resource_envelope_digest: Sha256Digest,
    /// Consequence-time observation time.
    pub observed_at_unix_ms: u64,
    /// Exclusive recheck expiry.
    pub valid_until_unix_ms: u64,
}

/// One-use release after exact claim/fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReleaseV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact prepared plan.
    pub plan_id: Sha256Digest,
    /// Exact claim/fence identity.
    pub claim_id: Sha256Digest,
    /// Exact runtime recheck.
    pub runtime_recheck_digest: Sha256Digest,
    /// Release time.
    pub released_at_unix_ms: u64,
}

/// Deferred-capacity lifecycle outside Kubernetes desired-state authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeferredCapacityStateV1 {
    /// AG/Docket authorization exists; no Pod identity exists.
    AwaitingBootstrap,
    /// One inert Pod/container is exact; no NQ claim exists.
    BootstrapObserved {
        /// Exact inert identity.
        bootstrap: InertBootstrapIdentityV1,
    },
    /// Runtime cgroup facts are exact; still no NQ claim/release.
    RuntimeQualified {
        /// Exact inert identity.
        bootstrap: InertBootstrapIdentityV1,
        /// Exact runtime facts.
        runtime: RuntimeCapacityRecheckV1,
    },
    /// NQ claim/fence exists and exactly one release is retained.
    Released {
        /// Exact inert identity.
        bootstrap: InertBootstrapIdentityV1,
        /// Exact runtime facts.
        runtime: RuntimeCapacityRecheckV1,
        /// One-use release.
        release: ExecutionReleaseV1,
    },
}

/// BEDROCK wrapper that cannot claim or release from pre-runtime projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredCapacityMachineV1 {
    /// Existing exact-occurrence machine.
    pub exact: ExactOccurrenceMachineV1,
    /// Qualified pre-runtime plan.
    pub pre_runtime: QualifiedPreRuntimeContextV1,
    /// Mandatory consequence-time obligation.
    pub deferred: DeferredRuntimeCapacityV1,
    /// Deferred-capacity state.
    pub state: DeferredCapacityStateV1,
}

impl DeferredCapacityMachineV1 {
    /// Opens an authority-empty exact occurrence whose plan binds the complete
    /// deferred runtime obligation rather than synthetic runtime facts.
    pub fn prepare(
        prepared: PreparedOccurrenceV1,
        pre_runtime: QualifiedPreRuntimeContextV1,
        deferred: DeferredRuntimeCapacityV1,
    ) -> Result<Self, ObservationError> {
        let pre_runtime_digest = semantic_digest(&pre_runtime)
            .map_err(|error| ObservationError::Invalid(error.to_string()))?;
        let deferred_digest = semantic_digest(&deferred)
            .map_err(|error| ObservationError::Invalid(error.to_string()))?;
        let binding = &prepared.plan.origin_capacity;
        if pre_runtime.schema != PRE_RUNTIME_SCHEMA_V1
            || deferred.schema != DEFERRED_SCHEMA_V1
            || deferred.pre_runtime_context_digest != pre_runtime_digest
            || binding.origin_profile != DEFERRED_ORIGIN_PROFILE_V1
            || binding.subject != pre_runtime.node_api_digest
            || binding.scope != pre_runtime.node_api_digest
            || binding.vantage != pre_runtime.signed_observation_digest
            || binding.cluster != pre_runtime.cluster_digest
            || binding.namespace_uid != pre_runtime.namespace_uid_digest
            || binding.service_account_uid != pre_runtime.service_account_uid_digest
            || binding.placement_digest != pre_runtime.placement_digest
            || binding.resource_envelope_digest != pre_runtime.resource_envelope_digest
            || binding.capacity_context_digest != deferred_digest
            || deferred.placement_digest != pre_runtime.placement_digest
            || deferred.resource_envelope_digest != pre_runtime.resource_envelope_digest
            || !(deferred.require_pod_uid
                && deferred.require_container_id
                && deferred.require_procfs_recheck
                && deferred.require_cgroup_recheck
                && deferred.require_available_parallelism_recheck
                && deferred.require_claim_fence_before_release)
        {
            return Err(ObservationError::Invalid(
                "prepared deferred-capacity links".into(),
            ));
        }
        Ok(Self {
            exact: ExactOccurrenceMachineV1::prepare(prepared)?,
            pre_runtime,
            deferred,
            state: DeferredCapacityStateV1::AwaitingBootstrap,
        })
    }

    /// Binds the one spent AG issuance and Docket attempt. It creates no Pod.
    pub fn authorize(
        &mut self,
        authorization: AuthorizationBindingV1,
    ) -> Result<TransitionEffectV1, ObservationError> {
        self.exact.authorize(authorization).map_err(Into::into)
    }

    /// Retains the sole inert bootstrap identity. This is mechanics identity,
    /// not NQ execution and not a claim/fence.
    pub fn observe_bootstrap(
        &mut self,
        bootstrap: InertBootstrapIdentityV1,
    ) -> Result<TransitionEffectV1, ObservationError> {
        if let DeferredCapacityStateV1::BootstrapObserved { bootstrap: prior }
        | DeferredCapacityStateV1::RuntimeQualified {
            bootstrap: prior, ..
        }
        | DeferredCapacityStateV1::Released {
            bootstrap: prior, ..
        } = &self.state
        {
            return if prior == &bootstrap {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(ObservationError::Invalid("bootstrap replay".into()))
            };
        }
        if !matches!(self.exact.state, OccurrenceStateV1::Authorized { .. })
            || !matches!(self.state, DeferredCapacityStateV1::AwaitingBootstrap)
            || bootstrap.schema != BOOTSTRAP_SCHEMA_V1
            || bootstrap.plan_id != self.exact.prepared.plan_id
            || bootstrap.node_uid != self.deferred.node_uid
            || bootstrap.observed_at_unix_ms >= self.pre_runtime.valid_until_unix_ms
        {
            return Err(ObservationError::Invalid("inert bootstrap".into()));
        }
        for (value, field) in [
            (&bootstrap.pod_name, "Pod name"),
            (&bootstrap.pod_uid, "Pod UID"),
            (&bootstrap.container_id, "container ID"),
            (&bootstrap.node_uid, "node UID"),
        ] {
            validate_token(value, field)?;
        }
        self.state = DeferredCapacityStateV1::BootstrapObserved { bootstrap };
        Ok(TransitionEffectV1::Applied)
    }

    /// Binds actual in-container consequence-time facts. It still does not
    /// claim NQ authority or release execution.
    pub fn qualify_runtime(
        &mut self,
        runtime: RuntimeCapacityRecheckV1,
        at_unix_ms: u64,
    ) -> Result<TransitionEffectV1, ObservationError> {
        if let DeferredCapacityStateV1::RuntimeQualified { runtime: prior, .. }
        | DeferredCapacityStateV1::Released { runtime: prior, .. } = &self.state
        {
            return if prior == &runtime {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(ObservationError::Invalid("runtime recheck replay".into()))
            };
        }
        let DeferredCapacityStateV1::BootstrapObserved { bootstrap } = &self.state else {
            return Err(ObservationError::Invalid("runtime recheck ordering".into()));
        };
        let pre_runtime_digest = semantic_digest(&self.pre_runtime)
            .map_err(|error| ObservationError::Invalid(error.to_string()))?;
        let deferred_digest = semantic_digest(&self.deferred)
            .map_err(|error| ObservationError::Invalid(error.to_string()))?;
        let bootstrap_digest = semantic_digest(bootstrap)
            .map_err(|error| ObservationError::Invalid(error.to_string()))?;
        if runtime.schema != RUNTIME_RECHECK_SCHEMA_V1
            || runtime.plan_id != self.exact.prepared.plan_id
            || runtime.pre_runtime_context_digest != pre_runtime_digest
            || runtime.deferred_obligation_digest != deferred_digest
            || runtime.bootstrap_digest != bootstrap_digest
            || runtime.placement_digest != self.deferred.placement_digest
            || runtime.resource_envelope_digest != self.deferred.resource_envelope_digest
            || runtime.procfs.mount.filesystem_type != "proc"
            || runtime.cgroup.mount.filesystem_type != "cgroup2"
            || runtime.available_parallelism == 0
            || runtime.observed_at_unix_ms >= runtime.valid_until_unix_ms
            || !(runtime.observed_at_unix_ms..runtime.valid_until_unix_ms).contains(&at_unix_ms)
            || runtime.valid_until_unix_ms > self.pre_runtime.valid_until_unix_ms
        {
            return Err(ObservationError::Invalid("runtime capacity recheck".into()));
        }
        self.state = DeferredCapacityStateV1::RuntimeQualified {
            bootstrap: bootstrap.clone(),
            runtime,
        };
        Ok(TransitionEffectV1::Applied)
    }

    /// Claims the exact NQ occurrence only after runtime facts are exact.
    pub fn claim(&mut self, claim: ClaimBindingV1) -> Result<TransitionEffectV1, ObservationError> {
        if !matches!(self.state, DeferredCapacityStateV1::RuntimeQualified { .. }) {
            return Err(ObservationError::Invalid(
                "claim requires runtime capacity recheck".into(),
            ));
        }
        self.exact.claim(claim).map_err(Into::into)
    }

    /// Releases one execution only after the existing exact claim/fence.
    pub fn release(&mut self, at_unix_ms: u64) -> Result<ExecutionReleaseV1, ObservationError> {
        if let DeferredCapacityStateV1::Released { release, .. } = &self.state {
            return Ok(release.clone());
        }
        let DeferredCapacityStateV1::RuntimeQualified { bootstrap, runtime } = &self.state else {
            return Err(ObservationError::Invalid("release ordering".into()));
        };
        let OccurrenceStateV1::Claimed { claim, .. } = &self.exact.state else {
            return Err(ObservationError::Invalid(
                "release lacks exact claim/fence".into(),
            ));
        };
        if at_unix_ms < claim.claimed_at_unix_ms
            || !(runtime.observed_at_unix_ms..runtime.valid_until_unix_ms).contains(&at_unix_ms)
        {
            return Err(ObservationError::Invalid("release time".into()));
        }
        let release = ExecutionReleaseV1 {
            schema: RELEASE_SCHEMA_V1.into(),
            plan_id: self.exact.prepared.plan_id.clone(),
            claim_id: claim.claim_id.clone(),
            runtime_recheck_digest: semantic_digest(runtime)
                .map_err(|error| ObservationError::Invalid(error.to_string()))?,
            released_at_unix_ms: at_unix_ms,
        };
        self.state = DeferredCapacityStateV1::Released {
            bootstrap: bootstrap.clone(),
            runtime: runtime.clone(),
            release: release.clone(),
        };
        Ok(release)
    }

    /// Records semantic execution only after one exact release exists.
    pub fn begin_execution(
        &mut self,
        runtime: RuntimeBindingV1,
    ) -> Result<TransitionEffectV1, ObservationError> {
        if !matches!(self.state, DeferredCapacityStateV1::Released { .. }) {
            return Err(ObservationError::Invalid("execution lacks release".into()));
        }
        self.exact.begin_execution(runtime).map_err(Into::into)
    }
}

/// Bounded observer/verifier error.
#[derive(Debug, Error)]
pub enum ObservationError {
    /// Exact input or closed semantic law refused.
    #[error("node observation refused: {0}")]
    Invalid(String),
    /// Local read/write observation failed.
    #[error("node observation I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Signing-key custody failed.
    #[error("node observer key refused: {0}")]
    Key(String),
    /// Existing exact-occurrence law refused.
    #[error(transparent)]
    Occurrence(#[from] OccurrenceError),
}

impl NodeObservationContractV1 {
    /// Validate and identify the closed contract.
    pub fn digest(&self) -> Result<Sha256Digest, ObservationError> {
        if self.schema != CONTRACT_SCHEMA_V1
            || self.procfs_mount_point != "/proc"
            || self.cgroup_mount_point != "/sys/fs/cgroup"
            || self.projection_schema != PROJECTION_SCHEMA_V1
            || self.maximum_lifetime_ms == 0
            || self.maximum_lifetime_ms > MAX_LIFETIME_MS
        {
            return Err(ObservationError::Invalid("acquisition contract".into()));
        }
        validate_token(&self.verifier_source_commit, "verifier source commit")?;
        semantic_digest(self).map_err(|error| ObservationError::Invalid(error.to_string()))
    }
}

impl NodeObservationBasisV1 {
    /// Validate API, placement, resource-intent, path, and temporal links.
    pub fn validate(&self, contract: &NodeObservationContractV1) -> Result<(), ObservationError> {
        if self.schema != BASIS_SCHEMA_V1
            || self.acquisition_contract_digest != contract.digest()?
            || self.cluster.acquisition_contract_digest != self.acquisition_contract_digest
            || self.placement.node_name != self.node.name
            || self.placement.node_uid != self.node.uid
            || self.placement.rescheduling_allowed
            || self.resources.cpu_limit_millicores.is_some()
            || self.requested_at_unix_ms >= self.valid_until_unix_ms
            || self.valid_until_unix_ms > MAX_SAFE_JSON_INTEGER
            || self.valid_until_unix_ms - self.requested_at_unix_ms > contract.maximum_lifetime_ms
        {
            return Err(ObservationError::Invalid("observation basis".into()));
        }
        for (value, field) in [
            (&self.acquisition_id, "acquisition ID"),
            (&self.node.name, "node name"),
            (&self.node.uid, "node UID"),
            (&self.node.provider_id, "provider ID"),
            (&self.node.machine_id, "machine ID"),
            (&self.node.boot_id, "boot ID"),
        ] {
            validate_token(value, field)?;
        }
        if !Path::new(&self.evidence_path).is_absolute() || self.evidence_path.contains("..") {
            return Err(ObservationError::Invalid("evidence path".into()));
        }
        Ok(())
    }
}

impl SignedNodeObservationV1 {
    /// Verify exact API/node/content/time bindings and emit a pre-runtime plan
    /// plus mandatory deferred consequence-time obligations.
    pub fn verify_pre_runtime(
        &self,
        basis: &NodeObservationBasisV1,
        contract: &NodeObservationContractV1,
        key: &VerifyingKey,
        at_unix_ms: u64,
    ) -> Result<(QualifiedPreRuntimeContextV1, DeferredRuntimeCapacityV1), ObservationError> {
        basis.validate(contract)?;
        let basis_digest =
            semantic_digest(basis).map_err(|e| ObservationError::Invalid(e.to_string()))?;
        let observation_digest = semantic_digest(&self.observation)
            .map_err(|e| ObservationError::Invalid(e.to_string()))?;
        if self.schema != SIGNED_SCHEMA_V1
            || self.observation.schema != OBSERVATION_SCHEMA_V1
            || self.observation.acquisition_id != basis.acquisition_id
            || self.observation.basis_digest != basis_digest
            || self.observation_digest != observation_digest
            || self.observation.reported_hostname != basis.node.name
            || self.observation.machine_id != basis.node.machine_id
            || self.observation.boot_id != basis.node.boot_id
            || self.observation.kernel_release != basis.node.kernel_version
            || self.observation.valid_until_unix_ms != basis.valid_until_unix_ms
            || !(self.observation.observed_at_unix_ms..self.observation.valid_until_unix_ms)
                .contains(&at_unix_ms)
            || self.observation.observed_at_unix_ms < basis.requested_at_unix_ms
            || self.observation.procfs.mount.mount_point != contract.procfs_mount_point
            || self.observation.procfs.mount.filesystem_type != "proc"
            || self.observation.cgroup.mount.mount_point != contract.cgroup_mount_point
            || self.observation.cgroup.mount.filesystem_type != "cgroup2"
            || self.observation.storage.path != basis.evidence_path
            || self.observation.storage.read_only
            || self.observation.available_parallelism == 0
            || sha256_bytes(key.as_bytes()) != contract.observer_key_digest
        {
            return Err(ObservationError::Invalid(
                "signed observation content".into(),
            ));
        }
        let signature: [u8; 64] = hex::decode(&self.signature_hex)
            .map_err(|_| ObservationError::Invalid("signature encoding".into()))?
            .try_into()
            .map_err(|_| ObservationError::Invalid("signature length".into()))?;
        let bytes = canonical_json_bytes(&self.observation)
            .map_err(|e| ObservationError::Invalid(e.to_string()))?;
        let mut preimage = SIGNED_SCHEMA_V1.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        key.verify(&preimage, &Signature::from_bytes(&signature))
            .map_err(|_| ObservationError::Invalid("signature".into()))?;

        let context = QualifiedPreRuntimeContextV1 {
            schema: PRE_RUNTIME_SCHEMA_V1.into(),
            acquisition_contract_digest: contract.digest()?,
            signed_observation_digest: semantic_digest(self)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            cluster_digest: semantic_digest(&basis.cluster)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            node_api_digest: semantic_digest(&basis.node)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            namespace_uid_digest: semantic_digest(&basis.namespace.uid)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            service_account_uid_digest: semantic_digest(&basis.service_account.uid)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            procfs_source_digest: semantic_digest(&self.observation.procfs)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            cgroup_source_digest: semantic_digest(&self.observation.cgroup)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            storage_digest: semantic_digest(&self.observation.storage)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            placement_digest: semantic_digest(&basis.placement)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            resource_envelope_digest: semantic_digest(&basis.resources)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            mechanics_policy_digest: basis.mechanics_policy_digest.clone(),
            valid_until_unix_ms: basis.valid_until_unix_ms,
        };
        let deferred = DeferredRuntimeCapacityV1 {
            schema: DEFERRED_SCHEMA_V1.into(),
            pre_runtime_context_digest: semantic_digest(&context)
                .map_err(|e| ObservationError::Invalid(e.to_string()))?,
            placement_digest: context.placement_digest.clone(),
            resource_envelope_digest: context.resource_envelope_digest.clone(),
            node_uid: basis.node.uid.clone(),
            require_pod_uid: true,
            require_container_id: true,
            require_procfs_recheck: true,
            require_cgroup_recheck: true,
            require_available_parallelism_recheck: true,
            require_claim_fence_before_release: true,
        };
        Ok((context, deferred))
    }
}

/// Execute the one-shot observer over exact canonical input/output.
pub fn run_observer(
    mut input: impl Read,
    mut output: impl Write,
    contract: &NodeObservationContractV1,
    key: &SigningKey,
) -> Result<(), ObservationError> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take((MAX_BASIS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_BASIS_BYTES {
        return Err(ObservationError::Invalid("basis size".into()));
    }
    let basis: NodeObservationBasisV1 =
        serde_json::from_slice(&bytes).map_err(|e| ObservationError::Invalid(e.to_string()))?;
    basis.validate(contract)?;
    if canonical_json_bytes(&basis).map_err(|e| ObservationError::Invalid(e.to_string()))? != bytes
    {
        return Err(ObservationError::Invalid(
            "basis is not exact canonical JCS".into(),
        ));
    }
    let observation = observe(&basis)?;
    let observation_bytes =
        canonical_json_bytes(&observation).map_err(|e| ObservationError::Invalid(e.to_string()))?;
    let mut preimage = SIGNED_SCHEMA_V1.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&observation_bytes);
    let signed = SignedNodeObservationV1 {
        schema: SIGNED_SCHEMA_V1.into(),
        observation_digest: sha256_bytes(&observation_bytes),
        signature_hex: hex::encode(key.sign(&preimage).to_bytes()),
        observation,
    };
    output.write_all(
        &canonical_json_bytes(&signed).map_err(|e| ObservationError::Invalid(e.to_string()))?,
    )?;
    output.flush()?;
    Ok(())
}

/// Read the fixed owned regular mode-0600 node observer key.
pub fn read_signing_key(path: &Path) -> Result<SigningKey, ObservationError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| ObservationError::Key(e.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|e| ObservationError::Key(e.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 128
    {
        return Err(ObservationError::Key(
            "key must be an owned regular 0600 file no larger than 128 bytes".into(),
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| ObservationError::Key(e.to_string()))?;
    let bytes: [u8; 32] = hex::decode(text.trim())
        .map_err(|_| ObservationError::Key("key encoding".into()))?
        .try_into()
        .map_err(|_| ObservationError::Key("key length".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Fixed live command surface.
pub fn live_main() -> Result<(), ObservationError> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let key = read_signing_key(Path::new(SIGNING_KEY_PATH))?;
    if arguments.as_slice() == ["--public-key"] {
        print!("{}", hex::encode(key.verifying_key().as_bytes()));
        return Ok(());
    }
    if arguments.len() != 2 || arguments[0] != "--contract" {
        return Err(ObservationError::Invalid(
            "only --public-key or --contract ABSOLUTE_PATH is accepted".into(),
        ));
    }
    let path = PathBuf::from(&arguments[1]);
    if !path.is_absolute() {
        return Err(ObservationError::Invalid("contract path".into()));
    }
    let bytes = fs::read(path)?;
    let contract: NodeObservationContractV1 =
        serde_json::from_slice(&bytes).map_err(|e| ObservationError::Invalid(e.to_string()))?;
    if canonical_json_bytes(&contract).map_err(|e| ObservationError::Invalid(e.to_string()))?
        != bytes
    {
        return Err(ObservationError::Invalid(
            "contract is not exact canonical JCS".into(),
        ));
    }
    run_observer(io::stdin().lock(), io::stdout().lock(), &contract, &key)
}

fn observe(basis: &NodeObservationBasisV1) -> Result<NodeObservationV1, ObservationError> {
    let observed_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ObservationError::Invalid(e.to_string()))?
            .as_millis(),
    )
    .map_err(|_| ObservationError::Invalid("clock range".into()))?;
    if !(basis.requested_at_unix_ms..basis.valid_until_unix_ms).contains(&observed_at_unix_ms) {
        return Err(ObservationError::Invalid("observation time".into()));
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let procfs = ProcfsObservationV1 {
        mount: exact_mount(&mountinfo, "/proc")?,
        cpus_allowed_list: status_value(
            &fs::read_to_string("/proc/self/status")?,
            "Cpus_allowed_list",
        )?,
    };
    let observer_cgroup_path = fs::read_to_string("/proc/self/cgroup")?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or_else(|| ObservationError::Invalid("cgroup v2 membership".into()))?;
    let cgroup_path =
        Path::new("/sys/fs/cgroup").join(observer_cgroup_path.trim_start_matches('/'));
    let cgroup = CgroupObservationV1 {
        mount: exact_mount(&mountinfo, "/sys/fs/cgroup")?,
        observer_cgroup_path,
        cpu_max: read_optional(&cgroup_path.join("cpu.max"))?,
        cpuset_cpus_effective: read_optional(&cgroup_path.join("cpuset.cpus.effective"))?,
        memory_max: read_optional(&cgroup_path.join("memory.max"))?,
    };
    let evidence = Path::new(&basis.evidence_path);
    let metadata = fs::symlink_metadata(evidence)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ObservationError::Invalid("evidence path type".into()));
    }
    let stat = statvfs(evidence)
        .map_err(|e| ObservationError::Io(io::Error::from_raw_os_error(e as i32)))?;
    let unit = stat.fragment_size();
    let storage = StorageObservationV1 {
        path: basis.evidence_path.clone(),
        mount: containing_mount(&mountinfo, evidence)?,
        total_bytes: stat.blocks().saturating_mul(unit),
        available_bytes: stat.blocks_available().saturating_mul(unit),
        read_only: stat.flags().contains(FsFlags::ST_RDONLY),
    };
    Ok(NodeObservationV1 {
        schema: OBSERVATION_SCHEMA_V1.into(),
        acquisition_id: basis.acquisition_id.clone(),
        basis_digest: semantic_digest(basis)
            .map_err(|e| ObservationError::Invalid(e.to_string()))?,
        reported_hostname: read_token("/etc/hostname")?,
        machine_id: read_token("/etc/machine-id")?,
        boot_id: read_token("/proc/sys/kernel/random/boot_id")?,
        kernel_release: read_token("/proc/sys/kernel/osrelease")?,
        procfs,
        cgroup,
        storage,
        available_parallelism: u32::try_from(std::thread::available_parallelism()?.get())
            .map_err(|_| ObservationError::Invalid("parallelism range".into()))?,
        observed_at_unix_ms,
        valid_until_unix_ms: basis.valid_until_unix_ms,
    })
}

fn read_token(path: &str) -> Result<String, ObservationError> {
    let value = fs::read_to_string(path)?.trim().to_owned();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ObservationError::Invalid(format!("malformed {path}")));
    }
    Ok(value)
}

fn read_optional(path: &Path) -> Result<Option<String>, ObservationError> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn status_value(status: &str, key: &str) -> Result<String, ObservationError> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.strip_prefix(':'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ObservationError::Invalid(format!("status lacks {key}")))
}

fn parse_mounts(text: &str) -> Result<Vec<MountSourceV1>, ObservationError> {
    text.lines()
        .map(|line| {
            let (left, right) = line
                .split_once(" - ")
                .ok_or_else(|| ObservationError::Invalid("mountinfo separator".into()))?;
            let left: Vec<_> = left.split_ascii_whitespace().collect();
            let right: Vec<_> = right.split_ascii_whitespace().collect();
            if left.len() < 6 || right.len() < 2 {
                return Err(ObservationError::Invalid("mountinfo fields".into()));
            }
            Ok(MountSourceV1 {
                mount_id: left[0]
                    .parse()
                    .map_err(|_| ObservationError::Invalid("mount id".into()))?,
                parent_mount_id: left[1]
                    .parse()
                    .map_err(|_| ObservationError::Invalid("mount parent".into()))?,
                device: left[2].into(),
                mount_point: left[4].into(),
                filesystem_type: right[0].into(),
                source: right[1].into(),
            })
        })
        .collect()
}

fn exact_mount(text: &str, path: &str) -> Result<MountSourceV1, ObservationError> {
    parse_mounts(text)?
        .into_iter()
        .find(|mount| mount.mount_point == path)
        .ok_or_else(|| ObservationError::Invalid(format!("missing mount {path}")))
}

fn containing_mount(text: &str, path: &Path) -> Result<MountSourceV1, ObservationError> {
    parse_mounts(text)?
        .into_iter()
        .filter(|mount| path.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.len())
        .ok_or_else(|| ObservationError::Invalid("containing mount".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::{
        ArtifactBindingV1, CAMPAIGN_NAME, CAMPAIGN_SLUG, CardinalityBindingV1,
        CoordinationBindingV1, EXECUTOR_WORK_SCHEMA_V1, EvidenceBindingV1, LifetimeBindingV1,
        NqAuthorityBindingV1, OriginCapacityBindingV1, PREPARED_PLAN_SCHEMA_V1,
        PreparedOccurrencePlanV1,
    };

    fn digest(value: &str) -> Sha256Digest {
        sha256_bytes(value.as_bytes())
    }

    fn fixture() -> (
        SigningKey,
        NodeObservationContractV1,
        NodeObservationBasisV1,
    ) {
        let key = SigningKey::from_bytes(&[29; 32]);
        let contract = NodeObservationContractV1 {
            schema: CONTRACT_SCHEMA_V1.into(),
            observer_executable_digest: digest("observer"),
            verifier_source_commit: "1dbae78451abb6958bb30b94c65cacbd0666ef0e".into(),
            observer_key_digest: sha256_bytes(key.verifying_key().as_bytes()),
            procfs_mount_point: "/proc".into(),
            cgroup_mount_point: "/sys/fs/cgroup".into(),
            projection_schema: PROJECTION_SCHEMA_V1.into(),
            maximum_lifetime_ms: 120_000,
        };
        let contract_digest = contract.digest().unwrap();
        let basis = NodeObservationBasisV1 {
            schema: BASIS_SCHEMA_V1.into(),
            acquisition_id: "bedrock-node-a-1".into(),
            challenge_digest: digest("challenge"),
            acquisition_contract_digest: contract_digest.clone(),
            cluster: ClusterFactsV1 {
                kube_system_namespace_uid: "cluster-uid".into(),
                api_server_ca_digest: digest("ca"),
                acquisition_contract_digest: contract_digest,
            },
            node: NodeApiFactsV1 {
                name: "bedrock-node-a".into(),
                uid: "node-uid-a".into(),
                provider_id: "k3s://bedrock-node-a".into(),
                machine_id: "machine-a".into(),
                boot_id: "boot-a".into(),
                kernel_version: "6.8.0".into(),
                container_runtime_version: "containerd://2".into(),
            },
            namespace: NamedUidV1 {
                name: "bedrock".into(),
                uid: "namespace-uid".into(),
            },
            service_account: NamedUidV1 {
                name: "bedrock-executor".into(),
                uid: "sa-uid".into(),
            },
            mechanics_policy_digest: digest("mechanics"),
            placement: PlacementFactsV1 {
                node_name: "bedrock-node-a".into(),
                node_uid: "node-uid-a".into(),
                provider_coordinate_digest: Some(digest("provider")),
                scheduler_name: "default-scheduler".into(),
                runtime_class_name: None,
                rescheduling_allowed: false,
            },
            resources: ResourceEnvelopeV1 {
                cpu_request_millicores: 500,
                cpu_limit_millicores: None,
                memory_request_bytes: 134_217_728,
                memory_limit_bytes: Some(268_435_456),
                storage_request_bytes: 1_073_741_824,
                storage_limit_bytes: None,
            },
            evidence_path: "/mnt/bedrock-custody".into(),
            requested_at_unix_ms: 1000,
            valid_until_unix_ms: 121_000,
        };
        (key, contract, basis)
    }

    fn signed(key: &SigningKey, basis: &NodeObservationBasisV1) -> SignedNodeObservationV1 {
        let observation = NodeObservationV1 {
            schema: OBSERVATION_SCHEMA_V1.into(),
            acquisition_id: basis.acquisition_id.clone(),
            basis_digest: semantic_digest(basis).unwrap(),
            reported_hostname: basis.node.name.clone(),
            machine_id: basis.node.machine_id.clone(),
            boot_id: basis.node.boot_id.clone(),
            kernel_release: basis.node.kernel_version.clone(),
            procfs: ProcfsObservationV1 {
                mount: MountSourceV1 {
                    mount_id: 1,
                    parent_mount_id: 0,
                    device: "0:1".into(),
                    mount_point: "/proc".into(),
                    filesystem_type: "proc".into(),
                    source: "proc".into(),
                },
                cpus_allowed_list: "0-1".into(),
            },
            cgroup: CgroupObservationV1 {
                mount: MountSourceV1 {
                    mount_id: 2,
                    parent_mount_id: 0,
                    device: "0:2".into(),
                    mount_point: "/sys/fs/cgroup".into(),
                    filesystem_type: "cgroup2".into(),
                    source: "cgroup2".into(),
                },
                observer_cgroup_path: "/system.slice/observer".into(),
                cpu_max: Some("max 100000".into()),
                cpuset_cpus_effective: Some("0-1".into()),
                memory_max: Some("max".into()),
            },
            storage: StorageObservationV1 {
                path: basis.evidence_path.clone(),
                mount: MountSourceV1 {
                    mount_id: 3,
                    parent_mount_id: 0,
                    device: "0:3".into(),
                    mount_point: "/mnt/bedrock-custody".into(),
                    filesystem_type: "9p".into(),
                    source: "bedrock_custody".into(),
                },
                total_bytes: 100_000,
                available_bytes: 90_000,
                read_only: false,
            },
            available_parallelism: 2,
            observed_at_unix_ms: 1100,
            valid_until_unix_ms: basis.valid_until_unix_ms,
        };
        let bytes = canonical_json_bytes(&observation).unwrap();
        let mut preimage = SIGNED_SCHEMA_V1.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        SignedNodeObservationV1 {
            schema: SIGNED_SCHEMA_V1.into(),
            observation_digest: sha256_bytes(&bytes),
            signature_hex: hex::encode(key.sign(&preimage).to_bytes()),
            observation,
        }
    }

    fn deferred_machine() -> (
        DeferredCapacityMachineV1,
        AuthorizationBindingV1,
        ClaimBindingV1,
    ) {
        let (key, contract, basis) = fixture();
        let (context, deferred) = signed(&key, &basis)
            .verify_pre_runtime(&basis, &contract, &key.verifying_key(), 1200)
            .unwrap();
        let deferred_digest = semantic_digest(&deferred).unwrap();
        let plan = PreparedOccurrencePlanV1 {
            schema: PREPARED_PLAN_SCHEMA_V1.into(),
            campaign: CAMPAIGN_NAME.into(),
            campaign_slug: CAMPAIGN_SLUG.into(),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.into(),
            nq: NqAuthorityBindingV1 {
                occurrence_id: digest("occurrence"),
                h_grant_id: "h-bedrock".into(),
                g_grant_id: "g-bedrock".into(),
                e_grant_id: "e-bedrock".into(),
                watcher_id: "watcher-bedrock".into(),
                admission_id: "admission-bedrock".into(),
                enrollment_id: digest("enrollment"),
                succession_relation_id: None,
                recurrence_slot: 1,
                selected_sample_id: digest("sample"),
                selected_sample_digest: digest("sample-document"),
            },
            artifact: ArtifactBindingV1 {
                source_commit: "1dbae78451abb6958bb30b94c65cacbd0666ef0e".into(),
                oci_manifest_digest: digest("oci"),
                nq_executable_digest: digest("nq"),
                passive_helper_digest: digest("helper"),
                configuration_digests: BTreeMap::from([(
                    "bedrock-bootstrap.v1".into(),
                    digest("bootstrap-config"),
                )]),
            },
            origin_capacity: OriginCapacityBindingV1 {
                origin_profile: DEFERRED_ORIGIN_PROFILE_V1.into(),
                subject: context.node_api_digest.clone(),
                scope: context.node_api_digest.clone(),
                vantage: context.signed_observation_digest.clone(),
                cluster: context.cluster_digest.clone(),
                namespace_uid: context.namespace_uid_digest.clone(),
                service_account_uid: context.service_account_uid_digest.clone(),
                placement_digest: context.placement_digest.clone(),
                resource_envelope_digest: context.resource_envelope_digest.clone(),
                capacity_context_digest: deferred_digest,
            },
            coordination: CoordinationBindingV1 {
                domain_id: "bedrock-test-domain".into(),
                fencing_epoch: 1,
                provider_safe_spacing_ms: 0,
            },
            evidence: EvidenceBindingV1 {
                canonical_custody_id: digest("canonical"),
                selection_contract_digest: digest("selection"),
                external_journal_id: digest("journal"),
                receipt_destination_id: digest("receipts"),
                required_free_bytes: 1,
                retention_mode: "retain_all".into(),
            },
            lifetime: LifetimeBindingV1 {
                not_before_unix_ms: 1000,
                expires_at_unix_ms: 121_000,
                max_runtime_ms: 10_000,
            },
            cardinality: CardinalityBindingV1 {
                max_authorizations: 1,
                max_docket_attempts: 1,
                max_runtime_instances: 1,
                max_terminal_results: 1,
            },
        };
        let prepared = PreparedOccurrenceV1::new(plan).unwrap();
        let authorization = AuthorizationBindingV1 {
            ag_campaign: digest("ag-campaign"),
            ag_occurrence: digest("ag-occurrence"),
            ag_issuance: digest("ag-issuance"),
            ag_work: prepared.plan_id.clone(),
            docket_attempt: digest("docket-attempt"),
            docket_marker: digest("docket-marker"),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.into(),
            subject: prepared.plan.origin_capacity.subject.clone(),
            scope: prepared.plan.origin_capacity.scope.clone(),
            authorized_at_unix_ms: 1200,
        };
        let claim = ClaimBindingV1 {
            claim_id: digest("claim"),
            nq_occurrence: prepared.plan.nq.occurrence_id.clone(),
            plan_id: prepared.plan_id.clone(),
            docket_attempt: authorization.docket_attempt.clone(),
            docket_marker: authorization.docket_marker.clone(),
            fencing_epoch: 1,
            selected_sample_id: prepared.plan.nq.selected_sample_id.clone(),
            claimed_at_unix_ms: 1400,
        };
        (
            DeferredCapacityMachineV1::prepare(prepared, context, deferred).unwrap(),
            authorization,
            claim,
        )
    }

    fn bootstrap(machine: &DeferredCapacityMachineV1) -> InertBootstrapIdentityV1 {
        InertBootstrapIdentityV1 {
            schema: BOOTSTRAP_SCHEMA_V1.into(),
            plan_id: machine.exact.prepared.plan_id.clone(),
            pod_name: "bedrock-pod".into(),
            pod_uid: "pod-uid".into(),
            container_id: "containerd://container-id".into(),
            node_uid: machine.deferred.node_uid.clone(),
            observed_at_unix_ms: 1250,
        }
    }

    fn runtime_recheck(
        machine: &DeferredCapacityMachineV1,
        bootstrap: &InertBootstrapIdentityV1,
    ) -> RuntimeCapacityRecheckV1 {
        RuntimeCapacityRecheckV1 {
            schema: RUNTIME_RECHECK_SCHEMA_V1.into(),
            plan_id: machine.exact.prepared.plan_id.clone(),
            pre_runtime_context_digest: semantic_digest(&machine.pre_runtime).unwrap(),
            deferred_obligation_digest: semantic_digest(&machine.deferred).unwrap(),
            bootstrap_digest: semantic_digest(bootstrap).unwrap(),
            procfs: ProcfsObservationV1 {
                mount: MountSourceV1 {
                    mount_id: 10,
                    parent_mount_id: 1,
                    device: "0:4".into(),
                    mount_point: "/proc".into(),
                    filesystem_type: "proc".into(),
                    source: "proc".into(),
                },
                cpus_allowed_list: "0-1".into(),
            },
            cgroup: CgroupObservationV1 {
                mount: MountSourceV1 {
                    mount_id: 11,
                    parent_mount_id: 1,
                    device: "0:28".into(),
                    mount_point: "/sys/fs/cgroup".into(),
                    filesystem_type: "cgroup2".into(),
                    source: "cgroup2".into(),
                },
                observer_cgroup_path: "/kubepods/pod-uid/container-id".into(),
                cpu_max: Some("max 100000".into()),
                cpuset_cpus_effective: Some("0-1".into()),
                memory_max: Some("268435456".into()),
            },
            available_parallelism: 2,
            placement_digest: machine.deferred.placement_digest.clone(),
            resource_envelope_digest: machine.deferred.resource_envelope_digest.clone(),
            observed_at_unix_ms: 1300,
            valid_until_unix_ms: 1500,
        }
    }

    #[test]
    fn deferred_machine_requires_bootstrap_runtime_claim_then_release() {
        let (mut machine, authorization, claim) = deferred_machine();
        machine.authorize(authorization).unwrap();
        assert!(machine.claim(claim.clone()).is_err());
        let bootstrap = bootstrap(&machine);
        machine.observe_bootstrap(bootstrap.clone()).unwrap();
        assert!(machine.claim(claim.clone()).is_err());
        assert!(machine.release(1350).is_err());
        let runtime = runtime_recheck(&machine, &bootstrap);
        machine.qualify_runtime(runtime, 1350).unwrap();
        assert!(machine.release(1350).is_err());
        machine.claim(claim.clone()).unwrap();
        let release = machine.release(1450).unwrap();
        assert_eq!(release.claim_id, claim.claim_id);
        machine
            .begin_execution(RuntimeBindingV1 {
                runtime_instance_id: semantic_digest(&bootstrap).unwrap(),
                oci_manifest_digest: machine
                    .exact
                    .prepared
                    .plan
                    .artifact
                    .oci_manifest_digest
                    .clone(),
                plan_id: machine.exact.prepared.plan_id.clone(),
                started_at_unix_ms: 1450,
            })
            .unwrap();
    }

    #[test]
    fn changed_bootstrap_node_and_runtime_links_refuse() {
        let (mut machine, authorization, _) = deferred_machine();
        machine.authorize(authorization).unwrap();
        let mut wrong = bootstrap(&machine);
        wrong.node_uid = "node-uid-b".into();
        assert!(machine.observe_bootstrap(wrong).is_err());
        let bootstrap = bootstrap(&machine);
        machine.observe_bootstrap(bootstrap.clone()).unwrap();
        let mut runtime = runtime_recheck(&machine, &bootstrap);
        runtime.resource_envelope_digest = digest("changed");
        assert!(machine.qualify_runtime(runtime, 1350).is_err());
    }

    #[test]
    fn pre_runtime_context_retains_mandatory_deferred_runtime_facts() {
        let (key, contract, basis) = fixture();
        let (context, deferred) = signed(&key, &basis)
            .verify_pre_runtime(&basis, &contract, &key.verifying_key(), 1200)
            .unwrap();
        assert_eq!(context.schema, PRE_RUNTIME_SCHEMA_V1);
        assert!(
            deferred.require_pod_uid
                && deferred.require_container_id
                && deferred.require_procfs_recheck
                && deferred.require_cgroup_recheck
                && deferred.require_available_parallelism_recheck
                && deferred.require_claim_fence_before_release
        );
    }

    #[test]
    fn changed_api_boot_resource_signature_and_stale_time_refuse() {
        let (key, contract, basis) = fixture();
        let observation = signed(&key, &basis);
        let mut changed = basis.clone();
        changed.node.uid = "node-uid-b".into();
        changed.placement.node_uid = changed.node.uid.clone();
        assert!(
            observation
                .verify_pre_runtime(&changed, &contract, &key.verifying_key(), 1200)
                .is_err()
        );
        let mut changed = basis.clone();
        changed.node.boot_id = "boot-b".into();
        assert!(
            observation
                .verify_pre_runtime(&changed, &contract, &key.verifying_key(), 1200)
                .is_err()
        );
        let mut changed = basis.clone();
        changed.resources.memory_limit_bytes = Some(536_870_912);
        assert!(
            observation
                .verify_pre_runtime(&changed, &contract, &key.verifying_key(), 1200)
                .is_err()
        );
        assert!(
            observation
                .verify_pre_runtime(
                    &basis,
                    &contract,
                    &SigningKey::from_bytes(&[30; 32]).verifying_key(),
                    1200
                )
                .is_err()
        );
        assert!(
            observation
                .verify_pre_runtime(&basis, &contract, &key.verifying_key(), 121_000)
                .is_err()
        );
    }

    #[test]
    fn cpu_limit_refuses_pre_runtime_projection() {
        let (_, contract, mut basis) = fixture();
        basis.resources.cpu_limit_millicores = Some(1000);
        assert!(basis.validate(&contract).is_err());
    }
}
