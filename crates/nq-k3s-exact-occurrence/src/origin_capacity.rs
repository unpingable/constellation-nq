//! Portable Kubernetes origin and capacity fact law for TURNSTILE.
//!
//! These facts grant no authority and choose no Kubernetes workload primitive.

use crate::{MAX_SAFE_JSON_INTEGER, OccurrenceError, OriginCapacityBindingV1, validate_token};
use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};

/// Closed fact schema.
pub const FACTS_SCHEMA_V1: &str = "nq.kubernetes_origin_capacity_facts.v1";
/// Existing qualified capacity-context schema.
pub const CAPACITY_SCHEMA_V1: &str = "nq.available_parallelism_context.v1";
/// Maximum life of one consequence-time projection.
pub const MAX_FACT_LIFETIME_MS: u64 = 300_000;

/// Closed semantic role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginRoleV1 {
    /// Workload subject/scope/vantage.
    WorkloadLocal,
    /// Qualified exact node-host delegation.
    NodeHostDelegated,
}

impl OriginRoleV1 {
    fn profile(self) -> &'static str {
        match self {
            Self::WorkloadLocal => "nq.kubernetes_workload_local_origin.v1",
            Self::NodeHostDelegated => "nq.kubernetes_node_host_delegated_origin.v1",
        }
    }
}

/// Exact cluster coordinate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterFactsV1 {
    /// UID of kube-system.
    pub kube_system_namespace_uid: String,
    /// API CA/SPKI identity.
    pub api_server_ca_digest: Sha256Digest,
    /// Qualified acquisition contract.
    pub acquisition_contract_digest: Sha256Digest,
}

/// Exact Kubernetes name/UID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedUidV1 {
    /// Name.
    pub name: String,
    /// Immutable UID.
    pub uid: String,
}

/// Subject/scope/vantage semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginSemanticsV1 {
    /// Closed role.
    pub role: OriginRoleV1,
    /// Exact subject.
    pub subject: Sha256Digest,
    /// Exact scope.
    pub scope: Sha256Digest,
    /// Exact vantage.
    pub vantage: Sha256Digest,
    /// Required only for node-host delegation.
    pub host_origin_contract_digest: Option<Sha256Digest>,
    /// Exact procfs source.
    pub procfs_source_digest: Sha256Digest,
    /// Exact cgroup source.
    pub cgroup_source_digest: Sha256Digest,
}

/// Placement independent of workload primitive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementFactsV1 {
    /// Node name.
    pub node_name: String,
    /// Node UID.
    pub node_uid: String,
    /// Optional provider coordinate.
    pub provider_coordinate_digest: Option<Sha256Digest>,
    /// Scheduler name.
    pub scheduler_name: String,
    /// Optional RuntimeClass.
    pub runtime_class_name: Option<String>,
    /// Closed V1 false.
    pub rescheduling_allowed: bool,
}

/// Stable base-unit resource envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceEnvelopeV1 {
    /// CPU request, millicores.
    pub cpu_request_millicores: u64,
    /// CPU limit.
    pub cpu_limit_millicores: Option<u64>,
    /// Memory request, bytes.
    pub memory_request_bytes: u64,
    /// Memory limit.
    pub memory_limit_bytes: Option<u64>,
    /// Storage request, bytes.
    pub storage_request_bytes: u64,
    /// Storage limit.
    pub storage_limit_bytes: Option<u64>,
}

/// Exact qualified capacity inputs and result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityContextV1 {
    /// Closed schema.
    pub schema: String,
    /// Proc status Cpus_allowed_list value.
    pub cpus_allowed_list: String,
    /// Closed value v2.
    pub cgroup_mode: String,
    /// Exact cpu.max.
    pub cpu_max: Option<String>,
    /// Exact effective cpuset.
    pub cpuset_cpus_effective: Option<String>,
    /// Rust result.
    pub available_parallelism: u32,
    /// Placement content identity.
    pub placement_digest: Sha256Digest,
    /// Resource content identity.
    pub resource_envelope_digest: Sha256Digest,
    /// Observation time.
    pub observed_at_unix_ms: u64,
    /// Exclusive expiry.
    pub valid_until_unix_ms: u64,
}

/// Complete portable fact projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesOriginCapacityFactsV1 {
    /// Closed schema.
    pub schema: String,
    /// Semantic origin.
    pub origin: OriginSemanticsV1,
    /// Cluster.
    pub cluster: ClusterFactsV1,
    /// Namespace.
    pub namespace: NamedUidV1,
    /// Service account.
    pub service_account: NamedUidV1,
    /// Exact mechanics/RBAC policy.
    pub mechanics_policy_digest: Sha256Digest,
    /// Placement.
    pub placement: PlacementFactsV1,
    /// Resources.
    pub resources: ResourceEnvelopeV1,
    /// Capacity.
    pub capacity: CapacityContextV1,
}

impl KubernetesOriginCapacityFactsV1 {
    /// Validates role, exact links, and consequence-time freshness.
    ///
    /// # Errors
    ///
    /// Refuses malformed, stale, widened, or content-inconsistent facts.
    pub fn validate_at(&self, at: u64) -> Result<(), OccurrenceError> {
        if self.schema != FACTS_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("origin/capacity schema"));
        }
        for (value, field) in [
            (&self.cluster.kube_system_namespace_uid, "cluster UID"),
            (&self.namespace.name, "namespace name"),
            (&self.namespace.uid, "namespace UID"),
            (&self.service_account.name, "service-account name"),
            (&self.service_account.uid, "service-account UID"),
            (&self.placement.node_name, "node name"),
            (&self.placement.node_uid, "node UID"),
            (&self.placement.scheduler_name, "scheduler name"),
            (&self.capacity.cpus_allowed_list, "Cpus_allowed_list"),
        ] {
            validate_token(value, field)?;
        }
        if let Some(value) = &self.placement.runtime_class_name {
            validate_token(value, "RuntimeClass")?;
        }
        if self.placement.rescheduling_allowed {
            return Err(OccurrenceError::InvalidPlan("rescheduling is outside V1"));
        }
        match self.origin.role {
            OriginRoleV1::WorkloadLocal if self.origin.host_origin_contract_digest.is_some() => {
                return Err(OccurrenceError::InvalidPlan(
                    "workload-local role cannot claim a host contract",
                ));
            }
            OriginRoleV1::NodeHostDelegated
                if self.origin.host_origin_contract_digest.is_none()
                    || self.origin.subject != self.origin.scope =>
            {
                return Err(OccurrenceError::InvalidPlan(
                    "node-host role requires one exact host coordinate and contract",
                ));
            }
            _ => {}
        }
        let resources = &self.resources;
        let invalid_limit = |request: u64, limit: Option<u64>| {
            limit.is_some_and(|value| value == 0 || request > value)
        };
        if resources.cpu_request_millicores == 0
            || resources.memory_request_bytes == 0
            || resources.storage_request_bytes == 0
            || invalid_limit(
                resources.cpu_request_millicores,
                resources.cpu_limit_millicores,
            )
            || invalid_limit(resources.memory_request_bytes, resources.memory_limit_bytes)
            || invalid_limit(
                resources.storage_request_bytes,
                resources.storage_limit_bytes,
            )
            || [
                resources.cpu_request_millicores,
                resources.memory_request_bytes,
                resources.storage_request_bytes,
            ]
            .into_iter()
            .any(|value| value > MAX_SAFE_JSON_INTEGER)
        {
            return Err(OccurrenceError::InvalidPlan("resource envelope"));
        }
        let capacity = &self.capacity;
        if capacity.schema != CAPACITY_SCHEMA_V1
            || capacity.cgroup_mode != "v2"
            || capacity.available_parallelism == 0
            || capacity.observed_at_unix_ms >= capacity.valid_until_unix_ms
            || capacity.valid_until_unix_ms > MAX_SAFE_JSON_INTEGER
            || capacity.valid_until_unix_ms - capacity.observed_at_unix_ms > MAX_FACT_LIFETIME_MS
            || !(capacity.observed_at_unix_ms..capacity.valid_until_unix_ms).contains(&at)
        {
            return Err(OccurrenceError::InvalidPlan("capacity context"));
        }
        for (value, field) in [
            (capacity.cpu_max.as_deref(), "cpu.max"),
            (
                capacity.cpuset_cpus_effective.as_deref(),
                "cpuset.cpus.effective",
            ),
        ] {
            if let Some(value) = value {
                validate_token(value, field)?;
            }
        }
        if capacity.placement_digest != semantic_digest(&self.placement)?
            || capacity.resource_envelope_digest != semantic_digest(&self.resources)?
        {
            return Err(OccurrenceError::ReplayConflict("capacity fact links"));
        }
        Ok(())
    }

    /// Produces the immutable T0 binding.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as validate_at.
    pub fn binding_at(&self, at: u64) -> Result<OriginCapacityBindingV1, OccurrenceError> {
        self.validate_at(at)?;
        Ok(OriginCapacityBindingV1 {
            origin_profile: self.origin.role.profile().into(),
            subject: self.origin.subject.clone(),
            scope: self.origin.scope.clone(),
            vantage: self.origin.vantage.clone(),
            cluster: semantic_digest(&self.cluster)?,
            namespace_uid: semantic_digest(&self.namespace.uid)?,
            service_account_uid: semantic_digest(&self.service_account.uid)?,
            placement_digest: semantic_digest(&self.placement)?,
            resource_envelope_digest: semantic_digest(&self.resources)?,
            capacity_context_digest: semantic_digest(&self.capacity)?,
        })
    }

    /// Rechecks exact content against T0.
    ///
    /// # Errors
    ///
    /// Refuses invalid facts or any binding substitution.
    pub fn verify_binding(
        &self,
        binding: &OriginCapacityBindingV1,
        at: u64,
    ) -> Result<(), OccurrenceError> {
        if self.binding_at(at)? != *binding {
            return Err(OccurrenceError::ReplayConflict("origin/capacity facts"));
        }
        Ok(())
    }

    /// Requires current passive host-load semantics.
    ///
    /// # Errors
    ///
    /// Refuses workload-local facts because they do not establish host semantics.
    pub fn require_passive_host_role(&self) -> Result<(), OccurrenceError> {
        if self.origin.role != OriginRoleV1::NodeHostDelegated {
            return Err(OccurrenceError::InvalidPlan(
                "workload-local facts do not establish passive host semantics",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_protocol::sha256_bytes;

    fn digest(value: &str) -> Sha256Digest {
        sha256_bytes(value.as_bytes())
    }

    fn facts() -> KubernetesOriginCapacityFactsV1 {
        let placement = PlacementFactsV1 {
            node_name: "turnstile-node-a".into(),
            node_uid: "491eb0c1-a529-43f3-907f-c180407b5d5f".into(),
            provider_coordinate_digest: Some(digest("provider-node")),
            scheduler_name: "default-scheduler".into(),
            runtime_class_name: Some("runc".into()),
            rescheduling_allowed: false,
        };
        let resources = ResourceEnvelopeV1 {
            cpu_request_millicores: 500,
            cpu_limit_millicores: Some(1000),
            memory_request_bytes: 268_435_456,
            memory_limit_bytes: Some(536_870_912),
            storage_request_bytes: 1_073_741_824,
            storage_limit_bytes: Some(2_147_483_648),
        };
        let mut facts = KubernetesOriginCapacityFactsV1 {
            schema: FACTS_SCHEMA_V1.into(),
            origin: OriginSemanticsV1 {
                role: OriginRoleV1::NodeHostDelegated,
                subject: digest("node-host"),
                scope: digest("node-host"),
                vantage: digest("node-local"),
                host_origin_contract_digest: Some(digest("host-contract")),
                procfs_source_digest: digest("node-procfs"),
                cgroup_source_digest: digest("workload-cgroup"),
            },
            cluster: ClusterFactsV1 {
                kube_system_namespace_uid: "5de940de-1884-4e29-abbd-59bca29c67cf".into(),
                api_server_ca_digest: digest("cluster-ca"),
                acquisition_contract_digest: digest("fact-contract"),
            },
            namespace: NamedUidV1 {
                name: "turnstile".into(),
                uid: "c7ba1597-bf05-45cd-869e-389722908fc5".into(),
            },
            service_account: NamedUidV1 {
                name: "turnstile-executor".into(),
                uid: "2c014201-fca1-486b-ad92-918b206789a0".into(),
            },
            mechanics_policy_digest: digest("mechanics-policy"),
            placement,
            resources,
            capacity: CapacityContextV1 {
                schema: CAPACITY_SCHEMA_V1.into(),
                cpus_allowed_list: "0".into(),
                cgroup_mode: "v2".into(),
                cpu_max: Some("100000 100000".into()),
                cpuset_cpus_effective: Some("0".into()),
                available_parallelism: 1,
                placement_digest: digest("unset"),
                resource_envelope_digest: digest("unset"),
                observed_at_unix_ms: 1000,
                valid_until_unix_ms: 2000,
            },
        };
        facts.capacity.placement_digest = semantic_digest(&facts.placement).unwrap();
        facts.capacity.resource_envelope_digest = semantic_digest(&facts.resources).unwrap();
        facts
    }

    #[test]
    fn node_facts_bind_and_pass_host_role() {
        let facts = facts();
        let binding = facts.binding_at(1500).unwrap();
        facts.verify_binding(&binding, 1500).unwrap();
        facts.require_passive_host_role().unwrap();
    }

    #[test]
    fn workload_facts_cannot_be_promoted() {
        let mut facts = facts();
        facts.origin.role = OriginRoleV1::WorkloadLocal;
        facts.origin.host_origin_contract_digest = None;
        facts.binding_at(1500).unwrap();
        assert!(facts.require_passive_host_role().is_err());
    }

    #[test]
    fn relocation_staleness_and_cgroup_v1_refuse() {
        let mut relocated = facts();
        relocated.placement.rescheduling_allowed = true;
        relocated.capacity.placement_digest = semantic_digest(&relocated.placement).unwrap();
        assert!(relocated.binding_at(1500).is_err());
        assert!(facts().binding_at(2000).is_err());
        let mut cgroup_v1 = facts();
        cgroup_v1.capacity.cgroup_mode = "v1".into();
        assert!(cgroup_v1.binding_at(1500).is_err());
    }

    #[test]
    fn changed_resources_break_capacity_link() {
        let mut facts = facts();
        facts.resources.memory_limit_bytes = Some(805_306_368);
        assert!(matches!(
            facts.binding_at(1500),
            Err(OccurrenceError::ReplayConflict("capacity fact links"))
        ));
    }

    #[test]
    fn uid_change_changes_binding_with_same_name() {
        let facts = facts();
        let first = facts.binding_at(1500).unwrap();
        let mut other = facts.clone();
        other.namespace.uid = "006cdb8a-06fb-46eb-81d6-2ebec7777d39".into();
        assert_ne!(
            first.namespace_uid,
            other.binding_at(1500).unwrap().namespace_uid
        );
    }
}
