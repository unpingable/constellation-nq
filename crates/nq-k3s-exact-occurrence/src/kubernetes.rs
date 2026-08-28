//! Closed bare-Pod representation for TURNSTILE.
//!
//! This module creates no Kubernetes objects. It deterministically projects an
//! already-authorized exact occurrence into one closed Pod document and
//! classifies runtime observations without granting authority.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};

use crate::artifact_evidence::{ExternalEvidenceCustodyV1, OciArtifactFactsV1};
use crate::origin_capacity::{
    KubernetesOriginCapacityFactsV1, NamedUidV1, PlacementFactsV1, ResourceEnvelopeV1,
};
use crate::{
    AuthorizationBindingV1, CAMPAIGN_SLUG, ExactOccurrenceMachineV1, OccurrenceError,
    PreparedOccurrenceV1, RuntimeBindingV1, validate_token,
};

/// Closed template schema.
pub const BARE_POD_TEMPLATE_SCHEMA_V1: &str = "nq.turnstile_bare_pod_template.v1";
/// Configuration binding name carrying the template identity in T0.
pub const BARE_POD_TEMPLATE_CONFIG_NAME_V1: &str = "turnstile-bare-pod-template.v1";
/// Closed Kubernetes API version.
pub const POD_API_VERSION_V1: &str = "v1";
/// Closed Kubernetes object kind.
pub const POD_KIND_V1: &str = "Pod";
const MAX_VOLUMES: usize = 3;

/// Closed custody-volume role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeRoleV1 {
    /// Canonical NQ retain-all sample/acquisition custody.
    CanonicalNqCustody,
    /// TURNSTILE append-only external journal.
    ExternalJournal,
    /// External terminal receipt destination.
    TerminalReceipts,
}

/// One exact retained persistent-volume claim and mount.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentVolumeBindingV1 {
    /// Closed semantic role.
    pub role: VolumeRoleV1,
    /// Content identity required by the T0 plan.
    pub custody_id: Sha256Digest,
    /// PVC name.
    pub claim_name: String,
    /// PVC UID.
    pub claim_uid: String,
    /// Bound persistent-volume UID.
    pub persistent_volume_uid: String,
    /// Public CSI/volume-handle identity.
    pub volume_handle_digest: Sha256Digest,
    /// Closed value `Retain`.
    pub reclaim_policy: String,
    /// Absolute in-container mount path.
    pub mount_path: String,
}

/// Closed non-privileged container security representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSecurityV1 {
    /// Must be true.
    pub run_as_non_root: bool,
    /// Must be false.
    pub allow_privilege_escalation: bool,
    /// Must be true; writes occur only in exact retained mounts.
    pub read_only_root_filesystem: bool,
    /// Must be true.
    pub drop_all_capabilities: bool,
    /// Closed value `RuntimeDefault`.
    pub seccomp_profile: String,
}

/// Immutable static Pod template bound by T0 configuration identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BarePodTemplateV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact namespace name/UID.
    pub namespace: NamedUidV1,
    /// Exact service-account name/UID.
    pub service_account: NamedUidV1,
    /// Exact admitted placement.
    pub placement: PlacementFactsV1,
    /// Exact admitted resource envelope.
    pub resources: ResourceEnvelopeV1,
    /// Exact digest-only image reference.
    pub image_reference: String,
    /// Exact top-level OCI digest.
    pub image_digest: Sha256Digest,
    /// One authority-bearing container name.
    pub container_name: String,
    /// Exact retained volumes; V1 requires all three roles.
    pub volumes: Vec<PersistentVolumeBindingV1>,
    /// Non-privileged container law.
    pub security: ContainerSecurityV1,
    /// Exact whole-second deadline.
    pub active_deadline_seconds: u64,
    /// Must be true: use OCI config entrypoint/arguments without overrides.
    pub use_oci_default_invocation: bool,
}

/// Closed Kubernetes object metadata. Owner references are unrepresentable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodMetadataV1 {
    /// Deterministic exact-attempt name.
    pub name: String,
    /// Exact namespace name.
    pub namespace: String,
    /// Immutable TURNSTILE annotations.
    pub annotations: BTreeMap<String, String>,
}

/// Persistent-volume claim reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistentVolumeClaimSourceV1 {
    /// Exact PVC name.
    pub claim_name: String,
    /// Must be false for retain-all append custody.
    pub read_only: bool,
}

/// Closed Pod volume.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodVolumeV1 {
    /// Stable role-derived name.
    pub name: String,
    /// Exact PVC source.
    pub persistent_volume_claim: PersistentVolumeClaimSourceV1,
}

/// Closed container volume mount.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodVolumeMountV1 {
    /// Stable role-derived name.
    pub name: String,
    /// Exact absolute path.
    pub mount_path: String,
    /// Must be false for append custody.
    pub read_only: bool,
}

/// Closed Pod container. Empty environment and absent command/args are exact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodContainerV1 {
    /// Exact authority-bearing container name.
    pub name: String,
    /// Digest-only image reference.
    pub image: String,
    /// Closed value `IfNotPresent`.
    pub image_pull_policy: String,
    /// Must remain absent to use the OCI config entrypoint.
    pub command: Option<Vec<String>>,
    /// Must remain absent to use the OCI config arguments.
    pub args: Option<Vec<String>>,
    /// Must remain empty in V1.
    pub env: BTreeMap<String, String>,
    /// Exact resources.
    pub resources: ResourceEnvelopeV1,
    /// Exact non-privileged security context.
    pub security_context: ContainerSecurityV1,
    /// Exact retained mounts.
    pub volume_mounts: Vec<PodVolumeMountV1>,
}

/// Closed Pod spec. Controller, replica, retry, and init-container fields are
/// unrepresentable and unknown JSON members refuse deserialization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BarePodSpecV1 {
    /// Exact service-account name.
    pub service_account_name: String,
    /// Must be false.
    pub automount_service_account_token: bool,
    /// Closed value `Never`.
    pub restart_policy: String,
    /// Exact node name; relocation is outside V1.
    pub node_name: String,
    /// Exact scheduler.
    pub scheduler_name: String,
    /// Optional exact RuntimeClass.
    pub runtime_class_name: Option<String>,
    /// Exact deadline.
    pub active_deadline_seconds: u64,
    /// Exactly one container.
    pub containers: Vec<PodContainerV1>,
    /// Exactly three retained volumes.
    pub volumes: Vec<PodVolumeV1>,
}

/// Exact authority-neutral bare-Pod API document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BarePodDocumentV1 {
    /// Closed value `v1`.
    pub api_version: String,
    /// Closed value `Pod`.
    pub kind: String,
    /// Closed metadata.
    pub metadata: PodMetadataV1,
    /// Closed spec.
    pub spec: BarePodSpecV1,
}

/// Exact inputs for one deterministic Pod projection.
pub struct PodProjectionContextV1<'a> {
    /// Immutable prepared occurrence.
    pub prepared: &'a PreparedOccurrenceV1,
    /// Exact AG/Docket authorization.
    pub authorization: &'a AuthorizationBindingV1,
    /// Exact OCI facts.
    pub artifact: &'a OciArtifactFactsV1,
    /// Exact current origin/capacity facts.
    pub origin: &'a KubernetesOriginCapacityFactsV1,
    /// Exact external evidence custody.
    pub custody: &'a ExternalEvidenceCustodyV1,
    /// Consequence-time fact-check time.
    pub at_unix_ms: u64,
}

impl BarePodTemplateV1 {
    /// Validates and projects one exact authorized occurrence into a Pod.
    ///
    /// # Errors
    ///
    /// Refuses any T0/T2/T3/template/authorization substitution or widened
    /// mechanics representation.
    pub fn build_pod(
        &self,
        context: &PodProjectionContextV1<'_>,
    ) -> Result<BarePodDocumentV1, OccurrenceError> {
        let prepared = context.prepared;
        let authorization = context.authorization;
        let artifact = context.artifact;
        let origin = context.origin;
        let custody = context.custody;
        let at_unix_ms = context.at_unix_ms;
        prepared.validate()?;
        artifact.verify_binding(&prepared.plan.artifact)?;
        origin.verify_binding(&prepared.plan.origin_capacity, at_unix_ms)?;
        origin.require_passive_host_role()?;
        custody.verify_binding(&prepared.plan.evidence)?;
        let mut machine = ExactOccurrenceMachineV1::prepare(prepared.clone())?;
        machine.authorize(authorization.clone())?;
        self.validate_static(prepared, artifact, origin)?;

        let pod_name = pod_name(&authorization.docket_attempt);
        let template_digest = semantic_digest(self)?;
        let annotations = BTreeMap::from([
            ("nq.openai.com/campaign".into(), CAMPAIGN_SLUG.into()),
            ("nq.openai.com/plan".into(), prepared.plan_id.to_string()),
            (
                "nq.openai.com/occurrence".into(),
                prepared.plan.nq.occurrence_id.to_string(),
            ),
            (
                "nq.openai.com/ag-issuance".into(),
                authorization.ag_issuance.to_string(),
            ),
            (
                "nq.openai.com/docket-attempt".into(),
                authorization.docket_attempt.to_string(),
            ),
            (
                "nq.openai.com/docket-marker".into(),
                authorization.docket_marker.to_string(),
            ),
            ("nq.openai.com/template".into(), template_digest.to_string()),
            (
                "nq.openai.com/oci-manifest".into(),
                self.image_digest.to_string(),
            ),
            (
                "nq.openai.com/external-journal".into(),
                custody.journal_id.to_string(),
            ),
        ]);
        let containers = vec![PodContainerV1 {
            name: self.container_name.clone(),
            image: self.image_reference.clone(),
            image_pull_policy: "IfNotPresent".into(),
            command: None,
            args: None,
            env: BTreeMap::new(),
            resources: self.resources.clone(),
            security_context: self.security.clone(),
            volume_mounts: self
                .volumes
                .iter()
                .map(|volume| PodVolumeMountV1 {
                    name: volume_name(volume.role).into(),
                    mount_path: volume.mount_path.clone(),
                    read_only: false,
                })
                .collect(),
        }];
        let volumes = self
            .volumes
            .iter()
            .map(|volume| PodVolumeV1 {
                name: volume_name(volume.role).into(),
                persistent_volume_claim: PersistentVolumeClaimSourceV1 {
                    claim_name: volume.claim_name.clone(),
                    read_only: false,
                },
            })
            .collect();
        Ok(BarePodDocumentV1 {
            api_version: POD_API_VERSION_V1.into(),
            kind: POD_KIND_V1.into(),
            metadata: PodMetadataV1 {
                name: pod_name,
                namespace: self.namespace.name.clone(),
                annotations,
            },
            spec: BarePodSpecV1 {
                service_account_name: self.service_account.name.clone(),
                automount_service_account_token: false,
                restart_policy: "Never".into(),
                node_name: self.placement.node_name.clone(),
                scheduler_name: self.placement.scheduler_name.clone(),
                runtime_class_name: self.placement.runtime_class_name.clone(),
                active_deadline_seconds: self.active_deadline_seconds,
                containers,
                volumes,
            },
        })
    }

    /// Rebuilds the only admitted document and compares every field.
    ///
    /// # Errors
    ///
    /// Refuses any document mutation, added field (during deserialization), or
    /// substituted execution binding.
    pub fn verify_pod(
        &self,
        candidate: &BarePodDocumentV1,
        context: &PodProjectionContextV1<'_>,
    ) -> Result<(), OccurrenceError> {
        if *candidate != self.build_pod(context)? {
            return Err(OccurrenceError::ReplayConflict("bare Pod document"));
        }
        Ok(())
    }

    fn validate_static(
        &self,
        prepared: &PreparedOccurrenceV1,
        artifact: &OciArtifactFactsV1,
        origin: &KubernetesOriginCapacityFactsV1,
    ) -> Result<(), OccurrenceError> {
        if self.schema != BARE_POD_TEMPLATE_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("bare Pod template schema"));
        }
        let expected_template = prepared
            .plan
            .artifact
            .configuration_digests
            .get(BARE_POD_TEMPLATE_CONFIG_NAME_V1)
            .ok_or(OccurrenceError::InvalidPlan(
                "missing bare Pod template binding",
            ))?;
        if &semantic_digest(self)? != expected_template {
            return Err(OccurrenceError::ReplayConflict("bare Pod template content"));
        }
        if self.namespace != origin.namespace
            || self.service_account != origin.service_account
            || self.placement != origin.placement
            || self.resources != origin.resources
            || self.image_reference != artifact.image_reference
            || self.image_digest != artifact.manifest_digest
        {
            return Err(OccurrenceError::ReplayConflict("bare Pod static facts"));
        }
        validate_token(&self.container_name, "Pod container name")?;
        if !self.use_oci_default_invocation
            || !self.security.run_as_non_root
            || self.security.allow_privilege_escalation
            || !self.security.read_only_root_filesystem
            || !self.security.drop_all_capabilities
            || self.security.seccomp_profile != "RuntimeDefault"
        {
            return Err(OccurrenceError::InvalidPlan(
                "bare Pod security/invocation law",
            ));
        }
        let expected_deadline = prepared.plan.lifetime.max_runtime_ms.div_ceil(1000);
        if self.active_deadline_seconds == 0 || self.active_deadline_seconds != expected_deadline {
            return Err(OccurrenceError::InvalidPlan("bare Pod active deadline"));
        }
        self.validate_volumes(prepared)
    }

    fn validate_volumes(&self, prepared: &PreparedOccurrenceV1) -> Result<(), OccurrenceError> {
        if self.volumes.len() != MAX_VOLUMES {
            return Err(OccurrenceError::InvalidPlan("bare Pod volume cardinality"));
        }
        let mut roles = BTreeSet::new();
        let mut claims = BTreeSet::new();
        let mut mounts = BTreeSet::new();
        for volume in &self.volumes {
            for (value, field) in [
                (&volume.claim_name, "PVC name"),
                (&volume.claim_uid, "PVC UID"),
                (&volume.persistent_volume_uid, "PV UID"),
            ] {
                validate_token(value, field)?;
            }
            if volume.reclaim_policy != "Retain"
                || !volume.mount_path.starts_with('/')
                || volume.mount_path == "/"
                || !roles.insert(volume.role)
                || !claims.insert(&volume.claim_uid)
                || !mounts.insert(&volume.mount_path)
            {
                return Err(OccurrenceError::InvalidPlan("bare Pod retained volume"));
            }
            let expected = match volume.role {
                VolumeRoleV1::CanonicalNqCustody => &prepared.plan.evidence.canonical_custody_id,
                VolumeRoleV1::ExternalJournal => &prepared.plan.evidence.external_journal_id,
                VolumeRoleV1::TerminalReceipts => &prepared.plan.evidence.receipt_destination_id,
            };
            if &volume.custody_id != expected {
                return Err(OccurrenceError::ReplayConflict("bare Pod volume custody"));
            }
        }
        Ok(())
    }
}

/// Exact runtime identity observed after create mechanics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesRuntimeIdentityV1 {
    /// Cluster identity from T0/T2.
    pub cluster: Sha256Digest,
    /// Exact namespace UID.
    pub namespace_uid: Sha256Digest,
    /// Kubernetes-assigned Pod UID.
    pub pod_uid: String,
    /// First authority-bearing container ID.
    pub container_id: String,
}

/// Runtime observation needed for exact-occurrence classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PodRuntimeFactsV1 {
    /// Observed Pod name.
    pub pod_name: String,
    /// Kubernetes-assigned Pod UID.
    pub pod_uid: String,
    /// First authority-bearing container ID, once created.
    pub container_id: Option<String>,
    /// Authority-bearing container restart count.
    pub restart_count: u32,
    /// Exact observed image identity.
    pub image_digest: Sha256Digest,
    /// Owner-reference count; V1 requires zero.
    pub owner_reference_count: u32,
    /// Whether deletion was already requested.
    pub deletion_pending: bool,
    /// Observation time.
    pub observed_at_unix_ms: u64,
}

/// Closed runtime observation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeObservationClassV1 {
    /// Exact originally retained runtime continues.
    SameExactRuntime,
    /// Pod exists but the authority-bearing container has not started.
    NotStarted,
    /// A different UID/container or restart was observed.
    DifferentRuntime,
    /// The exact runtime disappeared without a definite retained result.
    OutcomeUnknown,
}

/// Converts the first exact runtime facts into the T0/T1 runtime binding.
///
/// # Errors
///
/// Refuses wrong name/image, owner adoption, restart, deletion, missing
/// container identity, or malformed runtime identity.
pub fn bind_first_runtime(
    pod: &BarePodDocumentV1,
    prepared: &PreparedOccurrenceV1,
    facts: &PodRuntimeFactsV1,
) -> Result<RuntimeBindingV1, OccurrenceError> {
    if facts.pod_name != pod.metadata.name
        || facts.image_digest != prepared.plan.artifact.oci_manifest_digest
        || facts.owner_reference_count != 0
        || facts.restart_count != 0
        || facts.deletion_pending
    {
        return Err(OccurrenceError::ReplayConflict("bare Pod runtime facts"));
    }
    validate_token(&facts.pod_uid, "Pod UID")?;
    let container_id = facts
        .container_id
        .as_ref()
        .ok_or(OccurrenceError::InvalidPlan("Pod container not started"))?;
    validate_token(container_id, "container ID")?;
    let identity = KubernetesRuntimeIdentityV1 {
        cluster: prepared.plan.origin_capacity.cluster.clone(),
        namespace_uid: prepared.plan.origin_capacity.namespace_uid.clone(),
        pod_uid: facts.pod_uid.clone(),
        container_id: container_id.clone(),
    };
    Ok(RuntimeBindingV1 {
        runtime_instance_id: semantic_digest(&identity)?,
        oci_manifest_digest: facts.image_digest.clone(),
        plan_id: prepared.plan_id.clone(),
        started_at_unix_ms: facts.observed_at_unix_ms,
    })
}

/// Reconciles one observation without creating, replacing, or restarting work.
#[must_use]
pub fn classify_runtime_observation(
    pod: &BarePodDocumentV1,
    prepared: &PreparedOccurrenceV1,
    retained: Option<&RuntimeBindingV1>,
    facts: Option<&PodRuntimeFactsV1>,
) -> RuntimeObservationClassV1 {
    let Some(facts) = facts else {
        return if retained.is_some() {
            RuntimeObservationClassV1::OutcomeUnknown
        } else {
            RuntimeObservationClassV1::NotStarted
        };
    };
    let Some(container_id) = &facts.container_id else {
        return if retained.is_some() {
            RuntimeObservationClassV1::DifferentRuntime
        } else {
            RuntimeObservationClassV1::NotStarted
        };
    };
    let identity = KubernetesRuntimeIdentityV1 {
        cluster: prepared.plan.origin_capacity.cluster.clone(),
        namespace_uid: prepared.plan.origin_capacity.namespace_uid.clone(),
        pod_uid: facts.pod_uid.clone(),
        container_id: container_id.clone(),
    };
    let identity = semantic_digest(&identity).ok();
    if facts.pod_name != pod.metadata.name
        || facts.image_digest != prepared.plan.artifact.oci_manifest_digest
        || facts.owner_reference_count != 0
        || facts.restart_count != 0
        || facts.deletion_pending
        || retained.is_some_and(|runtime| Some(&runtime.runtime_instance_id) != identity.as_ref())
    {
        RuntimeObservationClassV1::DifferentRuntime
    } else if retained.is_some() {
        RuntimeObservationClassV1::SameExactRuntime
    } else {
        RuntimeObservationClassV1::DifferentRuntime
    }
}

fn pod_name(attempt: &Sha256Digest) -> String {
    format!(
        "turnstile-{}",
        attempt.as_str().trim_start_matches("sha256:")
    )
}

const fn volume_name(role: VolumeRoleV1) -> &'static str {
    match role {
        VolumeRoleV1::CanonicalNqCustody => "nq-canonical",
        VolumeRoleV1::ExternalJournal => "turnstile-journal",
        VolumeRoleV1::TerminalReceipts => "turnstile-receipts",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nq_protocol::sha256_bytes;

    use super::*;
    use crate::artifact_evidence::{
        EXTERNAL_CUSTODY_SCHEMA_V1, OCI_FACTS_SCHEMA_V1, OciLayerV1, OciObjectKindV1, OciPlatformV1,
    };
    use crate::origin_capacity::{
        CAPACITY_SCHEMA_V1, CapacityContextV1, ClusterFactsV1, FACTS_SCHEMA_V1, OriginRoleV1,
        OriginSemanticsV1,
    };
    use crate::{
        ArtifactBindingV1, CardinalityBindingV1, CoordinationBindingV1, EXECUTOR_WORK_SCHEMA_V1,
        EvidenceBindingV1, LifetimeBindingV1, NqAuthorityBindingV1, PREPARED_PLAN_SCHEMA_V1,
        PreparedOccurrencePlanV1,
    };

    fn digest(value: &str) -> Sha256Digest {
        sha256_bytes(value.as_bytes())
    }

    struct Fixture {
        prepared: PreparedOccurrenceV1,
        authorization: AuthorizationBindingV1,
        artifact: OciArtifactFactsV1,
        origin: KubernetesOriginCapacityFactsV1,
        custody: ExternalEvidenceCustodyV1,
        template: BarePodTemplateV1,
    }

    fn fixture() -> Fixture {
        let placement = PlacementFactsV1 {
            node_name: "node-a".into(),
            node_uid: "node-uid-a".into(),
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
        let namespace = NamedUidV1 {
            name: "turnstile".into(),
            uid: "namespace-uid".into(),
        };
        let service_account = NamedUidV1 {
            name: "turnstile-executor".into(),
            uid: "service-account-uid".into(),
        };
        let image_digest = digest("manifest");
        let image_reference = format!("registry.invalid/nq@{image_digest}");
        let evidence = EvidenceBindingV1 {
            canonical_custody_id: digest("canonical"),
            selection_contract_digest: digest("selection"),
            external_journal_id: digest("journal"),
            receipt_destination_id: digest("receipts"),
            required_free_bytes: 10 * 1024 * 1024 * 1024,
            retention_mode: "retain_all".into(),
        };
        let volumes = vec![
            PersistentVolumeBindingV1 {
                role: VolumeRoleV1::CanonicalNqCustody,
                custody_id: evidence.canonical_custody_id.clone(),
                claim_name: "nq-canonical".into(),
                claim_uid: "pvc-canonical".into(),
                persistent_volume_uid: "pv-canonical".into(),
                volume_handle_digest: digest("volume-canonical"),
                reclaim_policy: "Retain".into(),
                mount_path: "/var/lib/nq".into(),
            },
            PersistentVolumeBindingV1 {
                role: VolumeRoleV1::ExternalJournal,
                custody_id: evidence.external_journal_id.clone(),
                claim_name: "turnstile-journal".into(),
                claim_uid: "pvc-journal".into(),
                persistent_volume_uid: "pv-journal".into(),
                volume_handle_digest: digest("volume-journal"),
                reclaim_policy: "Retain".into(),
                mount_path: "/var/lib/turnstile/journal".into(),
            },
            PersistentVolumeBindingV1 {
                role: VolumeRoleV1::TerminalReceipts,
                custody_id: evidence.receipt_destination_id.clone(),
                claim_name: "turnstile-receipts".into(),
                claim_uid: "pvc-receipts".into(),
                persistent_volume_uid: "pv-receipts".into(),
                volume_handle_digest: digest("volume-receipts"),
                reclaim_policy: "Retain".into(),
                mount_path: "/var/lib/turnstile/receipts".into(),
            },
        ];
        let template = BarePodTemplateV1 {
            schema: BARE_POD_TEMPLATE_SCHEMA_V1.into(),
            namespace: namespace.clone(),
            service_account: service_account.clone(),
            placement: placement.clone(),
            resources: resources.clone(),
            image_reference: image_reference.clone(),
            image_digest: image_digest.clone(),
            container_name: "nq-occurrence".into(),
            volumes,
            security: ContainerSecurityV1 {
                run_as_non_root: true,
                allow_privilege_escalation: false,
                read_only_root_filesystem: true,
                drop_all_capabilities: true,
                seccomp_profile: "RuntimeDefault".into(),
            },
            active_deadline_seconds: 60,
            use_oci_default_invocation: true,
        };
        let template_digest = semantic_digest(&template).unwrap();
        let artifact_binding = ArtifactBindingV1 {
            source_commit: "675e247e85d8e2e1f2801c06445bf863f82b3a5b".into(),
            oci_manifest_digest: image_digest.clone(),
            nq_executable_digest: digest("nq"),
            passive_helper_digest: digest("helper"),
            configuration_digests: BTreeMap::from([(
                BARE_POD_TEMPLATE_CONFIG_NAME_V1.into(),
                template_digest,
            )]),
        };
        let artifact = OciArtifactFactsV1 {
            schema: OCI_FACTS_SCHEMA_V1.into(),
            image_reference,
            object_kind: OciObjectKindV1::ImageManifest,
            manifest_digest: image_digest,
            selected_manifest_digest: None,
            image_config_digest: digest("image-config"),
            platform: OciPlatformV1 {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None,
            },
            layers: vec![OciLayerV1 {
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
                digest: digest("layer"),
                size_bytes: 4096,
            }],
            source_commit: artifact_binding.source_commit.clone(),
            nq_executable_digest: artifact_binding.nq_executable_digest.clone(),
            passive_helper_digest: artifact_binding.passive_helper_digest.clone(),
            configuration_digests: artifact_binding.configuration_digests.clone(),
        };
        let mut origin = KubernetesOriginCapacityFactsV1 {
            schema: FACTS_SCHEMA_V1.into(),
            origin: OriginSemanticsV1 {
                role: OriginRoleV1::NodeHostDelegated,
                subject: digest("host"),
                scope: digest("host"),
                vantage: digest("node-local"),
                host_origin_contract_digest: Some(digest("host-contract")),
                procfs_source_digest: digest("procfs"),
                cgroup_source_digest: digest("cgroup"),
            },
            cluster: ClusterFactsV1 {
                kube_system_namespace_uid: "cluster-uid".into(),
                api_server_ca_digest: digest("cluster-ca"),
                acquisition_contract_digest: digest("origin-contract"),
            },
            namespace,
            service_account,
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
        origin.capacity.placement_digest = semantic_digest(&origin.placement).unwrap();
        origin.capacity.resource_envelope_digest = semantic_digest(&origin.resources).unwrap();
        let origin_binding = origin.binding_at(1500).unwrap();
        let plan = PreparedOccurrencePlanV1 {
            schema: PREPARED_PLAN_SCHEMA_V1.into(),
            campaign: crate::CAMPAIGN_NAME.into(),
            campaign_slug: CAMPAIGN_SLUG.into(),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.into(),
            nq: NqAuthorityBindingV1 {
                occurrence_id: digest("occurrence"),
                h_grant_id: "h".into(),
                g_grant_id: "g".into(),
                e_grant_id: "e".into(),
                watcher_id: "watcher".into(),
                admission_id: "admission".into(),
                enrollment_id: digest("enrollment"),
                succession_relation_id: None,
                recurrence_slot: 1,
                selected_sample_id: digest("sample"),
                selected_sample_digest: digest("sample-doc"),
            },
            artifact: artifact_binding,
            origin_capacity: origin_binding,
            coordination: CoordinationBindingV1 {
                domain_id: "turnstile:test".into(),
                fencing_epoch: 1,
                provider_safe_spacing_ms: 100,
            },
            evidence: evidence.clone(),
            lifetime: LifetimeBindingV1 {
                not_before_unix_ms: 1000,
                expires_at_unix_ms: 2000,
                max_runtime_ms: 60_000,
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
            docket_attempt: digest("attempt"),
            docket_marker: digest("marker"),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.into(),
            subject: prepared.plan.origin_capacity.subject.clone(),
            scope: prepared.plan.origin_capacity.scope.clone(),
            authorized_at_unix_ms: 1500,
        };
        let custody = ExternalEvidenceCustodyV1 {
            schema: EXTERNAL_CUSTODY_SCHEMA_V1.into(),
            journal_id: evidence.external_journal_id,
            receipt_destination_id: evidence.receipt_destination_id,
            outside_workload_ephemeral_state: true,
            append_only: true,
            retention_mode: "retain_all".into(),
            encoding: "rfc8785_jcs".into(),
            durability_law: "sync_event_then_parent_directory_v1".into(),
            writer_domain: digest("writer-domain"),
        };
        Fixture {
            prepared,
            authorization,
            artifact,
            origin,
            custody,
            template,
        }
    }

    fn context(fixture: &Fixture) -> PodProjectionContextV1<'_> {
        PodProjectionContextV1 {
            prepared: &fixture.prepared,
            authorization: &fixture.authorization,
            artifact: &fixture.artifact,
            origin: &fixture.origin,
            custody: &fixture.custody,
            at_unix_ms: 1500,
        }
    }

    #[test]
    fn exact_authorized_plan_builds_one_ownerless_nonrestarting_pod() {
        let f = fixture();
        let pod = f.template.build_pod(&context(&f)).unwrap();
        assert_eq!(pod.kind, "Pod");
        assert_eq!(pod.spec.restart_policy, "Never");
        assert_eq!(pod.spec.containers.len(), 1);
        assert_eq!(pod.spec.volumes.len(), 3);
        assert!(!pod.spec.automount_service_account_token);
        assert!(pod.spec.containers[0].command.is_none());
        f.template.verify_pod(&pod, &context(&f)).unwrap();
    }

    #[test]
    fn template_pod_and_namespace_substitutions_refuse() {
        let mut f = fixture();
        f.template.security.allow_privilege_escalation = true;
        assert!(f.template.build_pod(&context(&f)).is_err());
        let f = fixture();
        let mut pod = f.template.build_pod(&context(&f)).unwrap();
        pod.spec.restart_policy = "Always".into();
        assert!(f.template.verify_pod(&pod, &context(&f)).is_err());
        let mut f = fixture();
        f.origin.namespace.uid = "different-uid".into();
        assert!(f.template.build_pod(&context(&f)).is_err());
    }

    #[test]
    fn controller_replica_and_owner_fields_are_not_in_the_closed_json_shape() {
        let f = fixture();
        let pod = f.template.build_pod(&context(&f)).unwrap();
        let mut value = serde_json::to_value(&pod).unwrap();
        value["spec"]["replicas"] = serde_json::json!(2);
        assert!(serde_json::from_value::<BarePodDocumentV1>(value).is_err());
        let mut value = serde_json::to_value(&pod).unwrap();
        value["metadata"]["ownerReferences"] = serde_json::json!([]);
        assert!(serde_json::from_value::<BarePodDocumentV1>(value).is_err());
        let mut value = serde_json::to_value(&pod).unwrap();
        value["kind"] = serde_json::json!("Job");
        let parsed = serde_json::from_value::<BarePodDocumentV1>(value).unwrap();
        assert!(f.template.verify_pod(&parsed, &context(&f)).is_err());
    }

    #[test]
    fn runtime_uid_container_restart_and_absence_classify_without_reexecution() {
        let f = fixture();
        let pod = f.template.build_pod(&context(&f)).unwrap();
        let facts = PodRuntimeFactsV1 {
            pod_name: pod.metadata.name.clone(),
            pod_uid: "pod-uid-a".into(),
            container_id: Some("containerd://one".into()),
            restart_count: 0,
            image_digest: f.prepared.plan.artifact.oci_manifest_digest.clone(),
            owner_reference_count: 0,
            deletion_pending: false,
            observed_at_unix_ms: 1600,
        };
        let runtime = bind_first_runtime(&pod, &f.prepared, &facts).unwrap();
        assert_eq!(
            classify_runtime_observation(&pod, &f.prepared, Some(&runtime), Some(&facts)),
            RuntimeObservationClassV1::SameExactRuntime
        );
        assert_eq!(
            classify_runtime_observation(&pod, &f.prepared, Some(&runtime), None),
            RuntimeObservationClassV1::OutcomeUnknown
        );
        let mut replacement = facts.clone();
        replacement.pod_uid = "pod-uid-b".into();
        assert_eq!(
            classify_runtime_observation(&pod, &f.prepared, Some(&runtime), Some(&replacement)),
            RuntimeObservationClassV1::DifferentRuntime
        );
        let mut restarted = facts;
        restarted.restart_count = 1;
        assert_eq!(
            classify_runtime_observation(&pod, &f.prepared, Some(&runtime), Some(&restarted)),
            RuntimeObservationClassV1::DifferentRuntime
        );
    }
}
