//! Immutable OCI identity and external evidence custody for TURNSTILE.
//!
//! This module records facts only. It does not authorize, execute, reconcile,
//! or choose a Kubernetes workload primitive.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactBindingV1, EvidenceBindingV1, MAX_SAFE_JSON_INTEGER, OccurrenceError,
    TransitionEffectV1, validate_token,
};

/// Closed OCI fact schema.
pub const OCI_FACTS_SCHEMA_V1: &str = "nq.turnstile_oci_artifact_facts.v1";
/// Closed external custody schema.
pub const EXTERNAL_CUSTODY_SCHEMA_V1: &str = "nq.turnstile_external_evidence_custody.v1";
/// Closed evidence event schema.
pub const EVIDENCE_EVENT_SCHEMA_V1: &str = "nq.turnstile_external_evidence_event.v1";
const MAX_LAYERS: usize = 1024;
const MAX_EVENTS: usize = 1_000_000;

/// Whether the bound OCI digest names an index or one image manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciObjectKindV1 {
    /// Multi-platform OCI image index.
    ImageIndex,
    /// One platform-specific OCI image manifest.
    ImageManifest,
}

/// Exact selected OCI platform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OciPlatformV1 {
    /// Operating system; TURNSTILE V1 requires Linux.
    pub os: String,
    /// Target architecture.
    pub architecture: String,
    /// Optional architecture variant.
    pub variant: Option<String>,
}

/// One exact immutable OCI layer descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OciLayerV1 {
    /// OCI media type.
    pub media_type: String,
    /// Content digest.
    pub digest: Sha256Digest,
    /// Exact compressed size.
    pub size_bytes: u64,
}

/// Complete immutable OCI and in-image artifact facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OciArtifactFactsV1 {
    /// Closed schema.
    pub schema: String,
    /// Pull reference, required to end in the exact `@sha256:...` digest.
    pub image_reference: String,
    /// Kind named by `manifest_digest`.
    pub object_kind: OciObjectKindV1,
    /// Top-level immutable OCI identity.
    pub manifest_digest: Sha256Digest,
    /// Selected platform manifest when the top level is an index.
    pub selected_manifest_digest: Option<Sha256Digest>,
    /// Exact image-configuration descriptor.
    pub image_config_digest: Sha256Digest,
    /// Selected execution platform.
    pub platform: OciPlatformV1,
    /// Ordered layer descriptors.
    pub layers: Vec<OciLayerV1>,
    /// Qualified NQ source commit.
    pub source_commit: String,
    /// Exact `nq` executable bytes inside the image.
    pub nq_executable_digest: Sha256Digest,
    /// Exact passive helper bytes inside the image.
    pub passive_helper_digest: Sha256Digest,
    /// Exact authority-relevant configuration objects inside the image.
    pub configuration_digests: BTreeMap<String, Sha256Digest>,
}

impl OciArtifactFactsV1 {
    /// Validates closed OCI content and immutable-reference structure.
    ///
    /// # Errors
    ///
    /// Refuses mutable references, invalid platform/index shape, duplicate
    /// layers, unsafe sizes, or malformed identities.
    pub fn validate(&self) -> Result<(), OccurrenceError> {
        if self.schema != OCI_FACTS_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("OCI fact schema"));
        }
        validate_token(&self.image_reference, "OCI image reference")?;
        let Some((repository, digest)) = self.image_reference.split_once('@') else {
            return Err(OccurrenceError::InvalidPlan(
                "OCI reference is not bound to the exact manifest digest",
            ));
        };
        if repository.is_empty()
            || repository.contains('@')
            || digest != self.manifest_digest.as_str()
        {
            return Err(OccurrenceError::InvalidPlan(
                "OCI reference is not bound to the exact manifest digest",
            ));
        }
        match self.object_kind {
            OciObjectKindV1::ImageIndex if self.selected_manifest_digest.is_none() => {
                return Err(OccurrenceError::InvalidPlan(
                    "OCI index lacks selected platform manifest",
                ));
            }
            OciObjectKindV1::ImageManifest if self.selected_manifest_digest.is_some() => {
                return Err(OccurrenceError::InvalidPlan(
                    "OCI image manifest has an extraneous selected manifest",
                ));
            }
            _ => {}
        }
        if self.platform.os != "linux" {
            return Err(OccurrenceError::InvalidPlan("OCI platform is not Linux"));
        }
        validate_token(&self.platform.architecture, "OCI architecture")?;
        if let Some(variant) = &self.platform.variant {
            validate_token(variant, "OCI architecture variant")?;
        }
        if self.layers.is_empty() || self.layers.len() > MAX_LAYERS {
            return Err(OccurrenceError::InvalidPlan("OCI layer cardinality"));
        }
        let mut layer_digests = BTreeSet::new();
        for layer in &self.layers {
            validate_token(&layer.media_type, "OCI layer media type")?;
            if layer.size_bytes == 0
                || layer.size_bytes > MAX_SAFE_JSON_INTEGER
                || !layer_digests.insert(&layer.digest)
            {
                return Err(OccurrenceError::InvalidPlan("OCI layer descriptor"));
            }
        }
        if self.configuration_digests.is_empty() || self.configuration_digests.len() > 256 {
            return Err(OccurrenceError::InvalidPlan("OCI configuration bindings"));
        }
        for name in self.configuration_digests.keys() {
            validate_token(name, "OCI configuration name")?;
        }
        Ok(())
    }

    /// Rechecks the immutable OCI facts against a T0 artifact binding.
    ///
    /// # Errors
    ///
    /// Refuses invalid facts or any source/artifact/configuration substitution.
    pub fn verify_binding(&self, binding: &ArtifactBindingV1) -> Result<(), OccurrenceError> {
        self.validate()?;
        binding.validate()?;
        if self.source_commit != binding.source_commit
            || self.manifest_digest != binding.oci_manifest_digest
            || self.nq_executable_digest != binding.nq_executable_digest
            || self.passive_helper_digest != binding.passive_helper_digest
            || self.configuration_digests != binding.configuration_digests
        {
            return Err(OccurrenceError::ReplayConflict("OCI artifact facts"));
        }
        Ok(())
    }
}

/// External append-only custody representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceCustodyV1 {
    /// Closed schema.
    pub schema: String,
    /// Exact T0 external-journal identity.
    pub journal_id: Sha256Digest,
    /// Exact T0 terminal-receipt destination.
    pub receipt_destination_id: Sha256Digest,
    /// Must be true: evidence cannot live only in workload-local state.
    pub outside_workload_ephemeral_state: bool,
    /// Must be true: an old observation cannot be rewritten.
    pub append_only: bool,
    /// Closed value `retain_all`.
    pub retention_mode: String,
    /// Closed value `rfc8785_jcs`.
    pub encoding: String,
    /// Closed durable append ordering.
    pub durability_law: String,
    /// Exact exclusive-writer coordination domain.
    pub writer_domain: Sha256Digest,
}

impl ExternalEvidenceCustodyV1 {
    /// Rechecks the external representation against the T0 evidence binding.
    ///
    /// # Errors
    ///
    /// Refuses workload-local-only, mutable, non-retained, differently
    /// encoded, weakly ordered, or destination-substituted custody.
    pub fn verify_binding(&self, binding: &EvidenceBindingV1) -> Result<(), OccurrenceError> {
        binding.validate()?;
        if self.schema != EXTERNAL_CUSTODY_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("external custody schema"));
        }
        if !self.outside_workload_ephemeral_state
            || !self.append_only
            || self.retention_mode != "retain_all"
            || self.encoding != "rfc8785_jcs"
            || self.durability_law != "sync_event_then_parent_directory_v1"
        {
            return Err(OccurrenceError::InvalidPlan(
                "external evidence custody law",
            ));
        }
        if self.journal_id != binding.external_journal_id
            || self.receipt_destination_id != binding.receipt_destination_id
            || self.retention_mode != binding.retention_mode
        {
            return Err(OccurrenceError::ReplayConflict("external evidence custody"));
        }
        Ok(())
    }
}

/// Closed observational event kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEventKindV1 {
    /// Prepared content observed; no authority inferred.
    Prepared,
    /// Exact AG/Docket authorization observed.
    Authorized,
    /// Exact NQ claim observed.
    Claimed,
    /// Exact runtime identity observed.
    Executing,
    /// Definite terminal result observed.
    Terminal,
    /// Exact result cannot be established.
    OutcomeUnknown,
    /// Retirement and non-resurrection closeout observed.
    Closed,
}

/// Docket attempt/marker observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocketObservationV1 {
    /// Exact attempt.
    pub attempt: Sha256Digest,
    /// Exact executor marker.
    pub marker: Sha256Digest,
}

/// Canonical content of one external event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventBodyV1 {
    /// Closed schema.
    pub schema: String,
    /// Zero-based append sequence.
    pub sequence: u64,
    /// Exact predecessor event, absent only for sequence zero.
    pub predecessor: Option<Sha256Digest>,
    /// Exact external journal.
    pub journal_id: Sha256Digest,
    /// Exact prepared plan.
    pub plan_id: Sha256Digest,
    /// Exact NQ occurrence.
    pub nq_occurrence: Sha256Digest,
    /// Docket identity, absent only while prepared.
    pub docket: Option<DocketObservationV1>,
    /// Runtime identity once known.
    pub runtime: Option<Sha256Digest>,
    /// Closed observation kind.
    pub kind: EvidenceEventKindV1,
    /// Immutable source observation or receipt.
    pub observation_digest: Sha256Digest,
    /// Observation time.
    pub observed_at_unix_ms: u64,
}

/// Content-bound durable event wrapper.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableEvidenceEventV1 {
    /// JCS SHA-256 identity of `body`.
    pub event_id: Sha256Digest,
    /// Exact event body.
    pub body: EvidenceEventBodyV1,
}

impl DurableEvidenceEventV1 {
    /// Content-binds one event.
    ///
    /// # Errors
    ///
    /// Refuses an event that cannot be represented canonically.
    pub fn new(body: EvidenceEventBodyV1) -> Result<Self, OccurrenceError> {
        Ok(Self {
            event_id: semantic_digest(&body)?,
            body,
        })
    }

    fn validate(&self) -> Result<(), OccurrenceError> {
        if self.body.schema != EVIDENCE_EVENT_SCHEMA_V1 {
            return Err(OccurrenceError::ClosedIdentity("evidence event schema"));
        }
        if self.event_id != semantic_digest(&self.body)? {
            return Err(OccurrenceError::ReplayConflict("evidence event content"));
        }
        Ok(())
    }
}

/// Pure append-only evidence-chain model. It is observation, never authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceChainV1 {
    /// Exact external custody contract identity.
    pub custody_digest: Sha256Digest,
    /// Exact journal identity repeated for genesis validation.
    pub journal_id: Sha256Digest,
    /// Ordered content-bound events.
    pub events: Vec<DurableEvidenceEventV1>,
}

impl ExternalEvidenceChainV1 {
    /// Opens an empty chain bound to an external custody contract.
    ///
    /// # Errors
    ///
    /// Refuses a custody contract that does not match the T0 evidence binding.
    pub fn new(
        custody: &ExternalEvidenceCustodyV1,
        binding: &EvidenceBindingV1,
    ) -> Result<Self, OccurrenceError> {
        custody.verify_binding(binding)?;
        Ok(Self {
            custody_digest: semantic_digest(custody)?,
            journal_id: custody.journal_id.clone(),
            events: Vec::new(),
        })
    }

    /// Reopens and validates every content and predecessor link.
    ///
    /// # Errors
    ///
    /// Refuses custody substitution or any alternate transition history.
    pub fn reopen(
        custody: &ExternalEvidenceCustodyV1,
        binding: &EvidenceBindingV1,
        events: Vec<DurableEvidenceEventV1>,
    ) -> Result<Self, OccurrenceError> {
        let mut rebuilt = Self::new(custody, binding)?;
        for event in events {
            let effect = rebuilt.append(event.body.clone())?;
            if effect != TransitionEffectV1::Applied
                || rebuilt.events.last().map(|value| &value.event_id) != Some(&event.event_id)
            {
                return Err(OccurrenceError::ReplayConflict("evidence chain"));
            }
        }
        Ok(rebuilt)
    }

    /// Appends one exact observation or accepts an exact replay.
    ///
    /// # Errors
    ///
    /// Refuses changed content, broken links, widened cardinality, or an
    /// alternate transition after closeout.
    pub fn append(
        &mut self,
        body: EvidenceEventBodyV1,
    ) -> Result<TransitionEffectV1, OccurrenceError> {
        let event = DurableEvidenceEventV1::new(body)?;
        event.validate()?;
        let sequence = usize::try_from(event.body.sequence)
            .map_err(|_| OccurrenceError::InvalidPlan("evidence sequence"))?;
        if sequence < self.events.len() {
            return if self.events[sequence] == event {
                Ok(TransitionEffectV1::IdempotentReplay)
            } else {
                Err(OccurrenceError::ReplayConflict("evidence event replay"))
            };
        }
        if sequence != self.events.len() || self.events.len() >= MAX_EVENTS {
            return Err(OccurrenceError::InvalidPlan(
                "evidence sequence/cardinality",
            ));
        }
        self.validate_next(&event)?;
        self.events.push(event);
        Ok(TransitionEffectV1::Applied)
    }

    fn validate_next(&self, event: &DurableEvidenceEventV1) -> Result<(), OccurrenceError> {
        if event.body.sequence > MAX_SAFE_JSON_INTEGER
            || event.body.observed_at_unix_ms > MAX_SAFE_JSON_INTEGER
        {
            return Err(OccurrenceError::InvalidPlan("evidence I-JSON bound"));
        }
        let Some(previous) = self.events.last() else {
            if event.body.sequence != 0
                || event.body.predecessor.is_some()
                || event.body.journal_id != self.journal_id
                || event.body.kind != EvidenceEventKindV1::Prepared
                || event.body.docket.is_some()
                || event.body.runtime.is_some()
            {
                return Err(OccurrenceError::InvalidPlan("evidence genesis"));
            }
            return Ok(());
        };
        if event.body.predecessor.as_ref() != Some(&previous.event_id)
            || event.body.journal_id != previous.body.journal_id
            || event.body.plan_id != previous.body.plan_id
            || event.body.nq_occurrence != previous.body.nq_occurrence
            || event.body.observed_at_unix_ms < previous.body.observed_at_unix_ms
        {
            return Err(OccurrenceError::ReplayConflict(
                "evidence predecessor binding",
            ));
        }
        let allowed = matches!(
            (previous.body.kind, event.body.kind),
            (
                EvidenceEventKindV1::Prepared,
                EvidenceEventKindV1::Authorized
            ) | (
                EvidenceEventKindV1::Authorized,
                EvidenceEventKindV1::Claimed
            ) | (EvidenceEventKindV1::Claimed, EvidenceEventKindV1::Executing)
                | (EvidenceEventKindV1::Claimed, EvidenceEventKindV1::Terminal)
                | (
                    EvidenceEventKindV1::Claimed,
                    EvidenceEventKindV1::OutcomeUnknown
                )
                | (
                    EvidenceEventKindV1::Executing,
                    EvidenceEventKindV1::Terminal
                )
                | (
                    EvidenceEventKindV1::Executing,
                    EvidenceEventKindV1::OutcomeUnknown
                )
                | (
                    EvidenceEventKindV1::OutcomeUnknown,
                    EvidenceEventKindV1::Terminal
                )
                | (EvidenceEventKindV1::Terminal, EvidenceEventKindV1::Closed)
                | (
                    EvidenceEventKindV1::OutcomeUnknown,
                    EvidenceEventKindV1::Closed
                )
        );
        if !allowed {
            return Err(OccurrenceError::InvalidTransition {
                state: event_kind_label(previous.body.kind),
                requested: event_kind_label(event.body.kind),
            });
        }
        if event.body.docket.is_none()
            || previous
                .body
                .docket
                .as_ref()
                .is_some_and(|value| Some(value) != event.body.docket.as_ref())
        {
            return Err(OccurrenceError::ReplayConflict("evidence Docket binding"));
        }
        if (event.body.kind == EvidenceEventKindV1::Executing
            && (previous.body.runtime.is_some() || event.body.runtime.is_none()))
            || (event.body.kind != EvidenceEventKindV1::Executing
                && event.body.runtime != previous.body.runtime)
        {
            return Err(OccurrenceError::ReplayConflict("evidence runtime binding"));
        }
        Ok(())
    }
}

const fn event_kind_label(kind: EvidenceEventKindV1) -> &'static str {
    match kind {
        EvidenceEventKindV1::Prepared => "prepared",
        EvidenceEventKindV1::Authorized => "authorized",
        EvidenceEventKindV1::Claimed => "claimed",
        EvidenceEventKindV1::Executing => "executing",
        EvidenceEventKindV1::Terminal => "terminal",
        EvidenceEventKindV1::OutcomeUnknown => "outcome_unknown",
        EvidenceEventKindV1::Closed => "closed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_protocol::sha256_bytes;

    fn digest(value: &str) -> Sha256Digest {
        sha256_bytes(value.as_bytes())
    }

    fn artifact_binding() -> ArtifactBindingV1 {
        ArtifactBindingV1 {
            source_commit: "675e247e85d8e2e1f2801c06445bf863f82b3a5b".into(),
            oci_manifest_digest: digest("manifest"),
            nq_executable_digest: digest("nq"),
            passive_helper_digest: digest("helper"),
            configuration_digests: BTreeMap::from([("nq.toml".into(), digest("config"))]),
        }
    }

    fn artifact() -> OciArtifactFactsV1 {
        let binding = artifact_binding();
        OciArtifactFactsV1 {
            schema: OCI_FACTS_SCHEMA_V1.into(),
            image_reference: format!(
                "registry.invalid/turnstile/nq@{}",
                binding.oci_manifest_digest
            ),
            object_kind: OciObjectKindV1::ImageIndex,
            manifest_digest: binding.oci_manifest_digest,
            selected_manifest_digest: Some(digest("amd64-manifest")),
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
            source_commit: binding.source_commit,
            nq_executable_digest: binding.nq_executable_digest,
            passive_helper_digest: binding.passive_helper_digest,
            configuration_digests: binding.configuration_digests,
        }
    }

    fn evidence_binding() -> EvidenceBindingV1 {
        EvidenceBindingV1 {
            canonical_custody_id: digest("canonical"),
            selection_contract_digest: digest("selection"),
            external_journal_id: digest("journal"),
            receipt_destination_id: digest("receipts"),
            required_free_bytes: 10 * 1024 * 1024 * 1024,
            retention_mode: "retain_all".into(),
        }
    }

    fn custody() -> ExternalEvidenceCustodyV1 {
        let binding = evidence_binding();
        ExternalEvidenceCustodyV1 {
            schema: EXTERNAL_CUSTODY_SCHEMA_V1.into(),
            journal_id: binding.external_journal_id,
            receipt_destination_id: binding.receipt_destination_id,
            outside_workload_ephemeral_state: true,
            append_only: true,
            retention_mode: "retain_all".into(),
            encoding: "rfc8785_jcs".into(),
            durability_law: "sync_event_then_parent_directory_v1".into(),
            writer_domain: digest("writer-domain"),
        }
    }

    fn body(
        sequence: u64,
        predecessor: Option<Sha256Digest>,
        kind: EvidenceEventKindV1,
        docket: Option<DocketObservationV1>,
        runtime: Option<Sha256Digest>,
    ) -> EvidenceEventBodyV1 {
        EvidenceEventBodyV1 {
            schema: EVIDENCE_EVENT_SCHEMA_V1.into(),
            sequence,
            predecessor,
            journal_id: digest("journal"),
            plan_id: digest("plan"),
            nq_occurrence: digest("occurrence"),
            docket,
            runtime,
            kind,
            observation_digest: digest(&format!("observation-{sequence}")),
            observed_at_unix_ms: 1_000 + sequence,
        }
    }

    fn next(
        chain: &ExternalEvidenceChainV1,
        kind: EvidenceEventKindV1,
        docket: Option<DocketObservationV1>,
        runtime: Option<Sha256Digest>,
    ) -> EvidenceEventBodyV1 {
        body(
            chain.events.len() as u64,
            chain.events.last().map(|event| event.event_id.clone()),
            kind,
            docket,
            runtime,
        )
    }

    #[test]
    fn immutable_oci_facts_match_t0_and_mutable_reference_refuses() {
        let binding = artifact_binding();
        let mut facts = artifact();
        facts.verify_binding(&binding).unwrap();
        facts.image_reference = "registry.invalid/turnstile/nq:latest".into();
        assert!(facts.verify_binding(&binding).is_err());
    }

    #[test]
    fn artifact_or_layer_substitution_refuses() {
        let binding = artifact_binding();
        let mut facts = artifact();
        facts.nq_executable_digest = digest("different-nq");
        assert!(facts.verify_binding(&binding).is_err());
        let mut facts = artifact();
        facts.layers.push(facts.layers[0].clone());
        assert!(facts.validate().is_err());
    }

    #[test]
    fn pod_local_or_destination_substitution_refuses() {
        let binding = evidence_binding();
        let mut facts = custody();
        facts.verify_binding(&binding).unwrap();
        facts.outside_workload_ephemeral_state = false;
        assert!(facts.verify_binding(&binding).is_err());
        let mut facts = custody();
        facts.journal_id = digest("other-journal");
        assert!(facts.verify_binding(&binding).is_err());
    }

    #[test]
    fn exact_observation_chain_reopens_and_replay_is_idempotent() {
        let binding = evidence_binding();
        let custody = custody();
        let mut chain = ExternalEvidenceChainV1::new(&custody, &binding).unwrap();
        let prepared = next(&chain, EvidenceEventKindV1::Prepared, None, None);
        chain.append(prepared.clone()).unwrap();
        assert_eq!(
            chain.append(prepared).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        let docket = DocketObservationV1 {
            attempt: digest("attempt"),
            marker: digest("marker"),
        };
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Authorized,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Claimed,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        let runtime = digest("runtime");
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Executing,
                Some(docket.clone()),
                Some(runtime.clone()),
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::OutcomeUnknown,
                Some(docket.clone()),
                Some(runtime.clone()),
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Terminal,
                Some(docket.clone()),
                Some(runtime.clone()),
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Closed,
                Some(docket),
                Some(runtime),
            ))
            .unwrap();
        let reopened =
            ExternalEvidenceChainV1::reopen(&custody, &binding, chain.events.clone()).unwrap();
        assert_eq!(reopened, chain);
    }

    #[test]
    fn broken_link_alternate_history_and_post_close_append_refuse() {
        let binding = evidence_binding();
        let custody = custody();
        let mut chain = ExternalEvidenceChainV1::new(&custody, &binding).unwrap();
        chain
            .append(next(&chain, EvidenceEventKindV1::Prepared, None, None))
            .unwrap();
        let docket = DocketObservationV1 {
            attempt: digest("attempt"),
            marker: digest("marker"),
        };
        let mut authorized = next(
            &chain,
            EvidenceEventKindV1::Authorized,
            Some(docket.clone()),
            None,
        );
        authorized.predecessor = Some(digest("wrong"));
        assert!(chain.append(authorized).is_err());
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Authorized,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Claimed,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Terminal,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Closed,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        assert!(
            chain
                .append(next(
                    &chain,
                    EvidenceEventKindV1::Closed,
                    Some(docket),
                    None
                ))
                .is_err()
        );
    }

    #[test]
    fn genesis_must_name_the_bound_external_journal() {
        let binding = evidence_binding();
        let custody = custody();
        let mut chain = ExternalEvidenceChainV1::new(&custody, &binding).unwrap();
        let mut prepared = next(&chain, EvidenceEventKindV1::Prepared, None, None);
        prepared.journal_id = digest("substituted-journal");
        assert!(chain.append(prepared).is_err());
    }

    #[test]
    fn runtime_identity_begins_only_at_executing_and_cannot_be_dropped() {
        let binding = evidence_binding();
        let custody = custody();
        let mut chain = ExternalEvidenceChainV1::new(&custody, &binding).unwrap();
        chain
            .append(next(&chain, EvidenceEventKindV1::Prepared, None, None))
            .unwrap();
        let docket = DocketObservationV1 {
            attempt: digest("attempt"),
            marker: digest("marker"),
        };
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Authorized,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Claimed,
                Some(docket.clone()),
                None,
            ))
            .unwrap();
        let runtime = digest("runtime");
        assert!(
            chain
                .append(next(
                    &chain,
                    EvidenceEventKindV1::Terminal,
                    Some(docket.clone()),
                    Some(runtime.clone())
                ))
                .is_err()
        );
        chain
            .append(next(
                &chain,
                EvidenceEventKindV1::Executing,
                Some(docket.clone()),
                Some(runtime),
            ))
            .unwrap();
        assert!(
            chain
                .append(next(
                    &chain,
                    EvidenceEventKindV1::Terminal,
                    Some(docket),
                    None
                ))
                .is_err()
        );
    }
}
