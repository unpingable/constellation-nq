//! Cross-record resolution and semantic join validation.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde_json::{Map, Value};

use crate::{
    ContractError, Result,
    identity::{EffectiveInterval, IdentityCatalog, IdentityRef, RecordRef, Timestamp},
    record::{RuntimeSchema, ValidatedRuntimeRecord, resolve_pointer},
};

const MAX_EXECUTION_BINDING_SOURCE_ENTRIES: usize = 16;
const MAX_EXECUTION_BINDING_SOURCE_BYTES: usize = 131_072;
const PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA: &str = "nq.production_identity_descriptor.v1";
const CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA: &str = "nq.contract_specimen_identity.v1";

/// Exact externally retained record references admitted for one validation.
///
/// External admission confirms only that a reference may resolve outside this
/// record set. It grants no invocation, reliance, or mutation authority.
#[derive(Debug, Default, Clone)]
pub struct ExternalRecordCatalog {
    records: BTreeSet<RecordRef>,
}

impl ExternalRecordCatalog {
    /// Creates an empty external-reference catalog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeSet::new(),
        }
    }

    /// Admits one exact external reference.
    pub fn insert(&mut self, reference: RecordRef) {
        self.records.insert(reference);
    }

    fn contains(&self, reference: &RecordRef) -> bool {
        self.records.contains(reference)
    }
}

/// Exact catalogs used to validate one closed runtime record graph.
#[derive(Debug, Default, Clone)]
pub struct ValidationContext {
    /// Authoritative production identity descriptor catalog.
    pub identities: IdentityCatalog,
    /// Exact dependencies retained outside this record graph.
    pub external_records: ExternalRecordCatalog,
}

#[derive(Debug, Clone)]
struct CanonicalBindingSource {
    reference: RecordRef,
    canonical_bytes: Vec<u8>,
    value: Value,
}

/// Exact canonical source corpus used to qualify V2 identity-binding joins.
///
/// The ordinary external-reference catalog establishes only that a reference
/// is admitted. This corpus carries the exact bytes needed to prove that a
/// binding's source pointer and descriptor preimage actually say what the
/// binding claims. Corpus membership grants no invocation, reliance, or
/// operational authority. One v1 corpus is closed at 16 unique entries and
/// 131072 exact bytes; qualification additionally requires every entry to be
/// consumed by the validated binding closure.
#[derive(Debug, Default, Clone)]
pub struct ExecutionBindingSourceCorpus {
    sources: BTreeMap<(String, Sha256Digest), CanonicalBindingSource>,
    total_bytes: usize,
}

impl ExecutionBindingSourceCorpus {
    /// Creates an empty exact-byte source corpus.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    /// Inserts one exact canonical JSON source under its immutable reference.
    ///
    /// Exact replay is idempotent. Reusing `(schema, record_id)` with another
    /// reference or byte sequence is refused as source substitution.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical JSON, schema/reference mismatch, byte-digest
    /// substitution, source-identity reuse, or either closed-corpus bound.
    pub fn insert_canonical(
        &mut self,
        reference: RecordRef,
        canonical_bytes: Vec<u8>,
    ) -> Result<()> {
        let value: Value = serde_json::from_slice(&canonical_bytes)?;
        if canonical_json_bytes(&value)? != canonical_bytes {
            return Err(ContractError::NonCanonicalBindingSource);
        }
        if value.get("schema").and_then(Value::as_str) != Some(reference.schema.as_str())
            || sha256_bytes(&canonical_bytes) != reference.bytes_digest
        {
            return Err(ContractError::BindingSourceReferenceSubstitution);
        }
        let key = (reference.schema.to_string(), reference.record_id.clone());
        match self.sources.get(&key) {
            Some(existing)
                if existing.reference == reference
                    && existing.canonical_bytes == canonical_bytes =>
            {
                Ok(())
            }
            Some(_) => Err(ContractError::BindingSourceReferenceSubstitution),
            None => {
                if self.sources.len() >= MAX_EXECUTION_BINDING_SOURCE_ENTRIES {
                    return Err(ContractError::BindingSourceCorpusEntryLimit);
                }
                let new_total = self
                    .total_bytes
                    .checked_add(canonical_bytes.len())
                    .ok_or(ContractError::BindingSourceCorpusByteLimit)?;
                if new_total > MAX_EXECUTION_BINDING_SOURCE_BYTES {
                    return Err(ContractError::BindingSourceCorpusByteLimit);
                }
                self.sources.insert(
                    key,
                    CanonicalBindingSource {
                        reference,
                        canonical_bytes,
                        value,
                    },
                );
                self.total_bytes = new_total;
                Ok(())
            }
        }
    }

    /// Inserts one already validated runtime record as an exact source.
    ///
    /// # Errors
    ///
    /// Returns the same refusals as [`Self::insert_canonical`].
    pub fn insert_record(&mut self, record: &ValidatedRuntimeRecord) -> Result<()> {
        self.insert_canonical(record.exact_reference(), record.canonical_bytes().to_vec())
    }

    fn resolve(&self, reference: &RecordRef) -> Result<&CanonicalBindingSource> {
        let key = (reference.schema.to_string(), reference.record_id.clone());
        match self.sources.get(&key) {
            Some(source) if &source.reference == reference => Ok(source),
            Some(_) => Err(ContractError::BindingSourceReferenceSubstitution),
            None => Err(ContractError::UnresolvedBindingSource(
                reference.record_id.to_string(),
            )),
        }
    }

    fn references(&self) -> impl Iterator<Item = &RecordRef> {
        self.sources.values().map(|source| &source.reference)
    }
}

/// Closed immutable runtime record graph.
#[derive(Debug, Default, Clone)]
pub struct RuntimeRecordSet {
    records: BTreeMap<Sha256Digest, ValidatedRuntimeRecord>,
}

/// Opaque exact-record selection earned by one launch-correspondence query.
///
/// The private fields prevent callers from constructing a policy result by
/// assembling plausible references. Accessors expose only the immutable
/// records and production question needed by nq-core to reopen the exact
/// correspondence closure. This is evidence selection, not invocation,
/// reliance, authorization, recurrence, or action authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchCorrespondenceSelection {
    launch: RecordRef,
    outer_request: RecordRef,
    activation: RecordRef,
    cohort_manifest: RecordRef,
    native_profile_qualification: RecordRef,
    production_question: IdentityRef,
    native_clock_qualification: RecordRef,
    deadline_evaluation: RecordRef,
    cohort_semantics_digest: Sha256Digest,
}

impl LaunchCorrespondenceSelection {
    /// Returns the exact launch that selected this closure.
    #[must_use]
    pub const fn launch(&self) -> &RecordRef {
        &self.launch
    }

    /// Returns the exact bounded outer request.
    #[must_use]
    pub const fn outer_request(&self) -> &RecordRef {
        &self.outer_request
    }

    /// Returns the exact topology activation used by the launch.
    #[must_use]
    pub const fn activation(&self) -> &RecordRef {
        &self.activation
    }

    /// Returns the exact static-cohort manifest.
    #[must_use]
    pub const fn cohort_manifest(&self) -> &RecordRef {
        &self.cohort_manifest
    }

    /// Returns the exact native-profile qualification selected by the cohort.
    #[must_use]
    pub const fn native_profile_qualification(&self) -> &RecordRef {
        &self.native_profile_qualification
    }

    /// Returns the exact bounded production question named by that qualifier.
    #[must_use]
    pub const fn production_question(&self) -> &IdentityRef {
        &self.production_question
    }

    /// Returns the exact native-clock qualification selected by the cohort.
    #[must_use]
    pub const fn native_clock_qualification(&self) -> &RecordRef {
        &self.native_clock_qualification
    }

    /// Returns the exact accepted deadline evaluation used by the launch.
    #[must_use]
    pub const fn deadline_evaluation(&self) -> &RecordRef {
        &self.deadline_evaluation
    }

    /// Returns the canonical non-cyclic cohort-semantics commitment.
    #[must_use]
    pub const fn cohort_semantics_digest(&self) -> &Sha256Digest {
        &self.cohort_semantics_digest
    }
}

impl RuntimeRecordSet {
    /// Creates an empty record graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Inserts one locally validated canonical record.
    ///
    /// Exact replay is idempotent. Reusing a declared record identity with a
    /// different schema, digest, or bytes is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::DuplicateRecordIdentity`] on substitution.
    pub fn insert(&mut self, record: ValidatedRuntimeRecord) -> Result<()> {
        match self.records.get(record.record_id()) {
            Some(existing)
                if existing.schema() == record.schema()
                    && existing.canonical_bytes() == record.canonical_bytes() =>
            {
                Ok(())
            }
            Some(_) => Err(ContractError::DuplicateRecordIdentity),
            None => {
                self.records.insert(record.record_id().clone(), record);
                Ok(())
            }
        }
    }

    /// Returns one exact record by immutable identity.
    #[must_use]
    pub fn get(&self, id: &Sha256Digest) -> Option<&ValidatedRuntimeRecord> {
        self.records.get(id)
    }

    /// Iterates all records in stable identity order.
    pub fn records(&self) -> impl Iterator<Item = &ValidatedRuntimeRecord> {
        self.records.values()
    }

    /// Returns the number of materialized records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Selects the unique typed native correspondence closure for one launch.
    ///
    /// Callers first validate the closed record graph with [`Self::validate`].
    /// This query then reopens only the exact launch-local records needed by
    /// nq-core. It does not consult a mutable current generation, infer a
    /// question from a profile, accept an unreferenced qualifier, or
    /// reinterpret native observations.
    ///
    /// The cohort points to each qualifier by an exact [`RecordRef`]. To avoid
    /// an impossible circular Merkle commitment, each qualifier points back
    /// with the exact cohort identity and generation plus a canonical
    /// `cohort_semantics_digest`. That digest covers `namespace`, `cohort`,
    /// `generation`, `effective_interval`, `members`, `compatible_builds`,
    /// `protocol_store_compatibility`, and `nonclaims`. It deliberately
    /// excludes the record-envelope fields `schema` and `manifest_id`, and the
    /// cyclic `qualification_records` field.
    ///
    /// # Errors
    ///
    /// Refuses missing, substituted, duplicate, unreferenced, incompatible, or
    /// stale-generation qualifiers; a profile or question outside the exact
    /// cohort; a clock not qualified for the exact subject-platform relation;
    /// and any deadline evaluation that does not reproduce the exact request
    /// bounds and accepted launch values.
    #[allow(clippy::too_many_lines)]
    pub fn select_launch_correspondence(
        &self,
        launch_reference: &RecordRef,
    ) -> Result<LaunchCorrespondenceSelection> {
        let launch = self.exact_record(
            launch_reference,
            RuntimeSchema::ExecutionLaunchV1,
            "launch correspondence launch absent or substituted",
        )?;
        let launch_value = launch.record().as_value();
        let request_reference: RecordRef =
            serde_json::from_value(launch_value["outer_request"].clone())?;
        let request = self.exact_record(
            &request_reference,
            RuntimeSchema::DiagnosticInvocationRequestV1,
            "launch correspondence request absent or substituted",
        )?;
        let request_value = request.record().as_value();
        let activation_reference: RecordRef =
            serde_json::from_value(launch_value["activation_snapshot"].clone())?;
        let activation = self.exact_record(
            &activation_reference,
            RuntimeSchema::RuntimeActivationV1,
            "launch correspondence activation absent or substituted",
        )?;
        let activation_value = activation.record().as_value();
        let cohort_reference: RecordRef =
            serde_json::from_value(activation_value["cohort_manifest"].clone())?;
        let cohort = self.exact_record(
            &cohort_reference,
            RuntimeSchema::StaticProfileCohortManifestV1,
            "launch correspondence cohort absent or substituted",
        )?;
        let cohort_value = cohort.record().as_value();

        if activation_value["cohort_generation"] != cohort_value["generation"]
            || activation_value["static_profile_cohort"] != cohort_value["cohort"]
            || request_value["expected_binding"]["activation"]
                != Value::from(activation_reference.clone())
            || request_value["expected_binding"]["cohort_manifest"]
                != Value::from(cohort_reference.clone())
            || request_value["expected_binding"]["cohort_generation"] != cohort_value["generation"]
        {
            return Err(ContractError::InvocationJoin(
                "launch correspondence cohort generation or request binding",
            ));
        }

        let launch_profile: IdentityRef = serde_json::from_value(launch_value["profile"].clone())?;
        let request_profile: IdentityRef =
            serde_json::from_value(request_value["profile"].clone())?;
        if launch_profile != request_profile
            || identity_occurrences(cohort_value, &["members", "profiles"], &launch_profile)? != 1
        {
            return Err(ContractError::InvocationJoin(
                "launch correspondence profile outside exact cohort",
            ));
        }

        let cohort_identity: IdentityRef = serde_json::from_value(cohort_value["cohort"].clone())?;
        let cohort_generation =
            cohort_value["generation"]
                .as_str()
                .ok_or(ContractError::InvocationJoin(
                    "launch correspondence cohort generation",
                ))?;
        let cohort_semantics_digest = static_cohort_semantics_digest(cohort_value)?;
        let qualification_references = cohort_value["qualification_records"]
            .as_array()
            .ok_or(ContractError::InvocationJoin(
                "launch correspondence qualification set",
            ))?
            .iter()
            .cloned()
            .map(serde_json::from_value::<RecordRef>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let qualification_set = qualification_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        self.reject_unreferenced_launch_qualifiers(
            &qualification_set,
            &cohort_identity,
            cohort_generation,
        )?;

        let mut profile_candidates = Vec::new();
        let mut clock_candidates = Vec::new();
        let subject_platform = self.launch_subject_platform(activation_value, request_value)?;
        let launch_clock: IdentityRef = serde_json::from_value(launch_value["clock"].clone())?;
        let request_clock: IdentityRef =
            serde_json::from_value(request_value["time_bounds"]["clock"].clone())?;
        if launch_clock != request_clock {
            return Err(ContractError::InvocationJoin(
                "launch correspondence clock substituted request",
            ));
        }

        for reference in &qualification_references {
            match reference.schema.as_str() {
                "nq.native_profile_qualification.v1" => {
                    let qualification = self.exact_record(
                        reference,
                        RuntimeSchema::NativeProfileQualificationV1,
                        "launch correspondence profile qualifier absent or substituted",
                    )?;
                    let value = qualification.record().as_value();
                    require_qualifier_cohort(
                        value,
                        cohort_value,
                        &cohort_identity,
                        cohort_generation,
                        &cohort_semantics_digest,
                        "launch correspondence profile qualifier cohort",
                    )?;
                    let production_build: IdentityRef =
                        serde_json::from_value(value["production_build"].clone())?;
                    if identity_occurrences(
                        cohort_value,
                        &["compatible_builds"],
                        &production_build,
                    )? != 1
                    {
                        return Err(ContractError::InvocationJoin(
                            "launch correspondence profile qualifier build",
                        ));
                    }
                    let production_profile: IdentityRef =
                        serde_json::from_value(value["production_profile"].clone())?;
                    let production_question: IdentityRef =
                        serde_json::from_value(value["production_question"].clone())?;
                    if identity_occurrences(
                        cohort_value,
                        &["members", "profiles"],
                        &production_profile,
                    )? != 1
                        || identity_occurrences(
                            cohort_value,
                            &["members", "questions"],
                            &production_question,
                        )? != 1
                    {
                        return Err(ContractError::InvocationJoin(
                            "launch correspondence profile or question outside cohort",
                        ));
                    }
                    if production_profile == launch_profile {
                        profile_candidates
                            .push((qualification.exact_reference(), production_question));
                    }
                }
                "nq.native_clock_qualification.v1" => {
                    let qualification = self.exact_record(
                        reference,
                        RuntimeSchema::NativeClockQualificationV1,
                        "launch correspondence clock qualifier absent or substituted",
                    )?;
                    let value = qualification.record().as_value();
                    require_qualifier_cohort(
                        value,
                        cohort_value,
                        &cohort_identity,
                        cohort_generation,
                        &cohort_semantics_digest,
                        "launch correspondence clock qualifier cohort",
                    )?;
                    let production_build: IdentityRef =
                        serde_json::from_value(value["production_build"].clone())?;
                    if identity_occurrences(
                        cohort_value,
                        &["compatible_builds"],
                        &production_build,
                    )? != 1
                    {
                        return Err(ContractError::InvocationJoin(
                            "launch correspondence clock qualifier build",
                        ));
                    }
                    let production_clock: IdentityRef =
                        serde_json::from_value(value["production_clock"].clone())?;
                    let platform: IdentityRef = serde_json::from_value(value["platform"].clone())?;
                    if production_clock == launch_clock && platform == subject_platform {
                        clock_candidates.push(qualification.exact_reference());
                    }
                }
                _ => {}
            }
        }

        let [(profile_qualification, production_question)] = profile_candidates.as_slice() else {
            return Err(ContractError::InvocationJoin(
                "launch correspondence requires exactly one applicable profile qualifier",
            ));
        };
        let [clock_qualification] = clock_candidates.as_slice() else {
            return Err(ContractError::InvocationJoin(
                "launch correspondence requires exactly one applicable clock qualifier",
            ));
        };

        let deadline_reference: RecordRef =
            serde_json::from_value(launch_value["prelaunch_checks"]["deadline"].clone())?;
        let deadline = self.exact_record(
            &deadline_reference,
            RuntimeSchema::DeadlineEvaluationV1,
            "launch correspondence deadline absent or substituted",
        )?;
        let deadline_value = deadline.record().as_value();
        if deadline_value["outer_request"] != Value::from(request_reference.clone())
            || deadline_value["activation"] != Value::from(activation_reference.clone())
            || deadline_value["clock_qualification"] != Value::from(clock_qualification.clone())
            || deadline_value["clock"] != request_value["time_bounds"]["clock"]
            || deadline_value["request_bounds"]["not_before"]
                != request_value["time_bounds"]["not_before"]
            || deadline_value["request_bounds"]["deadline"]
                != request_value["time_bounds"]["deadline"]
            || deadline_value["request_bounds"]["maximum_execution_ms"]
                != request_value["time_bounds"]["maximum_execution_ms"]
            || deadline_value["decision"]["state"] != "accepted"
            || deadline_value["decision"]["violations"]
                .as_array()
                .is_none_or(|violations| !violations.is_empty())
            || deadline_value["derived"]["launched_at"] != launch_value["launched_at"]
            || deadline_value["derived"]["attempt_deadline"] != launch_value["attempt_deadline"]
            || launch_value["maximum_execution_ms"]
                != request_value["time_bounds"]["maximum_execution_ms"]
        {
            return Err(ContractError::InvocationJoin(
                "launch correspondence deadline does not reproduce exact launch",
            ));
        }

        Ok(LaunchCorrespondenceSelection {
            launch: launch.exact_reference(),
            outer_request: request_reference,
            activation: activation_reference,
            cohort_manifest: cohort_reference,
            native_profile_qualification: profile_qualification.clone(),
            production_question: production_question.clone(),
            native_clock_qualification: clock_qualification.clone(),
            deadline_evaluation: deadline.exact_reference(),
            cohort_semantics_digest,
        })
    }

    /// Requires one exact launch to sit on unique, state-continuous node,
    /// witness, and key lifecycle prefixes at its recorded launch instant.
    ///
    /// This is the launch-time lifecycle query needed by a native execution
    /// engine after [`Self::validate`] has admitted the complete immutable
    /// graph. It never consults a mutable "current" row. Later lifecycle
    /// events remain history and cannot reinterpret the returned launch-time
    /// judgment.
    ///
    /// In addition to exact predecessor closure, this requires:
    ///
    /// - one bootstrap-rooted host chain whose applicable head is `active`
    ///   and produced the launch activation;
    /// - one activation-rooted chain for each selected witness attachment,
    ///   with an `active` applicable head that produced the launch activation;
    /// - one activation-rooted chain for each node key generation, with no
    ///   overlapping active-key interval and the launch activation's exact key
    ///   as the sole active key at launch; and
    /// - no draining or terminal decommission cut effective at or before the
    ///   launch.
    ///
    /// This proves only lifecycle applicability for the recorded occurrence.
    /// It grants no invocation, reliance, recurrence, or operational
    /// authority.
    ///
    /// # Errors
    ///
    /// Refuses an unresolved or substituted launch, disconnected roots,
    /// incomplete predecessor closure, forks, resurrection, ambiguous active
    /// keys, inactive witnesses or keys, or an effective decommission fence.
    #[allow(clippy::too_many_lines)]
    pub fn require_effective_launch_lifecycle(&self, launch_reference: &RecordRef) -> Result<()> {
        let launch = self
            .get(&launch_reference.record_id)
            .ok_or(ContractError::LifecycleJoin("execution launch absent"))?;
        require_schema(launch, RuntimeSchema::ExecutionLaunchV1)?;
        if launch.exact_reference() != *launch_reference {
            return Err(ContractError::LifecycleJoin(
                "execution launch reference substitution",
            ));
        }
        let launch_value = launch.record().as_value();
        let activation = self.resolve_field(launch_value, "activation_snapshot")?;
        require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
        let activation_reference = activation.exact_reference();
        let activation_value = activation.record().as_value();
        let node = &activation_value["node"];
        let launched_at = timestamp(launch_value, "launched_at")?;

        let host_events = self
            .by_schema(RuntimeSchema::HostRoleLifecycleEventV1)
            .filter(|record| record.record().as_value()["node"] == *node)
            .collect::<Vec<_>>();
        let host_chain = exact_lifecycle_chain(
            host_events,
            host_lifecycle_predecessor,
            "host lifecycle root",
            "host lifecycle disconnected predecessor",
            "host lifecycle fork",
        )?;
        let host_root = host_chain
            .first()
            .ok_or(ContractError::LifecycleJoin("host lifecycle root"))?;
        if host_root.record().as_value()["operation"] != "bootstrap"
            || host_root.record().as_value()["from_state"] != "unbootstrapped"
        {
            return Err(ContractError::LifecycleJoin("host lifecycle root"));
        }
        let host_head = applicable_chain_head(&host_chain, launched_at).ok_or(
            ContractError::LifecycleJoin("host lifecycle absent at launch"),
        )?;
        if host_head.record().as_value()["to_state"] != "active"
            || !record_array_contains(
                host_head.record().as_value(),
                "result_records",
                &activation_reference,
            )?
        {
            return Err(ContractError::LifecycleJoin(
                "host lifecycle inactive or activation-substituted at launch",
            ));
        }

        for cut in self.by_schema(RuntimeSchema::DecommissionCutV1) {
            let value = cut.record().as_value();
            if value["node"] == *node && timestamp(value, "effective_at")? <= launched_at {
                return Err(ContractError::LifecycleJoin(
                    "decommission fence effective at launch",
                ));
            }
        }

        let selected = launch_value["selected_witness_attachments"]
            .as_array()
            .ok_or(ContractError::LifecycleJoin(
                "launch witness selection absent",
            ))?;
        for selected_reference in selected {
            let selected_reference: RecordRef = serde_json::from_value(selected_reference.clone())?;
            let attachment =
                self.get(&selected_reference.record_id)
                    .ok_or(ContractError::LifecycleJoin(
                        "selected witness attachment absent",
                    ))?;
            require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
            if attachment.exact_reference() != selected_reference
                || attachment.record().as_value()["node"] != *node
            {
                return Err(ContractError::LifecycleJoin(
                    "selected witness attachment substitution",
                ));
            }
            let witness_events = self
                .by_schema(RuntimeSchema::WitnessLifecycleEventV1)
                .filter(|event| {
                    serde_json::from_value::<RecordRef>(
                        event.record().as_value()["attachment"].clone(),
                    )
                    .is_ok_and(|reference| reference == selected_reference)
                })
                .collect::<Vec<_>>();
            let witness_chain = exact_lifecycle_chain(
                witness_events,
                nullable_lifecycle_predecessor,
                "witness lifecycle root",
                "witness lifecycle disconnected predecessor",
                "witness lifecycle fork",
            )?;
            let witness_root = witness_chain
                .first()
                .ok_or(ContractError::LifecycleJoin("witness lifecycle root"))?;
            if witness_root.record().as_value()["operation"] != "activate"
                || witness_root.record().as_value()["from_state"] != "admitted_inactive"
            {
                return Err(ContractError::LifecycleJoin("witness lifecycle root"));
            }
            let witness_head = applicable_chain_head(&witness_chain, launched_at).ok_or(
                ContractError::LifecycleJoin("witness lifecycle absent at launch"),
            )?;
            if witness_head.record().as_value()["to_state"] != "active"
                || !record_array_contains(
                    witness_head.record().as_value(),
                    "result_records",
                    &activation_reference,
                )?
            {
                return Err(ContractError::LifecycleJoin(
                    "witness inactive or activation-substituted at launch",
                ));
            }
        }

        let activation_key: IdentityRef =
            serde_json::from_value(activation_value["active_key"].clone())?;
        let mut key_events = BTreeMap::<IdentityRef, Vec<&ValidatedRuntimeRecord>>::new();
        for event in self.by_schema(RuntimeSchema::NodeKeyLifecycleEventV1) {
            let value = event.record().as_value();
            if value["node"] != *node {
                continue;
            }
            let key: IdentityRef = serde_json::from_value(value["key"].clone())?;
            key_events.entry(key).or_default().push(event);
        }

        let mut active_intervals = Vec::new();
        let mut launch_active_keys = Vec::new();
        let mut activation_key_head = None;
        for (key, events) in key_events {
            let chain = exact_lifecycle_chain(
                events,
                nullable_lifecycle_predecessor,
                "key lifecycle root",
                "key lifecycle disconnected predecessor",
                "key lifecycle fork",
            )?;
            let root = chain
                .first()
                .ok_or(ContractError::LifecycleJoin("key lifecycle root"))?;
            if root.record().as_value()["operation"] != "activate"
                || root.record().as_value()["from_state"] != "pending"
            {
                return Err(ContractError::LifecycleJoin("key lifecycle root"));
            }
            let start = timestamp(root.record().as_value(), "occurred_at")?;
            let end = chain
                .get(1)
                .map(|record| timestamp(record.record().as_value(), "occurred_at"))
                .transpose()?;
            if chain.len() > 2 {
                return Err(ContractError::LifecycleJoin("key lifecycle resurrection"));
            }
            active_intervals.push((key.clone(), start, end));
            if start <= launched_at && end.is_none_or(|terminal| launched_at < terminal) {
                launch_active_keys.push(key.clone());
            }
            if key == activation_key {
                activation_key_head = applicable_chain_head(&chain, launched_at);
            }
        }

        for (index, (left_key, left_start, left_end)) in active_intervals.iter().enumerate() {
            for (right_key, right_start, right_end) in &active_intervals[index + 1..] {
                if left_key != right_key
                    && left_end.is_none_or(|end| *right_start < end)
                    && right_end.is_none_or(|end| *left_start < end)
                {
                    return Err(ContractError::LifecycleJoin(
                        "node has overlapping active key generations",
                    ));
                }
            }
        }
        if launch_active_keys.as_slice() != [activation_key.clone()] {
            return Err(ContractError::LifecycleJoin(
                "activation key is not uniquely active at launch",
            ));
        }
        let activation_key_head = activation_key_head.ok_or(ContractError::LifecycleJoin(
            "activation key lifecycle absent at launch",
        ))?;
        if activation_key_head.record().as_value()["to_state"] != "active"
            || activation_key_head.record().as_value()["resulting_activation"]
                != Value::from(activation_reference)
        {
            return Err(ContractError::LifecycleJoin(
                "activation key inactive or activation-substituted at launch",
            ));
        }
        Ok(())
    }

    /// Validates exact identity/reference closure, graph acyclicity, and the
    /// ratified topology, generation, invocation, delivery, and inspector
    /// joins implemented by this package.
    ///
    /// This structural graph validation does not possess exact external
    /// descriptor bytes. A graph containing
    /// `nq.execution_identity_binding.v2` is production-source-qualified only
    /// by [`Self::validate_with_execution_binding_sources`].
    ///
    /// # Errors
    ///
    /// Returns a typed refusal at the first failed invariant. No record is
    /// rewritten, defaulted, or reinterpreted.
    pub fn validate(&self, context: &ValidationContext) -> Result<()> {
        self.validate_catalogs(context)?;
        self.validate_reference_dag()?;
        self.validate_authorizations()?;
        self.validate_topology()?;
        self.validate_lifecycle()?;
        self.validate_invocations()?;
        self.validate_bindings()?;
        self.validate_delivery()?;
        Ok(())
    }

    /// Validates the complete graph and every V2 binding against exact
    /// canonical source and descriptor bytes.
    ///
    /// This is the qualified source-complete binding entry point. It first
    /// applies every invariant from [`Self::validate`], then proves the ratified
    /// source-artifact/source-pointer joins, exact pointed identities, unique
    /// source pairs, descriptor preimage commitments, and exact closed source
    /// corpus.
    ///
    /// The current V2 carrier selects exactly one witness attachment and one
    /// provider-attempt reference. This shared contract proves their closed
    /// carrier shape only. Native `nq-core` must separately prove that its
    /// typed provider attempt corresponds to that witness, provider, and
    /// admission; this package does not interpret provider-native semantics.
    /// A product consumer must also require its admitted production identity
    /// descriptor schema; the shared package accepts the exact frozen contract
    /// specimen descriptor schema for non-production conformance vectors.
    ///
    /// # Errors
    ///
    /// Returns every refusal from [`Self::validate`] plus the exact binding
    /// source-corpus refusals.
    pub fn validate_with_execution_binding_sources(
        &self,
        context: &ValidationContext,
        sources: &ExecutionBindingSourceCorpus,
    ) -> Result<()> {
        self.validate(context)?;
        self.validate_execution_binding_sources(sources)
    }

    /// Validates the complete historical graph and one exact V2 binding
    /// against a source corpus closed to that binding.
    ///
    /// The V1 source-corpus bound intentionally describes one binding
    /// occurrence. Requiring one aggregate corpus for every historical
    /// binding would either make later topology generations impossible or
    /// silently reinterpret the bound as a growing archive. This entry point
    /// therefore applies every graph invariant first, resolves the selected
    /// immutable binding exactly, and then consumes only that binding's
    /// complete source corpus.
    ///
    /// This is not a weaker validation mode: all historical records remain in
    /// the graph passed to [`Self::validate`], while source completeness and
    /// the no-unused-source law are checked independently for the named
    /// occurrence.
    ///
    /// # Errors
    ///
    /// Returns every refusal from [`Self::validate`], an absent or substituted
    /// binding refusal, or any exact source-corpus refusal.
    pub fn validate_execution_binding_with_sources(
        &self,
        context: &ValidationContext,
        binding: &RecordRef,
        sources: &ExecutionBindingSourceCorpus,
    ) -> Result<()> {
        self.validate(context)?;
        let binding_record = self.exact_record(
            binding,
            RuntimeSchema::ExecutionIdentityBindingV2,
            "selected execution binding absent or substituted",
        )?;
        let mut consumed = BTreeSet::new();
        self.validate_execution_binding_source(binding_record, sources, &mut consumed)?;
        if let Some(unused) = sources
            .references()
            .find(|reference| !consumed.contains(*reference))
        {
            return Err(ContractError::UnusedBindingSource(
                unused.record_id.to_string(),
            ));
        }
        Ok(())
    }

    fn validate_execution_binding_sources(
        &self,
        sources: &ExecutionBindingSourceCorpus,
    ) -> Result<()> {
        let mut consumed = BTreeSet::new();
        for binding in self.by_schema(RuntimeSchema::ExecutionIdentityBindingV2) {
            self.validate_execution_binding_source(binding, sources, &mut consumed)?;
        }
        if let Some(unused) = sources
            .references()
            .find(|reference| !consumed.contains(*reference))
        {
            return Err(ContractError::UnusedBindingSource(
                unused.record_id.to_string(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One closed authorization/consumer law.
    fn validate_authorizations(&self) -> Result<()> {
        let administrative: Vec<_> = self
            .by_schema(RuntimeSchema::OperationAuthorizationV1)
            .filter(|record| record.record().as_value()["scope"] == "administrative_lifecycle")
            .collect();
        let mut occurrence_ids = BTreeSet::new();
        for authorization in &administrative {
            let occurrence =
                authorization.record().as_value()["binding"]["transition_occurrence_id"]
                    .as_str()
                    .ok_or(ContractError::AuthorizationJoin(
                        "administrative occurrence identity",
                    ))?;
            if !occurrence_ids.insert(occurrence) {
                return Err(ContractError::AuthorizationJoin(
                    "administrative occurrence identity replay",
                ));
            }
        }

        let mut consumers = BTreeMap::<Sha256Digest, Vec<&ValidatedRuntimeRecord>>::new();
        for consumer in self.records() {
            let Some(field) = administrative_authority_field(consumer.schema()) else {
                continue;
            };
            let authorization = self.resolve_field(consumer.record().as_value(), field)?;
            require_schema(authorization, RuntimeSchema::OperationAuthorizationV1)?;
            if authorization.record().as_value()["scope"] != "administrative_lifecycle" {
                return Err(ContractError::AuthorizationJoin(
                    "administrative consumer substituted authorization scope",
                ));
            }
            consumers
                .entry(authorization.record_id().clone())
                .or_default()
                .push(consumer);
        }

        let neutral_digests = self.administrative_neutral_digests()?;
        for authorization in administrative {
            let value = authorization.record().as_value();
            let binding = value["binding"]
                .as_object()
                .ok_or(ContractError::AuthorizationJoin(
                    "administrative binding absent",
                ))?;
            let operation = value["operation"]
                .as_str()
                .ok_or(ContractError::AuthorizationJoin(
                    "administrative operation absent",
                ))?;
            let authorized = binding["authorized_records"].as_array().ok_or(
                ContractError::AuthorizationJoin("authorized record set absent"),
            )?;
            let mut previous: Option<(String, Sha256Digest)> = None;
            let mut expected = BTreeSet::new();
            for item in authorized {
                let schema = item["schema"]
                    .as_str()
                    .ok_or(ContractError::AuthorizationJoin("authorized record schema"))?
                    .to_owned();
                let record_id: Sha256Digest = serde_json::from_value(item["record_id"].clone())?;
                let preimage: Sha256Digest =
                    serde_json::from_value(item["record_preimage_digest"].clone())?;
                let key = (schema.clone(), record_id.clone());
                if previous.as_ref().is_some_and(|prior| prior >= &key)
                    || !expected.insert(key.clone())
                {
                    return Err(ContractError::AuthorizationJoin(
                        "authorized records are not strictly sorted and unique",
                    ));
                }
                previous = Some(key.clone());
                if neutral_digests.get(&key) != Some(&preimage) {
                    return Err(ContractError::AuthorizationJoin(
                        "authority-neutral consumer preimage mismatch",
                    ));
                }
            }

            let mut snapshot = binding.clone();
            snapshot.remove("input_snapshot_digest");
            snapshot.insert("operation".to_owned(), Value::String(operation.to_owned()));
            let expected_snapshot = semantic_digest(&Value::Object(snapshot))?;
            if binding["input_snapshot_digest"] != Value::String(expected_snapshot.to_string()) {
                return Err(ContractError::AuthorizationJoin(
                    "administrative input snapshot substitution",
                ));
            }

            let actual_records = consumers
                .get(authorization.record_id())
                .map_or(&[][..], Vec::as_slice);
            let actual: BTreeSet<_> = actual_records
                .iter()
                .map(|record| {
                    (
                        record.schema().as_str().to_owned(),
                        record.record_id().clone(),
                    )
                })
                .collect();
            match value["decision"].as_str() {
                Some("granted") if actual != expected => {
                    return Err(ContractError::AuthorizationJoin(
                        "grant consumer set differs from authorized record set",
                    ));
                }
                Some("refused") if !actual.is_empty() => {
                    return Err(ContractError::AuthorizationJoin(
                        "refused administrative authority was consumed",
                    ));
                }
                Some("granted" | "refused") => {}
                _ => {
                    return Err(ContractError::AuthorizationJoin(
                        "invalid administrative decision",
                    ));
                }
            }

            if value["decision"] == "granted" && !administrative_shape(operation, actual_records)? {
                return Err(ContractError::AuthorizationJoin(
                    "administrative operation did not close its exact record shape",
                ));
            }
            let interval: EffectiveInterval =
                serde_json::from_value(value["effective_interval"].clone())?;
            for consumer in actual_records {
                if !operation_matches_consumer(operation, consumer.record().as_value())?
                    || !interval.contains(&Timestamp::parse(
                        consumer_occurrence_time(consumer)?.to_owned(),
                    )?)
                {
                    return Err(ContractError::AuthorizationJoin(
                        "administrative grant operation or interval mismatch",
                    ));
                }
                self.validate_administrative_scope(operation, binding, consumer)?;
            }
        }
        Ok(())
    }

    fn administrative_neutral_digests(
        &self,
    ) -> Result<BTreeMap<(String, Sha256Digest), Sha256Digest>> {
        let consumers: BTreeMap<_, _> = self
            .records()
            .filter(|record| administrative_authority_field(record.schema()).is_some())
            .map(|record| {
                (
                    (
                        record.schema().as_str().to_owned(),
                        record.record_id().clone(),
                    ),
                    record,
                )
            })
            .collect();
        let mut memo = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        for key in consumers.keys() {
            administrative_neutral_digest(self, &consumers, key, &mut memo, &mut visiting)?;
        }
        Ok(memo)
    }

    #[allow(clippy::too_many_lines)] // Exact per-consumer administrative scope joins.
    fn validate_administrative_scope(
        &self,
        operation: &str,
        binding: &Map<String, Value>,
        consumer: &ValidatedRuntimeRecord,
    ) -> Result<()> {
        let value = consumer.record().as_value();
        if value
            .get("node")
            .is_some_and(|node| node != &binding["node"])
        {
            return Err(ContractError::AuthorizationJoin(
                "administrative consumer substituted node",
            ));
        }
        match consumer.schema() {
            RuntimeSchema::NodeEnrollmentV1 => {
                if operation != "enroll"
                    || value["initial_key"] != binding["active_key"]
                    || value["deployment_generation"] != binding["deployment_generation"]
                    || value["configuration_generation"] != binding["configuration_generation"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "enrollment substituted authorized generations",
                    ));
                }
            }
            RuntimeSchema::WitnessAttachmentV1 => {
                let role = self.resolve_field(value, "role_manifest")?;
                if operation != "admit_witness"
                    || !binding["witness_attachment_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.contains(&value["attachment_id"]))
                    || role.record().as_value()["manifest_id"] != binding["role_manifest_id"]
                    || role.record().as_value()["generation"] != binding["role_generation"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "witness attachment substituted role or identity",
                    ));
                }
            }
            RuntimeSchema::HostRoleRelationV1 => {
                let (left, right) = self.administrative_relation_endpoints(binding, value)?;
                if value["left"] != left || value["right"] != right {
                    return Err(ContractError::AuthorizationJoin(
                        "relation substituted authorized endpoints",
                    ));
                }
            }
            RuntimeSchema::RuntimeActivationV1 => {
                let attachments: Vec<_> = value["witness_attachments"]
                    .as_array()
                    .ok_or(ContractError::AuthorizationJoin(
                        "activation witness set absent",
                    ))?
                    .iter()
                    .map(|item| item["record_id"].clone())
                    .collect();
                if value["role_manifest"]["record_id"] != binding["role_manifest_id"]
                    || value["role_generation"] != binding["role_generation"]
                    || value["cohort_manifest"]["record_id"] != binding["cohort_manifest_id"]
                    || value["cohort_generation"] != binding["cohort_generation"]
                    || Value::Array(attachments) != binding["witness_attachment_ids"]
                    || value["active_key"] != binding["active_key"]
                    || value["deployment_generation"] != binding["deployment_generation"]
                    || value["configuration_generation"] != binding["configuration_generation"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "activation substituted authorized topology or generations",
                    ));
                }
                for relation in value["relations"]
                    .as_object()
                    .ok_or(ContractError::AuthorizationJoin(
                        "activation relation set absent",
                    ))?
                    .values()
                {
                    let relation = self.resolve_value(relation)?;
                    let (left, right) = self
                        .administrative_relation_endpoints(binding, relation.record().as_value())?;
                    if relation.record().as_value()["left"] != left
                        || relation.record().as_value()["right"] != right
                    {
                        return Err(ContractError::AuthorizationJoin(
                            "activation relation scope substitution",
                        ));
                    }
                }
            }
            RuntimeSchema::HostRoleLifecycleEventV1
            | RuntimeSchema::WitnessLifecycleEventV1
            | RuntimeSchema::NodeKeyLifecycleEventV1 => {
                if value["from_state"] != binding["from_state"]
                    || value["to_state"] != binding["to_state"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "lifecycle transition substituted authorized state edge",
                    ));
                }
                if consumer.schema() == RuntimeSchema::NodeKeyLifecycleEventV1
                    && value["key"] != binding["active_key"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "key transition substituted active key",
                    ));
                }
            }
            RuntimeSchema::RestoreActivationProofV1 => {
                if value["new_deployment_generation"] != binding["deployment_generation"]
                    || (operation == "complete_restore"
                        && value["decision"] != "eligible_enrolled_inactive")
                {
                    return Err(ContractError::AuthorizationJoin(
                        "restore proof cannot complete from quarantine",
                    ));
                }
            }
            RuntimeSchema::DecommissionCutV1 => {
                let expected = if value["result_state"] == "decommissioned" {
                    "complete_decommission"
                } else {
                    "begin_decommission"
                };
                if operation != expected || binding["to_state"] != value["result_state"] {
                    return Err(ContractError::AuthorizationJoin(
                        "decommission cut substituted operation or state",
                    ));
                }
            }
            _ => {
                return Err(ContractError::AuthorizationJoin(
                    "unsupported administrative consumer schema",
                ));
            }
        }
        Ok(())
    }

    fn administrative_relation_endpoints(
        &self,
        binding: &Map<String, Value>,
        relation: &Value,
    ) -> Result<(Value, Value)> {
        let pair = match relation["relation_kind"].as_str() {
            Some("node_subject") => (binding["node"].clone(), binding["subject"].clone()),
            Some("subject_platform") => (binding["subject"].clone(), binding["platform"].clone()),
            Some("node_vantage") => (binding["node"].clone(), binding["vantage"].clone()),
            Some("node_role") => {
                let role_id: Sha256Digest =
                    serde_json::from_value(binding["role_manifest_id"].clone())?;
                let role = self.get(&role_id).ok_or(ContractError::AuthorizationJoin(
                    "authorized role manifest absent",
                ))?;
                require_schema(role, RuntimeSchema::RoleManifestV1)?;
                (
                    binding["node"].clone(),
                    role.record().as_value()["role"].clone(),
                )
            }
            Some("node_static_profile_cohort") => {
                let cohort_id: Sha256Digest =
                    serde_json::from_value(binding["cohort_manifest_id"].clone())?;
                let cohort = self
                    .get(&cohort_id)
                    .ok_or(ContractError::AuthorizationJoin(
                        "authorized cohort manifest absent",
                    ))?;
                require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;
                (
                    binding["node"].clone(),
                    cohort.record().as_value()["cohort"].clone(),
                )
            }
            _ => {
                return Err(ContractError::AuthorizationJoin(
                    "unknown administrative relation kind",
                ));
            }
        };
        Ok(pair)
    }

    #[allow(clippy::too_many_lines)] // Mirrors three closed ratified lifecycle graphs.
    fn validate_lifecycle(&self) -> Result<()> {
        let mut host_successors = BTreeMap::<Sha256Digest, usize>::new();
        for event in self.by_schema(RuntimeSchema::HostRoleLifecycleEventV1) {
            let value = event.record().as_value();
            if let Some(predecessor_value) = value["predecessor_events"]
                .as_array()
                .and_then(|items| items.first())
            {
                let predecessor = self.resolve_value(predecessor_value)?;
                require_schema(predecessor, RuntimeSchema::HostRoleLifecycleEventV1)?;
                require_equal(
                    value,
                    "node",
                    predecessor.record().as_value(),
                    "node",
                    "host lifecycle node",
                )?;
                if predecessor.record().as_value()["to_state"] != value["from_state"]
                    || timestamp(predecessor.record().as_value(), "occurred_at")?
                        >= timestamp(value, "occurred_at")?
                {
                    return Err(ContractError::LifecycleJoin(
                        "host lifecycle predecessor continuity",
                    ));
                }
                *host_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if host_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::LifecycleJoin("host lifecycle fork"));
                }
            }
            let operation = value["operation"]
                .as_str()
                .ok_or(ContractError::LifecycleJoin("host operation"))?;
            if let Some(proof) = value.get("operation_proof") {
                let proof = self.resolve_value(proof)?;
                let expected = match operation {
                    "complete_restore" => RuntimeSchema::RestoreActivationProofV1,
                    "begin_decommission" | "complete_decommission" => {
                        RuntimeSchema::DecommissionCutV1
                    }
                    _ => {
                        return Err(ContractError::LifecycleJoin(
                            "unexpected host lifecycle proof",
                        ));
                    }
                };
                require_schema(proof, expected)?;
                if !value["result_records"]
                    .as_array()
                    .is_some_and(|records| records.contains(&Value::from(proof.exact_reference())))
                {
                    return Err(ContractError::LifecycleJoin(
                        "operation proof outside result records",
                    ));
                }
            }
        }

        let mut witness_successors = BTreeMap::<Sha256Digest, usize>::new();
        for event in self.by_schema(RuntimeSchema::WitnessLifecycleEventV1) {
            let value = event.record().as_value();
            let attachment = self.resolve_field(value, "attachment")?;
            require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
            for field in ["node", "witness"] {
                require_equal(
                    value,
                    field,
                    attachment.record().as_value(),
                    field,
                    "witness lifecycle attachment",
                )?;
            }
            if value["attachment_generation"] != attachment.record().as_value()["generation"] {
                return Err(ContractError::LifecycleJoin(
                    "witness attachment generation",
                ));
            }
            if value["predecessor_event"] != Value::Null {
                let predecessor = self.resolve_field(value, "predecessor_event")?;
                require_schema(predecessor, RuntimeSchema::WitnessLifecycleEventV1)?;
                for field in ["node", "attachment", "witness", "attachment_generation"] {
                    if value[field] != predecessor.record().as_value()[field] {
                        return Err(ContractError::LifecycleJoin("witness predecessor identity"));
                    }
                }
                if predecessor.record().as_value()["to_state"] != value["from_state"]
                    || timestamp(predecessor.record().as_value(), "occurred_at")?
                        >= timestamp(value, "occurred_at")?
                {
                    return Err(ContractError::LifecycleJoin(
                        "witness predecessor continuity",
                    ));
                }
                *witness_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if witness_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::LifecycleJoin("witness lifecycle fork"));
                }
            }
        }

        let mut key_successors = BTreeMap::<Sha256Digest, usize>::new();
        for event in self.by_schema(RuntimeSchema::NodeKeyLifecycleEventV1) {
            let value = event.record().as_value();
            if value["predecessor_event"] != Value::Null {
                let predecessor = self.resolve_field(value, "predecessor_event")?;
                require_schema(predecessor, RuntimeSchema::NodeKeyLifecycleEventV1)?;
                require_equal(
                    value,
                    "node",
                    predecessor.record().as_value(),
                    "node",
                    "key lifecycle node",
                )?;
                if predecessor.record().as_value()["to_state"] != value["from_state"]
                    || timestamp(predecessor.record().as_value(), "occurred_at")?
                        >= timestamp(value, "occurred_at")?
                {
                    return Err(ContractError::LifecycleJoin("key predecessor continuity"));
                }
                *key_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if key_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::LifecycleJoin("key lifecycle fork"));
                }
            }
            if value["resulting_activation"] != Value::Null {
                let activation = self.resolve_field(value, "resulting_activation")?;
                require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
                if value["node"] != activation.record().as_value()["node"]
                    || value["key"] != activation.record().as_value()["active_key"]
                {
                    return Err(ContractError::LifecycleJoin("key resulting activation"));
                }
            }
        }

        self.validate_lifecycle_chain_closure()?;
        self.validate_restore_and_decommission()
    }

    fn validate_lifecycle_chain_closure(&self) -> Result<()> {
        let mut hosts = BTreeMap::<IdentityRef, Vec<&ValidatedRuntimeRecord>>::new();
        for event in self.by_schema(RuntimeSchema::HostRoleLifecycleEventV1) {
            let node: IdentityRef =
                serde_json::from_value(event.record().as_value()["node"].clone())?;
            hosts.entry(node).or_default().push(event);
        }
        for events in hosts.into_values() {
            let chain = exact_lifecycle_chain(
                events,
                host_lifecycle_predecessor,
                "host lifecycle root",
                "host lifecycle disconnected predecessor",
                "host lifecycle fork",
            )?;
            if chain
                .first()
                .is_none_or(|root| root.record().as_value()["operation"] != "bootstrap")
            {
                return Err(ContractError::LifecycleJoin("host lifecycle root"));
            }
        }

        let mut witnesses = BTreeMap::<RecordRef, Vec<&ValidatedRuntimeRecord>>::new();
        for event in self.by_schema(RuntimeSchema::WitnessLifecycleEventV1) {
            let attachment: RecordRef =
                serde_json::from_value(event.record().as_value()["attachment"].clone())?;
            witnesses.entry(attachment).or_default().push(event);
        }
        for events in witnesses.into_values() {
            let chain = exact_lifecycle_chain(
                events,
                nullable_lifecycle_predecessor,
                "witness lifecycle root",
                "witness lifecycle disconnected predecessor",
                "witness lifecycle fork",
            )?;
            if chain
                .first()
                .is_none_or(|root| root.record().as_value()["operation"] != "activate")
            {
                return Err(ContractError::LifecycleJoin("witness lifecycle root"));
            }
        }

        let mut keys = BTreeMap::<(IdentityRef, IdentityRef), Vec<&ValidatedRuntimeRecord>>::new();
        for event in self.by_schema(RuntimeSchema::NodeKeyLifecycleEventV1) {
            let value = event.record().as_value();
            let node: IdentityRef = serde_json::from_value(value["node"].clone())?;
            let key: IdentityRef = serde_json::from_value(value["key"].clone())?;
            keys.entry((node, key)).or_default().push(event);
        }
        for events in keys.into_values() {
            let chain = exact_lifecycle_chain(
                events,
                nullable_lifecycle_predecessor,
                "key lifecycle root",
                "key lifecycle disconnected predecessor",
                "key lifecycle fork",
            )?;
            if chain
                .first()
                .is_none_or(|root| root.record().as_value()["operation"] != "activate")
                || chain.len() > 2
            {
                return Err(ContractError::LifecycleJoin("key lifecycle root"));
            }
        }
        Ok(())
    }

    fn validate_restore_and_decommission(&self) -> Result<()> {
        for proof in self.by_schema(RuntimeSchema::RestoreActivationProofV1) {
            let value = proof.record().as_value();
            let enrollment = self.resolve_field(value, "predecessor_enrollment")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_equal(
                value,
                "node",
                enrollment.record().as_value(),
                "node",
                "restore enrollment node",
            )?;
            if value["decision"] == "eligible_enrolled_inactive" {
                let key = self.resolve_field(value, "new_key_event")?;
                let activation = self.resolve_field(value, "activation_candidate")?;
                require_schema(key, RuntimeSchema::NodeKeyLifecycleEventV1)?;
                require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
                if key.record().as_value()["node"] != value["node"]
                    || activation.record().as_value()["node"] != value["node"]
                    || key.record().as_value()["resulting_activation"]
                        != Value::from(activation.exact_reference())
                    || activation.record().as_value()["active_key"]
                        != key.record().as_value()["key"]
                {
                    return Err(ContractError::RetirementJoin(
                        "restore activation candidate",
                    ));
                }
            }
        }

        for snapshot in self.by_schema(RuntimeSchema::DecommissionLedgerSnapshotV1) {
            let value = snapshot.record().as_value();
            let enrollment = self.resolve_field(value, "enrollment")?;
            let activation = self.resolve_field(value, "activation")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            if value["node"] != enrollment.record().as_value()["node"]
                || value["node"] != activation.record().as_value()["node"]
                || value["enrollment"] != activation.record().as_value()["enrollment"]
                || value["namespace"] != enrollment.record().as_value()["namespace"]
                || value["namespace"] != activation.record().as_value()["namespace"]
            {
                return Err(ContractError::RetirementJoin("decommission snapshot scope"));
            }
        }

        let mut cut_successors = BTreeMap::<Sha256Digest, usize>::new();
        for cut in self.by_schema(RuntimeSchema::DecommissionCutV1) {
            let value = cut.record().as_value();
            let enrollment = self.resolve_field(value, "enrollment")?;
            let activation = self.resolve_field(value, "activation")?;
            let snapshot = self.resolve_field(value, "ledger_snapshot")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(snapshot, RuntimeSchema::DecommissionLedgerSnapshotV1)?;
            for target in [enrollment, activation, snapshot] {
                if value["node"] != target.record().as_value()["node"] {
                    return Err(ContractError::RetirementJoin("decommission node"));
                }
            }
            if value["enrollment"] != activation.record().as_value()["enrollment"]
                || value["enrollment"] != snapshot.record().as_value()["enrollment"]
                || value["activation"] != snapshot.record().as_value()["activation"]
                || value["effective_at"] != snapshot.record().as_value()["evaluated_at"]
            {
                return Err(ContractError::RetirementJoin("decommission cut snapshot"));
            }
            if value["result_state"] == "decommissioned" {
                let predecessor = self.resolve_field(value, "predecessor_cut")?;
                require_schema(predecessor, RuntimeSchema::DecommissionCutV1)?;
                if predecessor.record().as_value()["result_state"] != "draining"
                    || predecessor.record().as_value()["node"] != value["node"]
                    || timestamp(predecessor.record().as_value(), "effective_at")?
                        >= timestamp(value, "effective_at")?
                {
                    return Err(ContractError::RetirementJoin("decommission predecessor"));
                }
                *cut_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if cut_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::RetirementJoin("decommission cut fork"));
                }
            }
        }
        Ok(())
    }

    fn validate_catalogs(&self, context: &ValidationContext) -> Result<()> {
        for record in self.records() {
            let mut identities = Vec::new();
            let mut references = Vec::new();
            collect_carriers(record.record().as_value(), &mut identities, &mut references)?;
            for identity in identities {
                context.identities.resolve(&identity)?;
            }
            for reference in references {
                match self.records.get(&reference.record_id) {
                    Some(target)
                        if target.schema().as_str() == reference.schema.as_str()
                            && target.bytes_digest() == &reference.bytes_digest => {}
                    Some(_) => return Err(ContractError::RecordReferenceSubstitution),
                    None if context.external_records.contains(&reference) => {}
                    None => {
                        return Err(ContractError::UnresolvedRecordReference(
                            reference.record_id.to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_reference_dag(&self) -> Result<()> {
        let mut edges: BTreeMap<Sha256Digest, BTreeSet<Sha256Digest>> = BTreeMap::new();
        for record in self.records() {
            let mut identities = Vec::new();
            let mut references = Vec::new();
            collect_carriers(record.record().as_value(), &mut identities, &mut references)?;
            edges.insert(
                record.record_id().clone(),
                references
                    .into_iter()
                    .filter(|reference| self.records.contains_key(&reference.record_id))
                    .map(|reference| reference.record_id)
                    .collect(),
            );
        }
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for node in edges.keys() {
            visit_reference_dag(node, &edges, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Closed topology join is intentionally audited together.
    fn validate_topology(&self) -> Result<()> {
        let activations: Vec<_> = self.by_schema(RuntimeSchema::RuntimeActivationV1).collect();
        for activation in &activations {
            let value = activation.record().as_value();
            let enrollment = self.resolve_field(value, "enrollment")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            let role = self.resolve_field(value, "role_manifest")?;
            require_schema(role, RuntimeSchema::RoleManifestV1)?;
            let cohort = self.resolve_field(value, "cohort_manifest")?;
            require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;

            require_equal(
                value,
                "node",
                enrollment.record().as_value(),
                "node",
                "node",
            )?;
            require_equal(value, "role", role.record().as_value(), "role", "role")?;
            require_equal(
                value,
                "role_generation",
                role.record().as_value(),
                "generation",
                "role generation",
            )?;
            require_equal(
                value,
                "static_profile_cohort",
                cohort.record().as_value(),
                "cohort",
                "cohort",
            )?;
            require_equal(
                value,
                "cohort_generation",
                cohort.record().as_value(),
                "generation",
                "cohort generation",
            )?;

            let relations = value["relations"]
                .as_object()
                .ok_or(ContractError::TopologyJoin("activation relations"))?;
            let required_relations = [
                "node_subject",
                "subject_platform",
                "node_vantage",
                "node_role",
                "node_static_profile_cohort",
            ];
            if relations
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(required_relations)
            {
                return Err(ContractError::TopologyJoin("activation relation closure"));
            }
            for (kind, reference) in relations {
                let relation = self.resolve_value(reference)?;
                require_schema(relation, RuntimeSchema::HostRoleRelationV1)?;
                if relation.record().as_value()["relation_kind"] != *kind {
                    return Err(ContractError::TopologyJoin("relation kind"));
                }
                validate_relation_endpoints(value, relation.record().as_value())?;
            }

            let attachments = value["witness_attachments"]
                .as_array()
                .ok_or(ContractError::TopologyJoin("activation attachments"))?;
            if attachments.is_empty() {
                return Err(ContractError::TopologyJoin("empty activation attachments"));
            }
            for reference in attachments {
                let attachment = self.resolve_value(reference)?;
                require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
                require_equal(
                    attachment.record().as_value(),
                    "node",
                    value,
                    "node",
                    "attachment node",
                )?;
                require_reference_equal(
                    attachment.record().as_value(),
                    "enrollment",
                    enrollment,
                    "attachment enrollment",
                )?;
                require_equal(
                    attachment.record().as_value(),
                    "role",
                    value,
                    "role",
                    "attachment role",
                )?;
                require_reference_equal(
                    attachment.record().as_value(),
                    "role_manifest",
                    role,
                    "attachment role manifest",
                )?;
                validate_witness_slot(attachment.record().as_value(), role.record().as_value())?;
            }

            let compatible = role.record().as_value()["compatible_static_profile_cohorts"]
                .as_array()
                .ok_or(ContractError::TopologyJoin("role cohort compatibility"))?;
            let cohort_ref = cohort.exact_reference();
            let admitted = compatible.iter().any(|entry| {
                entry["cohort"] == value["static_profile_cohort"]
                    && entry["generation"] == value["cohort_generation"]
                    && serde_json::from_value::<RecordRef>(entry["manifest"].clone())
                        .is_ok_and(|reference| reference == cohort_ref)
            });
            if !admitted {
                return Err(ContractError::TopologyJoin("role/cohort compatibility"));
            }
            for dependency in [role, cohort] {
                if !interval_covers(
                    &dependency.record().as_value()["effective_interval"],
                    &value["effective_interval"],
                )? {
                    return Err(ContractError::TopologyJoin(
                        "activation exceeds role/cohort effective interval",
                    ));
                }
            }
            for reference in relations.values() {
                let relation = self.resolve_value(reference)?;
                if !interval_covers(
                    &relation.record().as_value()["effective_interval"],
                    &value["effective_interval"],
                )? {
                    return Err(ContractError::TopologyJoin(
                        "activation exceeds relation effective interval",
                    ));
                }
            }
            for reference in attachments {
                let attachment = self.resolve_value(reference)?;
                if !interval_covers(
                    &attachment.record().as_value()["effective_interval"],
                    &value["effective_interval"],
                )? {
                    return Err(ContractError::TopologyJoin(
                        "activation exceeds witness effective interval",
                    ));
                }
            }
        }
        for (index, left) in activations.iter().enumerate() {
            for right in &activations[index + 1..] {
                let left_value = left.record().as_value();
                let right_value = right.record().as_value();
                if left_value["node"] == right_value["node"]
                    && intervals_overlap(
                        &left_value["effective_interval"],
                        &right_value["effective_interval"],
                    )?
                {
                    return Err(ContractError::TopologyJoin(
                        "node has overlapping effective activation intervals",
                    ));
                }
                if left_value["enrollment"] == right_value["enrollment"]
                    && left_value["active_key"] != right_value["active_key"]
                    && intervals_overlap(
                        &left_value["effective_interval"],
                        &right_value["effective_interval"],
                    )?
                {
                    return Err(ContractError::TopologyJoin(
                        "enrollment has overlapping active key generations",
                    ));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One closed request/admission/custody/launch law.
    fn validate_invocations(&self) -> Result<()> {
        let mut request_occurrences = BTreeMap::<(String, Sha256Digest, String), Vec<u8>>::new();
        let mut idempotency_occurrences =
            BTreeMap::<(String, Sha256Digest, String), Vec<u8>>::new();
        for request in self.by_schema(RuntimeSchema::DiagnosticInvocationRequestV1) {
            let value = request.record().as_value();
            let authorization = self.resolve_field(value, "invocation_authorization")?;
            require_schema(authorization, RuntimeSchema::OperationAuthorizationV1)?;
            let authorization_value = authorization.record().as_value();
            if authorization_value["scope"] != "diagnostic_invocation"
                || authorization_value["operation"] != "diagnostic.invoke"
                || authorization_value["decision"] != "granted"
                || authorization_value["requesting_principal"] != value["requesting_principal"]
            {
                return Err(ContractError::InvocationJoin(
                    "request lacks exact granted diagnostic authority",
                ));
            }
            let activation = self.resolve_field(&value["expected_binding"], "activation")?;
            let role = self.resolve_field(&value["expected_binding"], "role_manifest")?;
            let cohort = self.resolve_field(&value["expected_binding"], "cohort_manifest")?;
            let enrollment = self.resolve_field(&value["expected_binding"], "enrollment")?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(role, RuntimeSchema::RoleManifestV1)?;
            require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            for (field, expected) in [
                ("node", &value["target"]["node"]),
                ("subject", &value["target"]["subject"]),
                ("vantage", &value["target"]["vantage"]),
            ] {
                let actual = match field {
                    "node" => activation.record().as_value()["node"].clone(),
                    "subject" => {
                        let relation = self.resolve_field(
                            &activation.record().as_value()["relations"],
                            "node_subject",
                        )?;
                        relation.record().as_value()["right"].clone()
                    }
                    "vantage" => {
                        let relation = self.resolve_field(
                            &activation.record().as_value()["relations"],
                            "node_vantage",
                        )?;
                        relation.record().as_value()["right"].clone()
                    }
                    _ => unreachable!(),
                };
                if &actual != expected {
                    return Err(ContractError::InvocationJoin(
                        "request target differs from effective activation",
                    ));
                }
            }
            if value["expected_binding"]["activation_generation"]
                != activation.record().as_value()["generation"]
                || value["expected_binding"]["role_generation"]
                    != role.record().as_value()["generation"]
                || value["expected_binding"]["cohort_generation"]
                    != cohort.record().as_value()["generation"]
                || value["expected_binding"]["witness_attachments"]
                    != activation.record().as_value()["witness_attachments"]
                || activation.record().as_value()["enrollment"]
                    != Value::from(enrollment.exact_reference())
                || activation.record().as_value()["role_manifest"]
                    != Value::from(role.exact_reference())
                || activation.record().as_value()["cohort_manifest"]
                    != Value::from(cohort.exact_reference())
            {
                return Err(ContractError::InvocationJoin(
                    "request expected topology generation substitution",
                ));
            }
            let profile = &value["profile"];
            if !role.record().as_value()["permitted_profiles"]
                .as_array()
                .is_some_and(|profiles| profiles.contains(profile))
                || !cohort.record().as_value()["members"]["profiles"]
                    .as_array()
                    .is_some_and(|profiles| profiles.contains(profile))
            {
                return Err(ContractError::InvocationJoin(
                    "profile absent from exact role/cohort",
                ));
            }
            for attachment_ref in value["expected_binding"]["witness_attachments"]
                .as_array()
                .ok_or(ContractError::InvocationJoin("request witness set absent"))?
            {
                let attachment = self.resolve_value(attachment_ref)?;
                require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
                if !attachment.record().as_value()["supported_profiles"]
                    .as_array()
                    .is_some_and(|profiles| profiles.contains(profile))
                {
                    return Err(ContractError::InvocationJoin(
                        "selected witness does not support profile",
                    ));
                }
            }
            let binding = serde_json::json!({
                "request_preimage_digest": value["request_preimage_digest"],
                "node": value["target"]["node"],
                "subject": value["target"]["subject"],
                "vantage": value["target"]["vantage"],
                "profile": value["profile"],
                "activation_id": activation.record_id(),
                "activation_generation": activation.record().as_value()["generation"],
                "role_manifest_id": role.record_id(),
                "role_generation": role.record().as_value()["generation"],
                "cohort_manifest_id": cohort.record_id(),
                "cohort_generation": cohort.record().as_value()["generation"],
                "witness_attachment_ids": value["expected_binding"]["witness_attachments"]
                    .as_array()
                    .expect("validated request witness array")
                    .iter()
                    .map(|reference| reference["record_id"].clone())
                    .collect::<Vec<_>>(),
                "purpose_digest": semantic_digest(&value["purpose"])?,
                "time_bounds_digest": semantic_digest(&value["time_bounds"])?,
                "delivery_binding_digest": semantic_digest(&value["delivery"])?,
            });
            if authorization_value["binding"] != binding {
                return Err(ContractError::InvocationJoin(
                    "invocation grant did not bind exact request inputs",
                ));
            }
            let interval: EffectiveInterval =
                serde_json::from_value(authorization_value["effective_interval"].clone())?;
            let not_before = value["time_bounds"]["not_before"]
                .as_str()
                .ok_or(ContractError::InvocationJoin("request not-before absent"))?;
            if !interval.contains(&Timestamp::parse(not_before.to_owned())?) {
                return Err(ContractError::InvocationJoin(
                    "invocation grant not effective at request admission",
                ));
            }
            let authorization_id = authorization.record_id().clone();
            let target_node = serde_json::to_string(&value["target"]["node"])?;
            let request_id = value["request_id"]
                .as_str()
                .ok_or(ContractError::InvocationJoin("request occurrence absent"))?
                .to_owned();
            let idempotency = value["idempotency"]["key"]
                .as_str()
                .ok_or(ContractError::InvocationJoin("idempotency key absent"))?
                .to_owned();
            for (map, key) in [
                (
                    &mut request_occurrences,
                    (target_node.clone(), authorization_id.clone(), request_id),
                ),
                (
                    &mut idempotency_occurrences,
                    (target_node, authorization_id, idempotency),
                ),
            ] {
                if map
                    .insert(key, request.canonical_bytes().to_vec())
                    .is_some_and(|prior| prior != request.canonical_bytes())
                {
                    return Err(ContractError::InvocationJoin(
                        "request or idempotency occurrence collision",
                    ));
                }
            }
        }

        for decision in self.by_schema(RuntimeSchema::InvocationDecisionV1) {
            let value = decision.record().as_value();
            let request = self.resolve_field(value, "request")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            if value["request_digest"] != request.record().as_value()["request_digest"] {
                return Err(ContractError::InvocationJoin("decision request digest"));
            }
            let activation = self.resolve_field(value, "activation_snapshot")?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            if value["invocation_authorization"]
                != request.record().as_value()["invocation_authorization"]
                || value["authentication_evidence"]
                    != request.record().as_value()["authentication_evidence"]
                || value["clock"] != request.record().as_value()["time_bounds"]["clock"]
            {
                return Err(ContractError::InvocationJoin(
                    "decision authentication/authorization",
                ));
            }
            if value["decision"] == "accepted" {
                let reservation = self.resolve_field(&value["custody"], "reservation")?;
                require_schema(reservation, RuntimeSchema::CustodyReservationV1)?;
                if value["custody"]["state"] != "reserved"
                    || reservation.record().as_value()["decision"] != "reserved"
                {
                    return Err(ContractError::InvocationJoin(
                        "accepted decision lacks exact reserved custody",
                    ));
                }
            }
        }
        for reservation in self.by_schema(RuntimeSchema::CustodyReservationV1) {
            let value = reservation.record().as_value();
            let request = self.resolve_field(value, "request")?;
            let activation = self.resolve_field(value, "activation")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_equal(
                value,
                "node",
                request.record().as_value(),
                "target",
                "reservation request target",
            )
            .or_else(|_| {
                if value["node"] == request.record().as_value()["target"]["node"] {
                    Ok(())
                } else {
                    Err(ContractError::InvocationJoin("reservation node"))
                }
            })?;
            if value["node"] != activation.record().as_value()["node"]
                || value["profile"] != request.record().as_value()["profile"]
                || value["clock"] != request.record().as_value()["time_bounds"]["clock"]
            {
                return Err(ContractError::InvocationJoin(
                    "reservation activation/profile",
                ));
            }
            let policy = self.resolve_field(value, "delivery_requirement")?;
            require_schema(policy, RuntimeSchema::BufferDeliveryPolicyV1)?;
            let total = value["component_bounds"]
                .as_object()
                .ok_or(ContractError::InvocationJoin("reservation components"))?
                .values()
                .try_fold(0_u64, |sum, component| {
                    component
                        .as_u64()
                        .and_then(|value| sum.checked_add(value))
                        .ok_or(ContractError::InvocationJoin(
                            "reservation component arithmetic",
                        ))
                })?;
            let required = value["total_required_bytes"]
                .as_u64()
                .ok_or(ContractError::InvocationJoin("reservation total"))?;
            let reserved = value["reserved_bytes"]
                .as_u64()
                .ok_or(ContractError::InvocationJoin("reservation bytes"))?;
            let protected = value["protected_failure_reserve_bytes"].as_u64().ok_or(
                ContractError::InvocationJoin("reservation protected reserve"),
            )?;
            let capacity = policy.record().as_value()["capacity"]["total_bytes"]
                .as_u64()
                .ok_or(ContractError::InvocationJoin("policy capacity"))?;
            if value["decision"] != "reserved"
                || total != required
                || reserved < required
                || protected
                    != policy.record().as_value()["capacity"]["protected_failure_receipt_bytes"]
                        .as_u64()
                        .ok_or(ContractError::InvocationJoin("policy protected reserve"))?
                || reserved
                    .checked_add(protected)
                    .is_none_or(|used| used > capacity)
                || value["custody_policy"]
                    != policy.record().as_value()["policy_identities"]["custody"]
            {
                return Err(ContractError::InvocationJoin(
                    "reservation does not close custody policy and capacity",
                ));
            }
        }
        for launch in self.by_schema(RuntimeSchema::ExecutionLaunchV1) {
            let value = launch.record().as_value();
            let request = self.resolve_field(value, "outer_request")?;
            let decision = self.resolve_field(value, "invocation_decision")?;
            let activation = self.resolve_field(value, "activation_snapshot")?;
            let reservation = self.resolve_field(value, "custody_reservation")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            require_schema(decision, RuntimeSchema::InvocationDecisionV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(reservation, RuntimeSchema::CustodyReservationV1)?;
            require_reference_equal(
                decision.record().as_value(),
                "request",
                request,
                "launch decision request",
            )?;
            require_reference_equal(
                reservation.record().as_value(),
                "request",
                request,
                "launch reservation request",
            )?;
            require_reference_equal(
                reservation.record().as_value(),
                "activation",
                activation,
                "launch reservation activation",
            )?;
            if value["node"] != request.record().as_value()["target"]["node"]
                || value["node"] != activation.record().as_value()["node"]
                || value["profile"] != request.record().as_value()["profile"]
                || value["clock"] != request.record().as_value()["time_bounds"]["clock"]
                || decision.record().as_value()["decision"] != "accepted"
                || decision.record().as_value()["custody"]["reservation"]
                    != Value::from(reservation.exact_reference())
                || value["selected_witness_attachments"]
                    != request.record().as_value()["expected_binding"]["witness_attachments"]
            {
                return Err(ContractError::InvocationJoin("launch node/profile"));
            }
            if value["prelaunch_checks"]["authentication"]
                != request.record().as_value()["authentication_evidence"]
                || value["prelaunch_checks"]["invocation_authorization"]
                    != request.record().as_value()["invocation_authorization"]
                || value["prelaunch_checks"]["custody"]
                    != reservation.record().as_value()["reservation_commit"]
            {
                return Err(ContractError::InvocationJoin(
                    "launch prechecks substituted authentication, authority, or custody",
                ));
            }
            for attachment in value["selected_witness_attachments"]
                .as_array()
                .ok_or(ContractError::InvocationJoin("launch attachments"))?
            {
                let attachment = self.resolve_value(attachment)?;
                require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
                if !activation.record().as_value()["witness_attachments"]
                    .as_array()
                    .is_some_and(|items| items.contains(&Value::from(attachment.exact_reference())))
                {
                    return Err(ContractError::InvocationJoin(
                        "launch attachment outside activation",
                    ));
                }
            }
            let reserved_at = timestamp(reservation.record().as_value(), "reserved_at")?;
            let decided_at = timestamp(decision.record().as_value(), "decided_at")?;
            let launched_at = timestamp(value, "launched_at")?;
            let expires_at = timestamp(reservation.record().as_value(), "expires_at")?;
            let not_before = Timestamp::parse(
                request.record().as_value()["time_bounds"]["not_before"]
                    .as_str()
                    .ok_or(ContractError::InvocationJoin("request not-before"))?
                    .to_owned(),
            )?
            .instant();
            let request_deadline = Timestamp::parse(
                request.record().as_value()["time_bounds"]["deadline"]
                    .as_str()
                    .ok_or(ContractError::InvocationJoin("request deadline"))?
                    .to_owned(),
            )?
            .instant();
            let attempt_deadline = timestamp(value, "attempt_deadline")?;
            if !(reserved_at <= decided_at
                && decided_at <= launched_at
                && launched_at < expires_at
                && launched_at >= not_before
                && attempt_deadline <= request_deadline)
            {
                return Err(ContractError::InvocationJoin(
                    "custody, decision, launch, or deadline ordering",
                ));
            }
            let budget = request.record().as_value()["time_bounds"]["maximum_execution_ms"]
                .as_i64()
                .ok_or(ContractError::InvocationJoin("request execution budget"))?;
            if value["maximum_execution_ms"].as_i64() != Some(budget)
                || (attempt_deadline - launched_at).num_milliseconds() != budget
            {
                return Err(ContractError::InvocationJoin(
                    "launch execution budget/deadline substitution",
                ));
            }
            for dependency in [
                activation,
                self.resolve_field(activation.record().as_value(), "role_manifest")?,
                self.resolve_field(activation.record().as_value(), "cohort_manifest")?,
            ] {
                if !interval_contains_attempt(
                    &dependency.record().as_value()["effective_interval"],
                    launched_at,
                    attempt_deadline,
                )? {
                    return Err(ContractError::InvocationJoin(
                        "topology dependency does not cover execution attempt",
                    ));
                }
            }
            for relation in activation.record().as_value()["relations"]
                .as_object()
                .ok_or(ContractError::InvocationJoin("activation relations"))?
                .values()
            {
                let relation = self.resolve_value(relation)?;
                if !interval_contains_attempt(
                    &relation.record().as_value()["effective_interval"],
                    launched_at,
                    attempt_deadline,
                )? {
                    return Err(ContractError::InvocationJoin(
                        "relation does not cover execution attempt",
                    ));
                }
            }
            for attachment in value["selected_witness_attachments"]
                .as_array()
                .expect("validated launch attachments")
            {
                let attachment = self.resolve_value(attachment)?;
                if !interval_contains_attempt(
                    &attachment.record().as_value()["effective_interval"],
                    launched_at,
                    attempt_deadline,
                )? {
                    return Err(ContractError::InvocationJoin(
                        "witness does not cover execution attempt",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_bindings(&self) -> Result<()> {
        for binding in self.by_schema(RuntimeSchema::ExecutionIdentityBindingV2) {
            let value = binding.record().as_value();
            let request = self.resolve_field(value, "outer_request")?;
            let decision = self.resolve_field(value, "invocation_decision")?;
            let launch = self.resolve_field(value, "execution_launch")?;
            let enrollment = self.resolve_field(value, "enrollment")?;
            let activation = self.resolve_field(value, "activation")?;
            let role = self.resolve_field(value, "role_manifest")?;
            let cohort = self.resolve_field(value, "static_profile_cohort_manifest")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            require_schema(decision, RuntimeSchema::InvocationDecisionV1)?;
            require_schema(launch, RuntimeSchema::ExecutionLaunchV1)?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(role, RuntimeSchema::RoleManifestV1)?;
            require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;

            require_reference_equal(
                launch.record().as_value(),
                "outer_request",
                request,
                "binding launch request",
            )?;
            require_reference_equal(
                launch.record().as_value(),
                "invocation_decision",
                decision,
                "binding launch decision",
            )?;
            require_reference_equal(
                launch.record().as_value(),
                "activation_snapshot",
                activation,
                "binding launch activation",
            )?;
            require_reference_equal(
                activation.record().as_value(),
                "enrollment",
                enrollment,
                "binding activation enrollment",
            )?;
            require_reference_equal(
                activation.record().as_value(),
                "role_manifest",
                role,
                "binding activation role",
            )?;
            require_reference_equal(
                activation.record().as_value(),
                "cohort_manifest",
                cohort,
                "binding activation cohort",
            )?;
            if value["source_relations"] != activation.record().as_value()["relations"]
                || value["diagnostic"]["request_id"] != request.record().as_value()["request_id"]
            {
                return Err(ContractError::TopologyJoin(
                    "binding relation/request closure",
                ));
            }
            if value["witness_attachments"] != activation.record().as_value()["witness_attachments"]
            {
                return Err(ContractError::TopologyJoin(
                    "binding witness attachment closure",
                ));
            }
            let witness_attachments = value["witness_attachments"]
                .as_array()
                .ok_or(ContractError::ExpectedArray)?;
            if witness_attachments.len() != 1
                || witness_attachments
                    != launch.record().as_value()["selected_witness_attachments"]
                        .as_array()
                        .ok_or(ContractError::ExpectedArray)?
            {
                return Err(ContractError::BindingWitnessMultiplicity);
            }
            if value["provider_attempts"]
                .as_array()
                .ok_or(ContractError::ExpectedArray)?
                .len()
                != 1
            {
                return Err(ContractError::BindingProviderAttemptMultiplicity);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Eight ratified slots form one closed source-join law.
    fn validate_execution_binding_source(
        &self,
        binding: &ValidatedRuntimeRecord,
        sources: &ExecutionBindingSourceCorpus,
        consumed: &mut BTreeSet<RecordRef>,
    ) -> Result<()> {
        let value = binding.record().as_value();
        let request = self.resolve_field(value, "outer_request")?;
        let activation = self.resolve_field(value, "activation")?;
        let role = self.resolve_field(value, "role_manifest")?;
        let cohort = self.resolve_field(value, "static_profile_cohort_manifest")?;
        require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
        require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
        require_schema(role, RuntimeSchema::RoleManifestV1)?;
        require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;
        if value["source_relations"] != activation.record().as_value()["relations"] {
            return Err(ContractError::BindingSourceJoin(
                "source_relations".to_owned(),
            ));
        }

        let relations = value["source_relations"]
            .as_object()
            .ok_or(ContractError::ExpectedObject("source_relations"))?;
        let node_subject = self.resolve_value(&relations["node_subject"])?;
        let subject_platform = self.resolve_value(&relations["subject_platform"])?;
        let node_vantage = self.resolve_value(&relations["node_vantage"])?;
        for relation in [node_subject, subject_platform, node_vantage] {
            require_schema(relation, RuntimeSchema::HostRoleRelationV1)?;
        }

        let resolved = value["resolved_references"]
            .as_object()
            .ok_or(ContractError::ExpectedObject("resolved_references"))?;
        let expected_slots = [
            ("node", activation, "/node".to_owned()),
            ("subject", node_subject, "/right".to_owned()),
            ("platform", subject_platform, "/right".to_owned()),
            ("vantage", node_vantage, "/right".to_owned()),
            ("role", role, "/role".to_owned()),
            ("static_profile_cohort", cohort, "/cohort".to_owned()),
        ];
        let mut source_pairs = BTreeSet::new();
        for slot in [
            "node",
            "subject",
            "platform",
            "vantage",
            "role",
            "static_profile_cohort",
            "witness",
            "diagnostic_profile",
        ] {
            let entry = resolved[slot]
                .as_object()
                .ok_or(ContractError::ExpectedObject("resolved_references[]"))?;
            let source: RecordRef = serde_json::from_value(entry["source_artifact"].clone())?;
            let pointer = entry["source_pointer"]
                .as_str()
                .ok_or(ContractError::ExpectedString("source_pointer"))?
                .to_owned();
            if !source_pairs.insert((source, pointer)) {
                return Err(ContractError::DuplicateBindingSource);
            }
        }
        for (slot, source, pointer) in expected_slots {
            validate_resolved_binding_source(slot, resolved, source, &pointer, sources, consumed)?;
        }

        let selected_witnesses = value["witness_attachments"]
            .as_array()
            .ok_or(ContractError::ExpectedArray)?
            .as_slice();
        if selected_witnesses.len() != 1 {
            return Err(ContractError::BindingWitnessMultiplicity);
        }
        let selected_witness = self.resolve_value(&selected_witnesses[0])?;
        require_schema(selected_witness, RuntimeSchema::WitnessAttachmentV1)?;
        validate_resolved_binding_source(
            "witness",
            resolved,
            selected_witness,
            "/witness",
            sources,
            consumed,
        )?;

        if value["provider_attempts"]
            .as_array()
            .ok_or(ContractError::ExpectedArray)?
            .len()
            != 1
        {
            return Err(ContractError::BindingProviderAttemptMultiplicity);
        }
        let profile = &request.record().as_value()["profile"];
        let profiles = cohort.record().as_value()["members"]["profiles"]
            .as_array()
            .ok_or(ContractError::ExpectedArray)?;
        let matching_profile_indexes = profiles
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| (candidate == profile).then_some(index))
            .collect::<Vec<_>>();
        if matching_profile_indexes.len() != 1 {
            return Err(ContractError::BindingSourceJoin(
                "diagnostic_profile".to_owned(),
            ));
        }
        validate_resolved_binding_source(
            "diagnostic_profile",
            resolved,
            cohort,
            &format!("/members/profiles/{}", matching_profile_indexes[0]),
            sources,
            consumed,
        )?;
        let resolution_engine_identity: IdentityRef =
            serde_json::from_value(value["resolver"].clone())?;
        validate_unreferenced_identity_descriptor(
            "resolver",
            &resolution_engine_identity,
            sources,
            consumed,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Delivery state and custody joins form one closed law.
    fn validate_delivery(&self) -> Result<()> {
        for envelope in self.by_schema(RuntimeSchema::AuthenticatedArtifactEnvelopeV1) {
            let value = envelope.record().as_value();
            let binding = self.resolve_field(value, "execution_binding")?;
            let activation = self.resolve_field(value, "producer_activation")?;
            require_schema(binding, RuntimeSchema::ExecutionIdentityBindingV2)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            let artifact = &value["artifact"];
            let diagnostic = &binding.record().as_value()["diagnostic"];
            let request = self.resolve_field(binding.record().as_value(), "outer_request")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            if ["schema", "artifact_id", "file_bytes_digest"]
                .iter()
                .any(|field| artifact[*field] != diagnostic[*field])
                || value["producer_node"] != activation.record().as_value()["node"]
                || value["producer_key_generation"] != activation.record().as_value()["active_key"]
                || value["intended_receiver"]
                    != request.record().as_value()["delivery"]["destination"]
                || value["destination_generation"]
                    != request.record().as_value()["delivery"]["destination_generation"]
                || value["transport_policy"]
                    != request.record().as_value()["delivery"]["delivery_policy"]
            {
                return Err(ContractError::DeliveryJoin(
                    "envelope artifact/producer binding",
                ));
            }
        }

        let mut attempt_starts = BTreeMap::<String, &ValidatedRuntimeRecord>::new();
        let mut attempt_completions = BTreeMap::<String, &ValidatedRuntimeRecord>::new();
        let mut attempt_numbers = BTreeSet::<(Sha256Digest, u64)>::new();
        for attempt in self.by_schema(RuntimeSchema::ArtifactDeliveryAttemptV1) {
            let value = attempt.record().as_value();
            let envelope = self.resolve_field(value, "envelope")?;
            require_schema(envelope, RuntimeSchema::AuthenticatedArtifactEnvelopeV1)?;
            if !artifact_tuple_equal(
                &value["artifact"],
                &envelope.record().as_value()["artifact"],
            ) || value["producer_node"] != envelope.record().as_value()["producer_node"]
                || value["producer_key_generation"]
                    != envelope.record().as_value()["producer_key_generation"]
                || value["destination"] != envelope.record().as_value()["intended_receiver"]
                || value["destination_generation"]
                    != envelope.record().as_value()["destination_generation"]
                || value["transport_policy"] != envelope.record().as_value()["transport_policy"]
            {
                return Err(ContractError::DeliveryJoin("attempt envelope binding"));
            }
            let occurrence = value["attempt_occurrence_id"]
                .as_str()
                .ok_or(ContractError::DeliveryJoin("attempt occurrence identity"))?
                .to_owned();
            let number = value["attempt_number"]
                .as_u64()
                .ok_or(ContractError::DeliveryJoin("attempt number"))?;
            if value["outcome"] == "in_progress" {
                if attempt_starts.insert(occurrence.clone(), attempt).is_some()
                    || !attempt_numbers.insert((envelope.record_id().clone(), number))
                {
                    return Err(ContractError::DeliveryJoin(
                        "duplicate attempt start occurrence or number",
                    ));
                }
                if number == 1 && value["predecessor_attempt_record"] != Value::Null {
                    return Err(ContractError::DeliveryJoin(
                        "first attempt start has predecessor",
                    ));
                }
                if number > 1 {
                    if value["predecessor_attempt_record"] == Value::Null {
                        return Err(ContractError::DeliveryJoin(
                            "later attempt start lacks predecessor",
                        ));
                    }
                    let predecessor = self.resolve_field(value, "predecessor_attempt_record")?;
                    require_schema(predecessor, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                    if predecessor.record().as_value()["outcome"] == "in_progress"
                        || predecessor.record().as_value()["attempt_number"].as_u64()
                            != Some(number - 1)
                        || predecessor.record().as_value()["envelope"] != value["envelope"]
                        || predecessor.record().as_value()["artifact"] != value["artifact"]
                        || predecessor.record().as_value()["destination"] != value["destination"]
                        || predecessor.record().as_value()["destination_generation"]
                            != value["destination_generation"]
                        || predecessor.record().as_value()["transport_policy"]
                            != value["transport_policy"]
                        || timestamp(predecessor.record().as_value(), "completed_at")?
                            > timestamp(value, "started_at")?
                    {
                        return Err(ContractError::DeliveryJoin(
                            "later attempt predecessor substitution",
                        ));
                    }
                    if predecessor.record().as_value()["next_attempt_not_before"] != Value::Null
                        && Timestamp::parse(
                            predecessor.record().as_value()["next_attempt_not_before"]
                                .as_str()
                                .ok_or(ContractError::DeliveryJoin("retry deadline malformed"))?
                                .to_owned(),
                        )?
                        .instant()
                            > timestamp(value, "started_at")?
                    {
                        return Err(ContractError::DeliveryJoin(
                            "retry started before durable deadline",
                        ));
                    }
                }
            } else {
                if attempt_completions
                    .insert(occurrence.clone(), attempt)
                    .is_some()
                {
                    return Err(ContractError::DeliveryJoin(
                        "duplicate attempt completion occurrence",
                    ));
                }
                let predecessor = self.resolve_field(value, "predecessor_attempt_record")?;
                require_schema(predecessor, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                for field in [
                    "attempt_occurrence_id",
                    "attempt_number",
                    "envelope",
                    "artifact",
                    "producer_node",
                    "producer_key_generation",
                    "destination",
                    "destination_generation",
                    "transport",
                    "transport_policy",
                    "started_at",
                ] {
                    if predecessor.record().as_value()[field] != value[field] {
                        return Err(ContractError::DeliveryJoin(
                            "attempt completion substituted start occurrence",
                        ));
                    }
                }
                if predecessor.record().as_value()["outcome"] != "in_progress"
                    || timestamp(value, "completed_at")? < timestamp(value, "started_at")?
                {
                    return Err(ContractError::DeliveryJoin(
                        "attempt completion lacks exact start",
                    ));
                }
            }
        }
        if attempt_completions
            .keys()
            .any(|occurrence| !attempt_starts.contains_key(occurrence))
        {
            return Err(ContractError::DeliveryJoin(
                "attempt completion exists without start",
            ));
        }

        for receipt in self.by_schema(RuntimeSchema::ArtifactCustodyReceiptV1) {
            let value = receipt.record().as_value();
            let envelope = self.resolve_field(value, "envelope")?;
            let attempt = self.resolve_field(value, "attempt")?;
            require_schema(envelope, RuntimeSchema::AuthenticatedArtifactEnvelopeV1)?;
            require_schema(attempt, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
            if !artifact_tuple_equal(
                &value["artifact"],
                &envelope.record().as_value()["artifact"],
            ) || !artifact_tuple_equal(
                &value["artifact"],
                &attempt.record().as_value()["artifact"],
            ) || value["authenticated_sender"] != envelope.record().as_value()["producer_node"]
                || value["receiver"] != envelope.record().as_value()["intended_receiver"]
                || value["producer_key_generation"]
                    != envelope.record().as_value()["producer_key_generation"]
                || value["destination_generation"]
                    != envelope.record().as_value()["destination_generation"]
                || value["transport_policy"] != envelope.record().as_value()["transport_policy"]
                || value["envelope"] != attempt.record().as_value()["envelope"]
                || value["replay"]["replay_key"] != envelope.record().as_value()["replay_key"]
                || value["producer_authentication"]["verified_signed_content_digest"]
                    != envelope.record().as_value()["authentication"]["signed_content_digest"]
                || value["custody"]["exact_bytes_digest"] != value["artifact"]["file_bytes_digest"]
                || value["custody"]["byte_length"] != value["artifact"]["byte_length"]
            {
                return Err(ContractError::DeliveryJoin("receiver custody binding"));
            }
            if timestamp(value, "received_at")?
                < timestamp(attempt.record().as_value(), "completed_at")?
                || Timestamp::parse(
                    value["custody"]["committed_at"]
                        .as_str()
                        .ok_or(ContractError::DeliveryJoin(
                            "receiver custody time malformed",
                        ))?
                        .to_owned(),
                )?
                .instant()
                    < timestamp(value, "received_at")?
            {
                return Err(ContractError::DeliveryJoin("receiver custody ordering"));
            }
        }

        let deliveries: Vec<_> = self
            .by_schema(RuntimeSchema::ArtifactDeliveryRecordV1)
            .collect();
        let mut successor_counts = BTreeMap::<Sha256Digest, usize>::new();
        let mut roots = BTreeSet::<String>::new();
        for delivery in &deliveries {
            let value = delivery.record().as_value();
            if value["predecessor"] == Value::Null {
                if !matches!(
                    value["state"].as_str(),
                    Some("not_required" | "export_committed")
                ) {
                    return Err(ContractError::DeliveryJoin("delivery root state"));
                }
                let root = serde_json::to_string(&serde_json::json!({
                    "artifact": value["artifact"],
                    "producer_node": value["producer_node"],
                    "destination": value["destination"],
                    "destination_generation": value["destination_generation"],
                    "transport_policy": value["transport_policy"],
                }))?;
                if !roots.insert(root) {
                    return Err(ContractError::DeliveryJoin("delivery chain root fork"));
                }
            } else {
                let predecessor = self.resolve_field(value, "predecessor")?;
                require_schema(predecessor, RuntimeSchema::ArtifactDeliveryRecordV1)?;
                *successor_counts
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if successor_counts[predecessor.record_id()] > 1 {
                    return Err(ContractError::DeliveryJoin("delivery chain fork"));
                }
                for field in [
                    "artifact",
                    "producer_node",
                    "producer_key_generation",
                    "destination",
                    "destination_generation",
                    "transport_policy",
                ] {
                    if value[field] != predecessor.record().as_value()[field] {
                        return Err(ContractError::DeliveryJoin(
                            "delivery transition substitution",
                        ));
                    }
                }
                if !allowed_delivery_transition(
                    predecessor.record().as_value()["state"].as_str(),
                    value["state"].as_str(),
                ) {
                    return Err(ContractError::DeliveryJoin("invalid delivery transition"));
                }
                if timestamp(value, "occurred_at")?
                    < timestamp(predecessor.record().as_value(), "occurred_at")?
                {
                    return Err(ContractError::DeliveryJoin("delivery transition ordering"));
                }
            }
            if value["envelope"] != Value::Null {
                let envelope = self.resolve_field(value, "envelope")?;
                require_schema(envelope, RuntimeSchema::AuthenticatedArtifactEnvelopeV1)?;
                if !artifact_tuple_equal(
                    &value["artifact"],
                    &envelope.record().as_value()["artifact"],
                ) || value["producer_node"] != envelope.record().as_value()["producer_node"]
                    || value["producer_key_generation"]
                        != envelope.record().as_value()["producer_key_generation"]
                    || value["destination"] != envelope.record().as_value()["intended_receiver"]
                    || value["destination_generation"]
                        != envelope.record().as_value()["destination_generation"]
                    || value["transport_policy"] != envelope.record().as_value()["transport_policy"]
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery state substituted envelope",
                    ));
                }
            }
            if value["attempt"] != Value::Null {
                let attempt = self.resolve_field(value, "attempt")?;
                require_schema(attempt, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                if !artifact_tuple_equal(
                    &value["artifact"],
                    &attempt.record().as_value()["artifact"],
                ) || value["envelope"] != attempt.record().as_value()["envelope"]
                    || value["destination"] != attempt.record().as_value()["destination"]
                    || value["destination_generation"]
                        != attempt.record().as_value()["destination_generation"]
                    || value["transport_policy"] != attempt.record().as_value()["transport_policy"]
                    || !delivery_state_accepts_outcome(
                        value["state"].as_str(),
                        attempt.record().as_value()["outcome"].as_str(),
                    )
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery state substituted attempt or outcome",
                    ));
                }
                if value["state"] != "attempt_in_progress"
                    && timestamp(value, "occurred_at")?
                        < timestamp(attempt.record().as_value(), "completed_at")?
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery outcome precedes attempt completion",
                    ));
                }
                if value["state"] == "retry_scheduled"
                    && value["next_attempt_not_before"]
                        != attempt.record().as_value()["next_attempt_not_before"]
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery retry deadline substitution",
                    ));
                }
            }
            if value["receiver_custody_receipt"] != Value::Null {
                let receipt = self.resolve_field(value, "receiver_custody_receipt")?;
                require_schema(receipt, RuntimeSchema::ArtifactCustodyReceiptV1)?;
                if value["state"] != "acknowledged_custody"
                    || value["attempt"] != receipt.record().as_value()["attempt"]
                    || value["envelope"] != receipt.record().as_value()["envelope"]
                    || !artifact_tuple_equal(
                        &value["artifact"],
                        &receipt.record().as_value()["artifact"],
                    )
                {
                    return Err(ContractError::DeliveryJoin(
                        "acknowledged custody borrowed receipt",
                    ));
                }
            }
        }
        Ok(())
    }

    fn exact_record(
        &self,
        reference: &RecordRef,
        schema: RuntimeSchema,
        error: &'static str,
    ) -> Result<&ValidatedRuntimeRecord> {
        let record = self
            .records
            .get(&reference.record_id)
            .ok_or(ContractError::InvocationJoin(error))?;
        if record.exact_reference() != *reference || record.schema() != schema {
            return Err(ContractError::InvocationJoin(error));
        }
        Ok(record)
    }

    fn reject_unreferenced_launch_qualifiers(
        &self,
        referenced: &BTreeSet<RecordRef>,
        cohort: &IdentityRef,
        generation: &str,
    ) -> Result<()> {
        for record in self.records().filter(|record| {
            matches!(
                record.schema(),
                RuntimeSchema::NativeProfileQualificationV1
                    | RuntimeSchema::NativeClockQualificationV1
            )
        }) {
            let value = record.record().as_value();
            let candidate_cohort: IdentityRef = serde_json::from_value(value["cohort"].clone())?;
            if candidate_cohort == *cohort
                && value["cohort_generation"] == generation
                && !referenced.contains(&record.exact_reference())
            {
                return Err(ContractError::InvocationJoin(
                    "launch correspondence qualifier claims cohort without exact cohort reference",
                ));
            }
        }
        Ok(())
    }

    fn launch_subject_platform(&self, activation: &Value, request: &Value) -> Result<IdentityRef> {
        let relation_reference: RecordRef =
            serde_json::from_value(activation["relations"]["subject_platform"].clone())?;
        let relation = self.exact_record(
            &relation_reference,
            RuntimeSchema::HostRoleRelationV1,
            "launch correspondence subject-platform relation absent or substituted",
        )?;
        let value = relation.record().as_value();
        if value["relation_kind"] != "subject_platform"
            || value["left"] != request["target"]["subject"]
        {
            return Err(ContractError::InvocationJoin(
                "launch correspondence subject-platform relation",
            ));
        }
        serde_json::from_value(value["right"].clone()).map_err(ContractError::from)
    }

    fn by_schema(&self, schema: RuntimeSchema) -> impl Iterator<Item = &ValidatedRuntimeRecord> {
        self.records()
            .filter(move |record| record.schema() == schema)
    }

    fn resolve_field<'a>(
        &'a self,
        value: &Value,
        field: &'static str,
    ) -> Result<&'a ValidatedRuntimeRecord> {
        self.resolve_value(
            value
                .get(field)
                .ok_or(ContractError::TopologyJoin("missing reference field"))?,
        )
    }

    fn resolve_value(&self, value: &Value) -> Result<&ValidatedRuntimeRecord> {
        let reference: RecordRef = serde_json::from_value(value.clone())?;
        let target = self.records.get(&reference.record_id).ok_or_else(|| {
            ContractError::UnresolvedRecordReference(reference.record_id.to_string())
        })?;
        if target.schema().as_str() != reference.schema.as_str()
            || target.bytes_digest() != &reference.bytes_digest
        {
            return Err(ContractError::RecordReferenceSubstitution);
        }
        Ok(target)
    }
}

/// Computes the non-cyclic semantic body committed by native qualifiers.
///
/// The domain separator is not a cohort field. The body includes every
/// verdict-relevant cohort field and excludes only the record envelope
/// (`schema`, `manifest_id`) plus `qualification_records`, whose exact
/// qualifier references would otherwise create a circular byte commitment.
fn static_cohort_semantics_digest(cohort: &Value) -> Result<Sha256Digest> {
    let object = cohort.as_object().ok_or(ContractError::InvocationJoin(
        "launch correspondence cohort semantic body",
    ))?;
    let mut body = Map::new();
    body.insert(
        "semantic_schema".to_owned(),
        Value::String("nq.static_profile_cohort_semantics.v1".to_owned()),
    );
    for field in [
        "namespace",
        "cohort",
        "generation",
        "effective_interval",
        "members",
        "compatible_builds",
        "protocol_store_compatibility",
        "nonclaims",
    ] {
        body.insert(
            field.to_owned(),
            object
                .get(field)
                .cloned()
                .ok_or(ContractError::InvocationJoin(
                    "launch correspondence cohort semantic field absent",
                ))?,
        );
    }
    semantic_digest(&Value::Object(body)).map_err(ContractError::from)
}

fn require_qualifier_cohort(
    qualification: &Value,
    cohort_value: &Value,
    cohort: &IdentityRef,
    generation: &str,
    semantics_digest: &Sha256Digest,
    error: &'static str,
) -> Result<()> {
    let claimed_cohort: IdentityRef = serde_json::from_value(qualification["cohort"].clone())?;
    let claimed_digest: Sha256Digest =
        serde_json::from_value(qualification["cohort_semantics_digest"].clone())?;
    if claimed_cohort != *cohort
        || qualification["cohort_generation"] != generation
        || claimed_digest != *semantics_digest
        || qualification["namespace"] != cohort_value["namespace"]
    {
        return Err(ContractError::InvocationJoin(error));
    }
    Ok(())
}

fn identity_occurrences(root: &Value, path: &[&str], expected: &IdentityRef) -> Result<usize> {
    let mut current = root;
    for segment in path {
        current = current.get(*segment).ok_or(ContractError::InvocationJoin(
            "launch correspondence identity set absent",
        ))?;
    }
    let entries = current.as_array().ok_or(ContractError::InvocationJoin(
        "launch correspondence identity set malformed",
    ))?;
    entries
        .iter()
        .map(|value| {
            serde_json::from_value::<IdentityRef>(value.clone())
                .map(|identity| usize::from(identity == *expected))
                .map_err(ContractError::from)
        })
        .sum()
}

fn administrative_authority_field(schema: RuntimeSchema) -> Option<&'static str> {
    match schema {
        RuntimeSchema::NodeEnrollmentV1 => Some("enrollment_authorization"),
        RuntimeSchema::RuntimeActivationV1 => Some("activation_authorization"),
        RuntimeSchema::WitnessAttachmentV1 => Some("attachment_authorization"),
        RuntimeSchema::HostRoleRelationV1
        | RuntimeSchema::HostRoleLifecycleEventV1
        | RuntimeSchema::WitnessLifecycleEventV1
        | RuntimeSchema::NodeKeyLifecycleEventV1
        | RuntimeSchema::RestoreActivationProofV1
        | RuntimeSchema::DecommissionCutV1 => Some("administrative_authorization"),
        _ => None,
    }
}

fn administrative_neutral_digest(
    records: &RuntimeRecordSet,
    consumers: &BTreeMap<(String, Sha256Digest), &ValidatedRuntimeRecord>,
    key: &(String, Sha256Digest),
    memo: &mut BTreeMap<(String, Sha256Digest), Sha256Digest>,
    visiting: &mut BTreeSet<(String, Sha256Digest)>,
) -> Result<Sha256Digest> {
    if let Some(digest) = memo.get(key) {
        return Ok(digest.clone());
    }
    if !visiting.insert(key.clone()) {
        return Err(ContractError::AuthorizationJoin(
            "administrative authority-neutral dependency cycle",
        ));
    }
    let record = consumers.get(key).ok_or(ContractError::AuthorizationJoin(
        "administrative consumer absent",
    ))?;
    let authority_field = administrative_authority_field(record.schema()).ok_or(
        ContractError::AuthorizationJoin("administrative consumer field absent"),
    )?;
    let mut preimage = record
        .record()
        .as_value()
        .as_object()
        .ok_or(ContractError::AuthorizationJoin(
            "administrative consumer must be an object",
        ))?
        .clone();
    preimage.remove(authority_field);
    let preimage = neutralize_administrative_references(
        records,
        consumers,
        Value::Object(preimage),
        memo,
        visiting,
    )?;
    let digest = semantic_digest(&preimage)?;
    visiting.remove(key);
    memo.insert(key.clone(), digest.clone());
    Ok(digest)
}

fn neutralize_administrative_references(
    records: &RuntimeRecordSet,
    consumers: &BTreeMap<(String, Sha256Digest), &ValidatedRuntimeRecord>,
    value: Value,
    memo: &mut BTreeMap<(String, Sha256Digest), Sha256Digest>,
    visiting: &mut BTreeSet<(String, Sha256Digest)>,
) -> Result<Value> {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
        {
            let reference: RecordRef = serde_json::from_value(Value::Object(object.clone()))?;
            if let Some(target) = records.get(&reference.record_id) {
                if administrative_authority_field(target.schema()).is_some() {
                    let key = (
                        target.schema().as_str().to_owned(),
                        target.record_id().clone(),
                    );
                    let digest =
                        administrative_neutral_digest(records, consumers, &key, memo, visiting)?;
                    return Ok(serde_json::json!({
                        "schema": target.schema().as_str(),
                        "record_id": target.record_id(),
                        "record_preimage_digest": digest,
                    }));
                }
            } else if RuntimeSchema::parse(reference.schema.as_str())
                .ok()
                .is_some_and(|schema| administrative_authority_field(schema).is_some())
            {
                return Err(ContractError::AuthorizationJoin(
                    "external administrative consumer cannot close a local grant",
                ));
            }
            Ok(Value::Object(object))
        }
        Value::Object(object) => Ok(Value::Object(
            object
                .into_iter()
                .map(|(key, child)| {
                    neutralize_administrative_references(records, consumers, child, memo, visiting)
                        .map(|child| (key, child))
                })
                .collect::<Result<Map<_, _>>>()?,
        )),
        Value::Array(array) => Ok(Value::Array(
            array
                .into_iter()
                .map(|child| {
                    neutralize_administrative_references(records, consumers, child, memo, visiting)
                })
                .collect::<Result<Vec<_>>>()?,
        )),
        primitive => Ok(primitive),
    }
}

fn consumer_occurrence_time(record: &ValidatedRuntimeRecord) -> Result<&str> {
    let value = record.record().as_value();
    let field = match record.schema() {
        RuntimeSchema::NodeEnrollmentV1 => "enrolled_at",
        RuntimeSchema::RuntimeActivationV1
        | RuntimeSchema::WitnessAttachmentV1
        | RuntimeSchema::HostRoleRelationV1 => {
            return value["effective_interval"]["effective_from"]
                .as_str()
                .ok_or(ContractError::AuthorizationJoin(
                    "administrative effective interval",
                ));
        }
        RuntimeSchema::HostRoleLifecycleEventV1
        | RuntimeSchema::WitnessLifecycleEventV1
        | RuntimeSchema::NodeKeyLifecycleEventV1 => "occurred_at",
        RuntimeSchema::RestoreActivationProofV1 => "decided_at",
        RuntimeSchema::DecommissionCutV1 => "effective_at",
        _ => {
            return Err(ContractError::AuthorizationJoin(
                "administrative occurrence time law absent",
            ));
        }
    };
    value[field]
        .as_str()
        .ok_or(ContractError::AuthorizationJoin(
            "administrative occurrence time absent",
        ))
}

fn interval_bounds(
    value: &Value,
) -> Result<(
    chrono::DateTime<chrono::FixedOffset>,
    Option<chrono::DateTime<chrono::FixedOffset>>,
)> {
    let start = value["effective_from"]
        .as_str()
        .ok_or(ContractError::TopologyJoin("interval start absent"))?;
    let end = value
        .get("effective_until")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or(ContractError::TopologyJoin("interval end malformed"))
                .and_then(|value| Ok(Timestamp::parse(value.to_owned())?.instant()))
        })
        .transpose()?;
    Ok((Timestamp::parse(start.to_owned())?.instant(), end))
}

fn interval_covers(outer: &Value, inner: &Value) -> Result<bool> {
    let (outer_start, outer_end) = interval_bounds(outer)?;
    let (inner_start, inner_end) = interval_bounds(inner)?;
    Ok(outer_start <= inner_start
        && match (outer_end, inner_end) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(outer), Some(inner)) => outer >= inner,
        })
}

fn intervals_overlap(left: &Value, right: &Value) -> Result<bool> {
    let (left_start, left_end) = interval_bounds(left)?;
    let (right_start, right_end) = interval_bounds(right)?;
    Ok(
        left_end.is_none_or(|end| right_start < end)
            && right_end.is_none_or(|end| left_start < end),
    )
}

fn interval_contains_attempt(
    interval: &Value,
    start: chrono::DateTime<chrono::FixedOffset>,
    deadline: chrono::DateTime<chrono::FixedOffset>,
) -> Result<bool> {
    let (effective_from, effective_until) = interval_bounds(interval)?;
    Ok(effective_from <= start && effective_until.is_none_or(|end| deadline <= end))
}

fn operation_matches_consumer(operation: &str, consumer: &Value) -> Result<bool> {
    Ok(match consumer["schema"].as_str() {
        Some("nq.node_enrollment.v1") => operation == "enroll",
        Some("nq.witness_attachment.v1") => operation == "admit_witness",
        Some("nq.host_role_relation.v1") => match consumer["relation_kind"].as_str() {
            Some("node_subject") => operation == "enroll",
            Some("subject_platform" | "node_vantage") => {
                matches!(operation, "enroll" | "rehome")
            }
            Some("node_role") => matches!(operation, "enroll" | "change_role"),
            Some("node_static_profile_cohort") => {
                matches!(operation, "enroll" | "change_static_profile_cohort")
            }
            _ => false,
        },
        Some("nq.runtime_activation.v1") => matches!(
            operation,
            "activate_node"
                | "rekey"
                | "rehome"
                | "change_role"
                | "change_static_profile_cohort"
                | "complete_restore"
        ),
        Some("nq.host_role_lifecycle_event.v1") => {
            let mapped = match consumer["operation"].as_str() {
                Some("activate") => "activate_node",
                Some(value) => value,
                None => return Err(ContractError::AuthorizationJoin("host operation absent")),
            };
            operation == mapped
        }
        Some("nq.witness_lifecycle_event.v1") => {
            let mapped = match consumer["operation"].as_str() {
                Some("activate") => "activate_witness",
                Some(value) => value,
                None => {
                    return Err(ContractError::AuthorizationJoin("witness operation absent"));
                }
            };
            operation == mapped
        }
        Some("nq.node_key_lifecycle_event.v1") => match consumer["operation"].as_str() {
            Some("activate") => matches!(operation, "activate_key" | "rekey" | "complete_restore"),
            Some("supersede" | "revoke") => operation == "rekey",
            _ => false,
        },
        Some("nq.restore_activation_proof.v1") => {
            matches!(operation, "begin_restore" | "complete_restore")
        }
        Some("nq.decommission_cut.v1") => {
            operation
                == if consumer["result_state"] == "decommissioned" {
                    "complete_decommission"
                } else {
                    "begin_decommission"
                }
        }
        _ => false,
    })
}

fn administrative_shape(operation: &str, consumers: &[&ValidatedRuntimeRecord]) -> Result<bool> {
    let expected = expected_administrative_shape(operation)?;
    let mut actual = BTreeMap::<&str, usize>::new();
    for consumer in consumers {
        *actual.entry(consumer.schema().as_str()).or_default() += 1;
    }
    Ok(expected
        .iter()
        .all(|(schema, count)| actual.get(schema) == Some(count))
        && actual.len() == expected.len())
}

fn expected_administrative_shape(operation: &str) -> Result<&'static [(&'static str, usize)]> {
    Ok(match operation {
        "bootstrap" => &[("nq.host_role_lifecycle_event.v1", 1)],
        "enroll" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.host_role_relation.v1", 5),
            ("nq.node_enrollment.v1", 1),
        ],
        "admit_witness" => &[("nq.witness_attachment.v1", 1)],
        "activate_witness" | "suspend_witness" | "resume_witness" | "retire_witness" => {
            &[("nq.witness_lifecycle_event.v1", 1)]
        }
        "activate_key" => &[("nq.node_key_lifecycle_event.v1", 1)],
        "activate_node" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.runtime_activation.v1", 1),
        ],
        "rekey" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.node_key_lifecycle_event.v1", 2),
            ("nq.runtime_activation.v1", 1),
        ],
        "rehome" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.host_role_relation.v1", 2),
            ("nq.runtime_activation.v1", 1),
        ],
        "change_role" | "change_static_profile_cohort" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.host_role_relation.v1", 1),
            ("nq.runtime_activation.v1", 1),
        ],
        // The first restore decision is the quarantine/eligibility proof
        // itself. Completion is the closed topology mutation it authorizes.
        "begin_restore" => &[("nq.restore_activation_proof.v1", 1)],
        "complete_restore" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.node_key_lifecycle_event.v1", 1),
            ("nq.restore_activation_proof.v1", 1),
            ("nq.runtime_activation.v1", 1),
        ],
        "begin_decommission" | "complete_decommission" => &[
            ("nq.decommission_cut.v1", 1),
            ("nq.host_role_lifecycle_event.v1", 1),
        ],
        _ => {
            return Err(ContractError::AuthorizationJoin(
                "operation has no exact administrative record-shape law",
            ));
        }
    })
}

fn visit_reference_dag(
    node: &Sha256Digest,
    edges: &BTreeMap<Sha256Digest, BTreeSet<Sha256Digest>>,
    visiting: &mut BTreeSet<Sha256Digest>,
    visited: &mut BTreeSet<Sha256Digest>,
) -> Result<()> {
    if visiting.contains(node) {
        return Err(ContractError::RecordReferenceCycle);
    }
    if visited.contains(node) {
        return Ok(());
    }
    visiting.insert(node.clone());
    if let Some(children) = edges.get(node) {
        for child in children {
            visit_reference_dag(child, edges, visiting, visited)?;
        }
    }
    visiting.remove(node);
    visited.insert(node.clone());
    Ok(())
}

fn artifact_tuple_equal(left: &Value, right: &Value) -> bool {
    ["schema", "artifact_id", "file_bytes_digest", "byte_length"]
        .iter()
        .all(|field| {
            left.get(*field)
                .zip(right.get(*field))
                .is_none_or(|(left, right)| left == right)
        })
        && ["schema", "artifact_id", "file_bytes_digest"]
            .iter()
            .all(|field| left.get(*field) == right.get(*field))
}

fn collect_carriers(
    value: &Value,
    identities: &mut Vec<IdentityRef>,
    references: &mut Vec<RecordRef>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
            if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                identities.push(serde_json::from_value(value.clone())?);
                return Ok(());
            }
            if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                references.push(serde_json::from_value(value.clone())?);
                return Ok(());
            }
            for child in object.values() {
                collect_carriers(child, identities, references)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_carriers(child, identities, references)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn require_schema(record: &ValidatedRuntimeRecord, expected: RuntimeSchema) -> Result<()> {
    if record.schema() != expected {
        return Err(ContractError::RecordReferenceSubstitution);
    }
    Ok(())
}

fn validate_resolved_binding_source(
    slot: &str,
    resolved: &Map<String, Value>,
    expected_source: &ValidatedRuntimeRecord,
    expected_pointer: &str,
    sources: &ExecutionBindingSourceCorpus,
    consumed: &mut BTreeSet<RecordRef>,
) -> Result<()> {
    let entry = resolved[slot]
        .as_object()
        .ok_or(ContractError::ExpectedObject("resolved_references[]"))?;
    let source_reference: RecordRef = serde_json::from_value(entry["source_artifact"].clone())?;
    let source_pointer = entry["source_pointer"]
        .as_str()
        .ok_or(ContractError::ExpectedString("source_pointer"))?;
    if source_reference != expected_source.exact_reference() || source_pointer != expected_pointer {
        return Err(ContractError::BindingSourceJoin(slot.to_owned()));
    }
    let source = sources.resolve(&source_reference)?;
    consumed.insert(source_reference);
    if source.canonical_bytes != expected_source.canonical_bytes() {
        return Err(ContractError::BindingSourceReferenceSubstitution);
    }
    let pointed = resolve_pointer(&source.value, source_pointer)?;
    let pointed_identity: IdentityRef = serde_json::from_value(pointed.clone())
        .map_err(|_| ContractError::BindingSourceIdentityMismatch(slot.to_owned()))?;
    let claimed_identity: IdentityRef = serde_json::from_value(entry["identity"].clone())?;
    if pointed_identity != claimed_identity {
        return Err(ContractError::BindingSourceIdentityMismatch(
            slot.to_owned(),
        ));
    }

    let descriptor_reference: RecordRef = serde_json::from_value(entry["descriptor"].clone())?;
    let descriptor = sources.resolve(&descriptor_reference)?;
    consumed.insert(descriptor_reference.clone());
    if claimed_identity.descriptor_digest != descriptor_reference.bytes_digest {
        return Err(ContractError::BindingDescriptorDigestMismatch(
            slot.to_owned(),
        ));
    }
    validate_identity_descriptor(slot, &claimed_identity, descriptor)
}

fn validate_unreferenced_identity_descriptor(
    slot: &str,
    identity: &IdentityRef,
    sources: &ExecutionBindingSourceCorpus,
    consumed: &mut BTreeSet<RecordRef>,
) -> Result<()> {
    let candidates = sources
        .sources
        .values()
        .filter(|source| source.reference.bytes_digest == identity.descriptor_digest)
        .collect::<Vec<_>>();
    let [descriptor] = candidates.as_slice() else {
        return if candidates.is_empty() {
            Err(ContractError::UnresolvedBindingSource(
                identity.descriptor_digest.to_string(),
            ))
        } else {
            Err(ContractError::DuplicateBindingSource)
        };
    };
    consumed.insert(descriptor.reference.clone());
    validate_identity_descriptor(slot, identity, descriptor)
}

fn validate_identity_descriptor(
    slot: &str,
    identity: &IdentityRef,
    descriptor: &CanonicalBindingSource,
) -> Result<()> {
    if !matches!(
        descriptor.reference.schema.as_str(),
        PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA | CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA
    ) {
        return Err(ContractError::BindingDescriptorPreimageMismatch(
            slot.to_owned(),
        ));
    }
    let descriptor_object = descriptor
        .value
        .as_object()
        .ok_or_else(|| ContractError::BindingDescriptorPreimageMismatch(slot.to_owned()))?;
    let exact_fields = descriptor_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if exact_fields != BTreeSet::from(["schema", "kind", "id", "version"]) {
        return Err(ContractError::BindingDescriptorPreimageMismatch(
            slot.to_owned(),
        ));
    }
    let identity_value = serde_json::to_value(identity)?;
    if ["kind", "id", "version"]
        .into_iter()
        .any(|field| descriptor_object.get(field) != identity_value.get(field))
    {
        return Err(ContractError::BindingDescriptorPreimageMismatch(
            slot.to_owned(),
        ));
    }
    Ok(())
}

fn host_lifecycle_predecessor(record: &ValidatedRuntimeRecord) -> Result<Option<RecordRef>> {
    let predecessors = record.record().as_value()["predecessor_events"]
        .as_array()
        .ok_or(ContractError::LifecycleJoin(
            "host lifecycle predecessor set",
        ))?;
    match predecessors.as_slice() {
        [] => Ok(None),
        [predecessor] => Ok(Some(serde_json::from_value(predecessor.clone())?)),
        _ => Err(ContractError::LifecycleJoin(
            "host lifecycle predecessor multiplicity",
        )),
    }
}

fn nullable_lifecycle_predecessor(record: &ValidatedRuntimeRecord) -> Result<Option<RecordRef>> {
    let value = &record.record().as_value()["predecessor_event"];
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(serde_json::from_value(value.clone())?))
    }
}

fn exact_lifecycle_chain<'a, F>(
    records: Vec<&'a ValidatedRuntimeRecord>,
    predecessor: F,
    root_error: &'static str,
    disconnected_error: &'static str,
    fork_error: &'static str,
) -> Result<Vec<&'a ValidatedRuntimeRecord>>
where
    F: Fn(&ValidatedRuntimeRecord) -> Result<Option<RecordRef>>,
{
    if records.is_empty() {
        return Err(ContractError::LifecycleJoin(root_error));
    }
    let by_id = records
        .iter()
        .map(|record| (record.record_id().clone(), *record))
        .collect::<BTreeMap<_, _>>();
    let mut roots = Vec::new();
    let mut successors = BTreeMap::<Sha256Digest, Sha256Digest>::new();
    for record in records {
        let Some(predecessor) = predecessor(record)? else {
            roots.push(record.record_id().clone());
            continue;
        };
        let predecessor_record = by_id
            .get(&predecessor.record_id)
            .ok_or(ContractError::LifecycleJoin(disconnected_error))?;
        if predecessor_record.exact_reference() != predecessor
            || predecessor_record.schema() != record.schema()
            || predecessor_record.record().as_value()["to_state"]
                != record.record().as_value()["from_state"]
            || timestamp(predecessor_record.record().as_value(), "occurred_at")?
                >= timestamp(record.record().as_value(), "occurred_at")?
        {
            return Err(ContractError::LifecycleJoin(disconnected_error));
        }
        if successors
            .insert(predecessor.record_id, record.record_id().clone())
            .is_some()
        {
            return Err(ContractError::LifecycleJoin(fork_error));
        }
    }
    let [root] = roots.as_slice() else {
        return Err(ContractError::LifecycleJoin(root_error));
    };
    let mut chain = Vec::with_capacity(by_id.len());
    let mut visited = BTreeSet::new();
    let mut current = root.clone();
    loop {
        if !visited.insert(current.clone()) {
            return Err(ContractError::LifecycleJoin(disconnected_error));
        }
        let record = by_id
            .get(&current)
            .ok_or(ContractError::LifecycleJoin(disconnected_error))?;
        chain.push(*record);
        let Some(successor) = successors.get(&current) else {
            break;
        };
        current.clone_from(successor);
    }
    if visited.len() != by_id.len() {
        return Err(ContractError::LifecycleJoin(disconnected_error));
    }
    Ok(chain)
}

fn applicable_chain_head<'a>(
    chain: &[&'a ValidatedRuntimeRecord],
    at: chrono::DateTime<chrono::FixedOffset>,
) -> Option<&'a ValidatedRuntimeRecord> {
    chain
        .iter()
        .rev()
        .find(|record| {
            timestamp(record.record().as_value(), "occurred_at")
                .is_ok_and(|occurred_at| occurred_at <= at)
        })
        .copied()
}

fn record_array_contains(
    value: &Value,
    field: &'static str,
    reference: &RecordRef,
) -> Result<bool> {
    let items = value[field]
        .as_array()
        .ok_or(ContractError::LifecycleJoin("lifecycle result-record set"))?;
    Ok(items.contains(&Value::from(reference.clone())))
}

fn require_reference_equal(
    source: &Value,
    field: &'static str,
    target: &ValidatedRuntimeRecord,
    context: &'static str,
) -> Result<()> {
    if source[field] != Value::from(target.exact_reference()) {
        return Err(ContractError::TopologyJoin(context));
    }
    Ok(())
}

fn require_equal(
    left: &Value,
    left_field: &'static str,
    right: &Value,
    right_field: &'static str,
    context: &'static str,
) -> Result<()> {
    if left[left_field] != right[right_field] {
        return Err(ContractError::TopologyJoin(context));
    }
    Ok(())
}

fn timestamp(value: &Value, field: &'static str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    let text = value[field]
        .as_str()
        .ok_or(ContractError::ExpectedString(field))?;
    Ok(Timestamp::parse(text.to_owned())?.instant())
}

fn validate_relation_endpoints(activation: &Value, relation: &Value) -> Result<()> {
    let kind = relation["relation_kind"]
        .as_str()
        .ok_or(ContractError::TopologyJoin("relation kind"))?;
    let node = &activation["node"];
    match kind {
        "node_subject" | "node_vantage" | "node_role" | "node_static_profile_cohort"
            if relation["left"] != *node =>
        {
            Err(ContractError::TopologyJoin("relation node endpoint"))
        }
        "node_role" if relation["right"] != activation["role"] => {
            Err(ContractError::TopologyJoin("relation role endpoint"))
        }
        "node_static_profile_cohort"
            if relation["right"] != activation["static_profile_cohort"] =>
        {
            Err(ContractError::TopologyJoin("relation cohort endpoint"))
        }
        _ => Ok(()),
    }
}

fn validate_witness_slot(attachment: &Value, role: &Value) -> Result<()> {
    let slot_id = attachment["role_slot"]
        .as_str()
        .ok_or(ContractError::WitnessSlotJoin("slot identity"))?;
    let slots = role["witness_slots"]
        .as_array()
        .ok_or(ContractError::WitnessSlotJoin("role slots"))?;
    let slot = slots
        .iter()
        .find(|slot| slot["slot_id"].as_str() == Some(slot_id))
        .ok_or(ContractError::WitnessSlotJoin("unknown role slot"))?;
    if attachment["witness_class"] != slot["witness_class"] {
        return Err(ContractError::WitnessSlotJoin("witness class"));
    }
    for (attachment_field, ceiling_field) in [
        ("privileges", "privilege_ceiling"),
        ("namespaces", "namespace_ceiling"),
        ("supported_profiles", "supported_profiles"),
    ] {
        let ceiling = slot[ceiling_field]
            .as_array()
            .ok_or(ContractError::WitnessSlotJoin("role slot ceiling"))?;
        let members = attachment[attachment_field]
            .as_array()
            .ok_or(ContractError::WitnessSlotJoin("attachment members"))?;
        if members.iter().any(|member| !ceiling.contains(member)) {
            return Err(ContractError::WitnessSlotJoin(attachment_field));
        }
    }
    Ok(())
}

fn allowed_delivery_transition(predecessor: Option<&str>, successor: Option<&str>) -> bool {
    matches!(
        (predecessor, successor),
        (
            Some("export_committed"),
            Some("queued" | "blocked_backpressure" | "committed_unavailable")
        ) | (
            Some("queued"),
            Some("attempt_in_progress" | "blocked_backpressure" | "committed_unavailable")
        ) | (
            Some("attempt_in_progress"),
            Some(
                "retry_scheduled"
                    | "delivery_ambiguous"
                    | "acknowledged_custody"
                    | "terminal_rejected"
                    | "attempts_exhausted"
                    | "committed_unavailable"
            )
        ) | (
            Some("retry_scheduled"),
            Some("attempt_in_progress" | "attempts_exhausted" | "committed_unavailable")
        ) | (
            Some("delivery_ambiguous"),
            Some(
                "attempt_in_progress"
                    | "acknowledged_custody"
                    | "attempts_exhausted"
                    | "committed_unavailable"
            )
        ) | (
            Some("blocked_backpressure" | "committed_unavailable"),
            Some("queued" | "committed_unavailable")
        )
    )
}

fn delivery_state_accepts_outcome(state: Option<&str>, outcome: Option<&str>) -> bool {
    matches!(
        (state, outcome),
        (Some("attempt_in_progress"), Some("in_progress"))
            | (
                Some("retry_scheduled" | "attempts_exhausted"),
                Some("transport_unavailable" | "transport_timeout" | "receiver_rate_limited")
            )
            | (
                Some("delivery_ambiguous"),
                Some("ambiguous_possible_acceptance" | "transport_completed_receipt_pending")
            )
            | (
                Some("acknowledged_custody"),
                Some("transport_completed_receipt_pending")
            )
            | (Some("terminal_rejected"), Some("terminal_rejected"))
    )
}

impl From<RecordRef> for Value {
    fn from(value: RecordRef) -> Self {
        serde_json::to_value(value).expect("RecordRef is JSON serializable")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
    use serde_json::{Value, json};

    use super::{
        CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA, CanonicalBindingSource,
        ExecutionBindingSourceCorpus, PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA, RuntimeRecordSet,
        collect_carriers, expected_administrative_shape, static_cohort_semantics_digest,
    };
    use crate::{
        ContractError, ExternalRecordCatalog, IdentityCatalog, IdentityRef, RecordRef, Token,
        ValidatedRuntimeRecord, ValidationContext, record::resolve_pointer,
    };

    const RECORDS: &str = include_str!("../assets/host-role-runtime-records.v1.json");
    type DescriptorSources = Vec<(RecordRef, Vec<u8>)>;
    type NamedBindingSourceFixture = (
        RuntimeRecordSet,
        ValidationContext,
        RecordRef,
        ExecutionBindingSourceCorpus,
        RecordRef,
        ExecutionBindingSourceCorpus,
    );

    #[test]
    fn cohort_semantics_digest_covers_every_noncyclic_verdict_field() {
        let cohort = fixture_values()["cohort_manifest"].clone();
        let baseline = static_cohort_semantics_digest(&cohort).expect("baseline semantics");
        let verdict_fields = [
            "namespace",
            "cohort",
            "generation",
            "effective_interval",
            "members",
            "compatible_builds",
            "protocol_store_compatibility",
            "nonclaims",
        ];
        for field in verdict_fields {
            let mut changed = cohort.clone();
            changed[field] = json!({"hostile_replacement": field});
            assert_ne!(
                static_cohort_semantics_digest(&changed).expect("changed semantics"),
                baseline,
                "{field} must remain load-bearing"
            );
        }

        for excluded in ["schema", "manifest_id", "qualification_records"] {
            let mut changed = cohort.clone();
            changed[excluded] = json!({"excluded_envelope_or_cycle": excluded});
            assert_eq!(
                static_cohort_semantics_digest(&changed).expect("excluded field"),
                baseline,
                "{excluded} is deliberately outside the non-cyclic semantic body"
            );
        }
    }

    #[test]
    fn every_ratified_administrative_operation_has_one_exact_shape_law() {
        for operation in [
            "bootstrap",
            "enroll",
            "admit_witness",
            "activate_witness",
            "suspend_witness",
            "resume_witness",
            "retire_witness",
            "activate_key",
            "activate_node",
            "rekey",
            "rehome",
            "change_role",
            "change_static_profile_cohort",
            "begin_restore",
            "complete_restore",
            "begin_decommission",
            "complete_decommission",
        ] {
            assert!(
                !expected_administrative_shape(operation)
                    .expect("ratified operation must have a shape")
                    .is_empty()
            );
        }
        assert!(expected_administrative_shape("invented_operation").is_err());
    }

    #[test]
    fn self_consistent_refused_administrative_grant_cannot_be_consumed() {
        let mut values = fixture_values();
        values
            .get_mut("activate_node_authorization")
            .expect("authorization")["decision"] = json!("refused");
        let authorization =
            ValidatedRuntimeRecord::validate_value(values["activate_node_authorization"].clone())
                .expect("locally valid refused grant");
        let reference = serde_json::to_value(authorization.exact_reference()).expect("reference");
        values.get_mut("activation").expect("activation")["activation_authorization"] =
            reference.clone();
        values.get_mut("lifecycle_event").expect("lifecycle event")["administrative_authorization"] =
            reference;
        let records = record_set(values);
        assert!(matches!(
            records.validate_authorizations(),
            Err(ContractError::AuthorizationJoin(
                "refused administrative authority was consumed"
            ))
        ));
    }

    #[test]
    fn overlapping_activation_and_active_key_intervals_refuse() {
        let mut values = fixture_values();
        let mut activation = values["activation"].clone();
        activation["activation_id"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        values.insert("overlapping_activation".to_owned(), activation);
        let records = record_set(values);
        assert!(matches!(
            records.validate_topology(),
            Err(ContractError::TopologyJoin(
                "node has overlapping effective activation intervals"
            ))
        ));
    }

    #[test]
    fn accepted_invocation_cannot_substitute_administrative_authority() {
        let mut values = fixture_values();
        let administrative =
            ValidatedRuntimeRecord::validate_value(values["activate_node_authorization"].clone())
                .expect("administrative authorization");
        values
            .get_mut("invocation_decision")
            .expect("invocation decision")["invocation_authorization"] =
            serde_json::to_value(administrative.exact_reference()).expect("reference");
        let records = record_set(values);
        assert!(matches!(
            records.validate_invocations(),
            Err(ContractError::InvocationJoin(
                "decision authentication/authorization"
            ))
        ));
    }

    #[test]
    fn acknowledged_delivery_cannot_borrow_an_unreceipted_attempt() {
        let mut values = fixture_values();
        let attempt =
            ValidatedRuntimeRecord::validate_value(values["delivery_attempt_start_record"].clone())
                .expect("attempt start");
        values.get_mut("delivery").expect("delivery")["attempt"] =
            serde_json::to_value(attempt.exact_reference()).expect("reference");
        let records = record_set(values);
        assert!(matches!(
            records.validate_delivery(),
            Err(ContractError::DeliveryJoin(
                "delivery state substituted attempt or outcome"
                    | "acknowledged custody borrowed receipt"
            ))
        ));
    }

    #[test]
    fn derived_3b_source_complete_successor_qualifies_through_full_entry() {
        let (_, records, context, sources) = source_complete_successor();
        records
            .validate_with_execution_binding_sources(&context, &sources)
            .expect("derived 3B successor has exact graph and source correspondence");
    }

    #[test]
    fn named_bindings_use_separate_bounded_corpora_across_topology_change() {
        let (records, context, first_binding, first_sources, second_binding, second_sources) =
            topology_changed_binding_sources();
        records
            .validate_execution_binding_with_sources(&context, &first_binding, &first_sources)
            .expect("first topology binding");
        records
            .validate_execution_binding_with_sources(&context, &second_binding, &second_sources)
            .expect("second topology binding");
        assert_eq!(first_sources.sources.len(), 16);
        assert_eq!(second_sources.sources.len(), 16);
        assert_ne!(
            first_sources.references().collect::<Vec<_>>(),
            second_sources.references().collect::<Vec<_>>()
        );
    }

    #[test]
    fn named_binding_refuses_missing_substituted_and_unused_input() {
        let (records, context, binding, sources, _, _) = topology_changed_binding_sources();
        let binding_record = records.get(&binding.record_id).expect("selected binding");
        let node_source: RecordRef = serde_json::from_value(
            binding_record.record().as_value()["resolved_references"]["node"]["source_artifact"]
                .clone(),
        )
        .expect("node source");
        let mut missing = sources.clone();
        remove_source(&mut missing, &node_source);
        assert!(matches!(
            records.validate_execution_binding_with_sources(&context, &binding, &missing),
            Err(ContractError::UnresolvedBindingSource(_))
        ));

        let mut substituted = binding.clone();
        substituted.bytes_digest = sha256_bytes(b"substituted binding bytes");
        assert!(matches!(
            records.validate_execution_binding_with_sources(&context, &substituted, &sources),
            Err(ContractError::InvocationJoin(
                "selected execution binding absent or substituted"
            ))
        ));

        let mut unused = sources;
        force_unused_binding_source(&mut unused);
        assert!(matches!(
            records.validate_execution_binding_with_sources(&context, &binding, &unused),
            Err(ContractError::UnusedBindingSource(_))
        ));
    }

    #[test]
    fn exact_launch_lifecycle_query_uses_unique_historical_prefixes() {
        let (values, records, context, sources) = source_complete_successor();
        records
            .validate_with_execution_binding_sources(&context, &sources)
            .expect("source-complete graph");
        let launch = ValidatedRuntimeRecord::validate_value(values["execution_launch"].clone())
            .expect("execution launch");
        records
            .require_effective_launch_lifecycle(&launch.exact_reference())
            .expect("unique active node, witness, and key prefixes at launch");
    }

    #[test]
    fn disconnected_witness_root_cannot_mint_launch_activity() {
        let (mut values, _) = source_complete_successor_values();
        let mut disconnected = values["witness_event"].clone();
        disconnected["event_id"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        disconnected["occurred_at"] = json!("2026-07-28T22:00:31Z");
        values.insert("disconnected_witness_root".to_owned(), disconnected);
        let values: BTreeMap<String, Value> = source_qualification_slice(&values)
            .into_iter()
            .chain(std::iter::once((
                "disconnected_witness_root".to_owned(),
                values["disconnected_witness_root"].clone(),
            )))
            .collect();
        let launch = ValidatedRuntimeRecord::validate_value(values["execution_launch"].clone())
            .expect("execution launch");
        let records = record_set(values);
        assert!(matches!(
            records.require_effective_launch_lifecycle(&launch.exact_reference()),
            Err(ContractError::LifecycleJoin("witness lifecycle root"))
        ));
    }

    #[test]
    fn disconnected_key_root_cannot_mint_launch_authority() {
        let (mut values, _) = source_complete_successor_values();
        let mut disconnected = values["key_event"].clone();
        disconnected["event_id"] =
            json!("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        disconnected["occurred_at"] = json!("2026-07-28T22:00:01Z");
        values.insert("disconnected_key_root".to_owned(), disconnected);
        let values: BTreeMap<String, Value> = source_qualification_slice(&values)
            .into_iter()
            .chain(std::iter::once((
                "disconnected_key_root".to_owned(),
                values["disconnected_key_root"].clone(),
            )))
            .collect();
        let launch = ValidatedRuntimeRecord::validate_value(values["execution_launch"].clone())
            .expect("execution launch");
        let records = record_set(values);
        assert!(matches!(
            records.require_effective_launch_lifecycle(&launch.exact_reference()),
            Err(ContractError::LifecycleJoin("key lifecycle root"))
        ));
    }

    #[test]
    fn source_valid_global_graph_invalid_refuses_at_full_entry() {
        let (mut values, descriptors) = source_complete_successor_values();
        binding_mut(&mut values)["diagnostic"]["request_id"] = json!("substituted-request");
        let values = source_qualification_slice(&values);
        let records = record_set(values.clone());
        let context = validation_context(&records);
        let sources = source_corpus_from_materialized(&values, descriptors);
        records
            .validate_execution_binding_sources(&sources)
            .expect("source correspondence remains exact");
        assert!(matches!(
            records.validate_with_execution_binding_sources(&context, &sources),
            Err(ContractError::TopologyJoin(
                "binding relation/request closure"
            ))
        ));
    }

    #[test]
    fn frozen_3a_structural_specimen_does_not_earn_exact_source_qualification() {
        let values = fixture_values();
        let records = record_set(values.clone());
        let context = validation_context(&records);
        let sources = runtime_binding_sources(&values);
        assert!(records.validate(&context).is_ok());
        assert!(matches!(
            records.validate_with_execution_binding_sources(&context, &sources),
            Err(ContractError::UnresolvedBindingSource(_))
        ));

        // The exact identity descriptor preimage cannot be relabelled with the
        // frozen structural specimen's unrelated external descriptor reference.
        let node = &values["execution_binding"]["resolved_references"]["node"];
        let descriptor = identity_descriptor_bytes(&node["identity"]);
        let frozen_reference: RecordRef =
            serde_json::from_value(node["descriptor"].clone()).expect("frozen descriptor ref");
        let mut attempted = ExecutionBindingSourceCorpus::new();
        assert!(matches!(
            attempted.insert_canonical(frozen_reference, descriptor),
            Err(ContractError::BindingSourceReferenceSubstitution)
        ));
    }

    #[test]
    fn execution_binding_source_corpus_refuses_unclosed_and_missing_inputs() {
        let (values, records, context, mut missing_source) = source_complete_successor();
        let node_source: RecordRef = serde_json::from_value(
            values["execution_binding"]["resolved_references"]["node"]["source_artifact"].clone(),
        )
        .expect("node source");
        remove_source(&mut missing_source, &node_source);
        assert!(matches!(
            records.validate_with_execution_binding_sources(&context, &missing_source),
            Err(ContractError::UnresolvedBindingSource(_))
        ));

        let (_, records, context, mut missing_descriptor) = source_complete_successor();
        let node_descriptor: RecordRef = serde_json::from_value(
            values["execution_binding"]["resolved_references"]["node"]["descriptor"].clone(),
        )
        .expect("node descriptor");
        remove_source(&mut missing_descriptor, &node_descriptor);
        assert!(matches!(
            records.validate_with_execution_binding_sources(&context, &missing_descriptor),
            Err(ContractError::UnresolvedBindingSource(_))
        ));

        let (values, records, context, mut missing_resolver_descriptor) =
            source_complete_successor();
        let resolver: IdentityRef =
            serde_json::from_value(values["execution_binding"]["resolver"].clone())
                .expect("resolver identity");
        let resolver_descriptor = missing_resolver_descriptor
            .sources
            .values()
            .find(|source| source.reference.bytes_digest == resolver.descriptor_digest)
            .expect("resolver descriptor source")
            .reference
            .clone();
        remove_source(&mut missing_resolver_descriptor, &resolver_descriptor);
        assert!(matches!(
            records.validate_with_execution_binding_sources(&context, &missing_resolver_descriptor),
            Err(ContractError::UnresolvedBindingSource(_))
        ));

        let records = RuntimeRecordSet::new();
        let context = ValidationContext::default();
        let mut unused = ExecutionBindingSourceCorpus::new();
        let bytes = canonical_json_bytes(&json!({
            "schema": PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": "subject",
            "id": "lab/unused",
            "version": "1",
        }))
        .expect("unused canonical source");
        let digest = sha256_bytes(&bytes);
        unused
            .insert_canonical(
                RecordRef {
                    schema: Token::parse(PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA)
                        .expect("source schema"),
                    record_id: digest.clone(),
                    bytes_digest: digest,
                },
                bytes,
            )
            .expect("bounded unused entry");
        assert!(matches!(
            records.validate_with_execution_binding_sources(&context, &unused),
            Err(ContractError::UnusedBindingSource(_))
        ));
    }

    #[test]
    fn execution_binding_source_corpus_refuses_carrier_substitution() {
        let noncanonical = br#"{"schema": "nq.test_source.v1"}"#.to_vec();
        let noncanonical_digest = sha256_bytes(&noncanonical);
        let mut corpus = ExecutionBindingSourceCorpus::new();
        assert!(matches!(
            corpus.insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.test_source.v1").expect("source schema"),
                    record_id: noncanonical_digest.clone(),
                    bytes_digest: noncanonical_digest,
                },
                noncanonical,
            ),
            Err(ContractError::NonCanonicalBindingSource)
        ));

        let canonical =
            canonical_json_bytes(&json!({"schema": "nq.test_source.v1"})).expect("canonical");
        let canonical_digest = sha256_bytes(&canonical);
        assert!(matches!(
            corpus.insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.other_source.v1").expect("substituted schema"),
                    record_id: canonical_digest.clone(),
                    bytes_digest: canonical_digest.clone(),
                },
                canonical.clone(),
            ),
            Err(ContractError::BindingSourceReferenceSubstitution)
        ));
        assert!(matches!(
            corpus.insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.test_source.v1").expect("source schema"),
                    record_id: canonical_digest.clone(),
                    bytes_digest: Sha256Digest::parse(
                        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    )
                    .expect("hostile digest"),
                },
                canonical.clone(),
            ),
            Err(ContractError::BindingSourceReferenceSubstitution)
        ));

        let stable_id = Sha256Digest::parse(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("stable source identity");
        corpus
            .insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.test_source.v1").expect("source schema"),
                    record_id: stable_id.clone(),
                    bytes_digest: canonical_digest,
                },
                canonical,
            )
            .expect("first exact occurrence");
        let replacement =
            canonical_json_bytes(&json!({"schema": "nq.test_source.v1", "replacement": true}))
                .expect("replacement source");
        assert!(matches!(
            corpus.insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.test_source.v1").expect("source schema"),
                    record_id: stable_id,
                    bytes_digest: sha256_bytes(&replacement),
                },
                replacement,
            ),
            Err(ContractError::BindingSourceReferenceSubstitution)
        ));
    }

    #[test]
    fn execution_binding_source_corpus_enforces_v1_count_and_byte_bounds() {
        let mut counted = ExecutionBindingSourceCorpus::new();
        for index in 0..16 {
            let bytes =
                canonical_json_bytes(&json!({"schema": "nq.test_source.v1", "index": index}))
                    .expect("bounded source");
            let digest = sha256_bytes(&bytes);
            counted
                .insert_canonical(
                    RecordRef {
                        schema: Token::parse("nq.test_source.v1").expect("source schema"),
                        record_id: digest.clone(),
                        bytes_digest: digest,
                    },
                    bytes,
                )
                .expect("within entry limit");
        }
        let overflow = canonical_json_bytes(&json!({"schema": "nq.test_source.v1", "index": 16}))
            .expect("overflow source");
        let overflow_digest = sha256_bytes(&overflow);
        assert!(matches!(
            counted.insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.test_source.v1").expect("source schema"),
                    record_id: overflow_digest.clone(),
                    bytes_digest: overflow_digest,
                },
                overflow,
            ),
            Err(ContractError::BindingSourceCorpusEntryLimit)
        ));

        let oversized = canonical_json_bytes(&json!({
            "schema": "nq.test_source.v1",
            "payload": "x".repeat(131_072),
        }))
        .expect("oversized source");
        let oversized_digest = sha256_bytes(&oversized);
        let mut bytes = ExecutionBindingSourceCorpus::new();
        assert!(matches!(
            bytes.insert_canonical(
                RecordRef {
                    schema: Token::parse("nq.test_source.v1").expect("source schema"),
                    record_id: oversized_digest.clone(),
                    bytes_digest: oversized_digest,
                },
                oversized,
            ),
            Err(ContractError::BindingSourceCorpusByteLimit)
        ));
    }

    #[test]
    fn current_v2_binding_refuses_unused_extra_witness_and_attempt_multiplicity() {
        let (mut witness_values, descriptors) = source_complete_successor_values();
        binding_mut(&mut witness_values)["witness_attachments"]
            .as_array_mut()
            .expect("witness attachments")
            .push(json!({
                "schema": "nq.witness_attachment.v1",
                "record_id": "sha256:abababababababababababababababababababababababababababababababab",
                "bytes_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            }));
        let sources = source_corpus_from_materialized(&witness_values, descriptors);
        let records = record_set(witness_values);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingWitnessMultiplicity)
        ));

        let (mut attempt_values, descriptors) = source_complete_successor_values();
        binding_mut(&mut attempt_values)["provider_attempts"]
            .as_array_mut()
            .expect("provider attempts")
            .push(json!({
                "schema": "nq.external_record.v1",
                "record_id": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "bytes_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            }));
        let sources = source_corpus_from_materialized(&attempt_values, descriptors);
        let records = record_set(attempt_values);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingProviderAttemptMultiplicity)
        ));
    }

    #[test]
    fn execution_binding_source_pointer_and_artifact_substitution_refuse() {
        let mut pointer = fixture_values();
        binding_mut(&mut pointer)["resolved_references"]["node"]["source_pointer"] =
            json!("/resolved/node");
        let (records, sources) = binding_source_fixture(pointer);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingSourceJoin(slot)) if slot == "node"
        ));

        let mut artifact = fixture_values();
        let relation =
            ValidatedRuntimeRecord::validate_value(artifact["node_subject_relation"].clone())
                .expect("node-subject relation");
        binding_mut(&mut artifact)["resolved_references"]["subject"]["source_artifact"] =
            serde_json::to_value(relation.exact_reference()).expect("relation reference");
        binding_mut(&mut artifact)["resolved_references"]["subject"]["source_pointer"] =
            json!("/left");
        let (records, sources) = binding_source_fixture(artifact);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingSourceJoin(slot)) if slot == "subject"
        ));
    }

    #[test]
    fn execution_binding_duplicate_source_pair_and_pointed_identity_refuse() {
        let mut duplicate = fixture_values();
        let activation = ValidatedRuntimeRecord::validate_value(duplicate["activation"].clone())
            .expect("activation");
        binding_mut(&mut duplicate)["resolved_references"]["subject"]["source_artifact"] =
            serde_json::to_value(activation.exact_reference()).expect("activation reference");
        binding_mut(&mut duplicate)["resolved_references"]["subject"]["source_pointer"] =
            json!("/node");
        let (records, sources) = binding_source_fixture(duplicate);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::DuplicateBindingSource)
        ));

        let mut identity = fixture_values();
        binding_mut(&mut identity)["resolved_references"]["node"]["identity"]["id"] =
            json!("lab/substituted-node");
        let (records, sources) = binding_source_fixture(identity);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingSourceIdentityMismatch(slot)) if slot == "node"
        ));
    }

    #[test]
    fn execution_binding_descriptor_reference_and_preimage_are_load_bearing() {
        let mut values = fixture_values();
        let descriptors = materialize_binding_descriptors(&mut values);
        let subject_descriptor =
            values["execution_binding"]["resolved_references"]["subject"]["descriptor"].clone();
        binding_mut(&mut values)["resolved_references"]["node"]["descriptor"] = subject_descriptor;
        let (records, sources) = binding_source_fixture_from_materialized(values, descriptors);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingDescriptorDigestMismatch(slot)) if slot == "node"
        ));
    }

    #[test]
    fn execution_binding_descriptor_relabel_cannot_hide_behind_a_matching_digest() {
        for (field, substitution) in [
            ("kind", json!("subject")),
            ("id", json!("lab/relabelled-node")),
            ("version", json!("2")),
        ] {
            let mut values = fixture_values();
            let mut descriptors = materialize_binding_descriptors(&mut values);
            let old_descriptor: RecordRef = serde_json::from_value(
                values["execution_binding"]["resolved_references"]["node"]["descriptor"].clone(),
            )
            .expect("old node descriptor");
            let mut descriptor = json!({"schema": CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA,
                    "kind": "nq_node", "id": "lab/node-a", "version": "1"});
            descriptor[field] = substitution;
            let descriptor_bytes =
                canonical_json_bytes(&descriptor).expect("hostile descriptor bytes");
            let descriptor_digest = sha256_bytes(&descriptor_bytes);
            let descriptor_reference = RecordRef {
                schema: Token::parse(CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA)
                    .expect("descriptor schema"),
                record_id: descriptor_digest.clone(),
                bytes_digest: descriptor_digest.clone(),
            };
            let binding = binding_mut(&mut values);
            binding["resolved_references"]["node"]["identity"]["descriptor_digest"] =
                Value::String(descriptor_digest.to_string());
            binding["resolved_references"]["node"]["descriptor"] =
                serde_json::to_value(&descriptor_reference).expect("descriptor reference");
            values.get_mut("activation").expect("activation")["node"]["descriptor_digest"] =
                Value::String(descriptor_digest.to_string());
            let activation = ValidatedRuntimeRecord::validate_value(values["activation"].clone())
                .expect("hostile activation");
            let activation_reference =
                serde_json::to_value(activation.exact_reference()).expect("activation reference");
            let binding = binding_mut(&mut values);
            binding["activation"] = activation_reference.clone();
            binding["resolved_references"]["node"]["source_artifact"] = activation_reference;
            descriptors.retain(|(reference, _)| reference != &old_descriptor);
            descriptors.push((descriptor_reference, descriptor_bytes));

            let (records, sources) = binding_source_fixture_from_materialized(values, descriptors);
            assert!(matches!(
                records.validate_execution_binding_sources(&sources),
                Err(ContractError::BindingDescriptorPreimageMismatch(slot)) if slot == "node"
            ));
        }

        let mut values = fixture_values();
        let mut descriptors = materialize_binding_descriptors(&mut values);
        let old_descriptor: RecordRef = serde_json::from_value(
            values["execution_binding"]["resolved_references"]["node"]["descriptor"].clone(),
        )
        .expect("old node descriptor");
        let descriptor = json!({
            "schema": CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": "nq_node",
            "id": "lab/node-a",
            "version": "1",
            "policy": "smuggled",
        });
        let descriptor_bytes = canonical_json_bytes(&descriptor).expect("hostile descriptor bytes");
        let descriptor_digest = sha256_bytes(&descriptor_bytes);
        let descriptor_reference = RecordRef {
            schema: Token::parse(CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA)
                .expect("descriptor schema"),
            record_id: descriptor_digest.clone(),
            bytes_digest: descriptor_digest.clone(),
        };
        let binding = binding_mut(&mut values);
        binding["resolved_references"]["node"]["identity"]["descriptor_digest"] =
            Value::String(descriptor_digest.to_string());
        binding["resolved_references"]["node"]["descriptor"] =
            serde_json::to_value(&descriptor_reference).expect("descriptor reference");
        values.get_mut("activation").expect("activation")["node"]["descriptor_digest"] =
            Value::String(descriptor_digest.to_string());
        let activation = ValidatedRuntimeRecord::validate_value(values["activation"].clone())
            .expect("hostile activation");
        let activation_reference =
            serde_json::to_value(activation.exact_reference()).expect("activation reference");
        let binding = binding_mut(&mut values);
        binding["activation"] = activation_reference.clone();
        binding["resolved_references"]["node"]["source_artifact"] = activation_reference;
        descriptors.retain(|(reference, _)| reference != &old_descriptor);
        descriptors.push((descriptor_reference, descriptor_bytes));
        let (records, sources) = binding_source_fixture_from_materialized(values, descriptors);
        assert!(matches!(
            records.validate_execution_binding_sources(&sources),
            Err(ContractError::BindingDescriptorPreimageMismatch(slot)) if slot == "node"
        ));
    }

    #[test]
    fn json_pointer_resolution_is_exact_rfc6901() {
        let document = json!({
            "a/b": {
                "~key": ["zero", "one"],
            },
        });
        assert_eq!(
            resolve_pointer(&document, "/a~1b/~0key/1").expect("exact pointer"),
            "one"
        );
        assert!(matches!(
            resolve_pointer(&document, "/a~2b"),
            Err(ContractError::InvalidJsonPointer(_))
        ));
        assert!(matches!(
            resolve_pointer(&document, "/a~1b/~0key/01"),
            Err(ContractError::UnresolvedJsonPointer(_))
        ));
        assert!(matches!(
            resolve_pointer(
                &document,
                "/a~1b/~0key/999999999999999999999999999999999999"
            ),
            Err(ContractError::UnresolvedJsonPointer(_))
        ));
        assert!(matches!(
            resolve_pointer(&document, "/a~1b/~"),
            Err(ContractError::InvalidJsonPointer(_))
        ));
    }

    fn fixture_values() -> BTreeMap<String, Value> {
        let fixture: Value = serde_json::from_str(RECORDS).expect("fixture");
        fixture["records"]
            .as_object()
            .expect("records")
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn binding_mut(values: &mut BTreeMap<String, Value>) -> &mut Value {
        values
            .get_mut("execution_binding")
            .expect("execution binding")
    }

    fn binding_source_fixture(
        mut values: BTreeMap<String, Value>,
    ) -> (RuntimeRecordSet, ExecutionBindingSourceCorpus) {
        let descriptors = materialize_binding_descriptors(&mut values);
        binding_source_fixture_from_materialized(values, descriptors)
    }

    fn materialize_binding_descriptors(values: &mut BTreeMap<String, Value>) -> DescriptorSources {
        let slots = [
            "node",
            "subject",
            "platform",
            "vantage",
            "role",
            "static_profile_cohort",
            "witness",
            "diagnostic_profile",
        ];
        let mut descriptors = Vec::new();
        for slot in slots {
            let identity =
                values["execution_binding"]["resolved_references"][slot]["identity"].clone();
            let descriptor = json!({
                "schema": CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA,
                "kind": identity["kind"],
                "id": identity["id"],
                "version": identity["version"],
            });
            let bytes = canonical_json_bytes(&descriptor).expect("descriptor bytes");
            let digest = sha256_bytes(&bytes);
            let reference = RecordRef {
                schema: Token::parse(CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA)
                    .expect("descriptor schema"),
                record_id: digest.clone(),
                bytes_digest: digest,
            };
            binding_mut(values)["resolved_references"][slot]["descriptor"] =
                serde_json::to_value(&reference).expect("descriptor reference");
            descriptors.push((reference, bytes));
        }
        let resolver = values["execution_binding"]["resolver"].clone();
        let resolver_bytes = identity_descriptor_bytes(&resolver);
        let resolver_digest = sha256_bytes(&resolver_bytes);
        binding_mut(values)["resolver"]["descriptor_digest"] =
            Value::String(resolver_digest.to_string());
        descriptors.push((
            RecordRef {
                schema: Token::parse(CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA)
                    .expect("resolver descriptor schema"),
                record_id: resolver_digest.clone(),
                bytes_digest: resolver_digest,
            },
            resolver_bytes,
        ));
        descriptors
    }

    fn binding_source_fixture_from_materialized(
        values: BTreeMap<String, Value>,
        descriptors: DescriptorSources,
    ) -> (RuntimeRecordSet, ExecutionBindingSourceCorpus) {
        let sources = source_corpus_from_materialized(&values, descriptors);
        (record_set(values), sources)
    }

    fn source_corpus_from_materialized(
        values: &BTreeMap<String, Value>,
        descriptors: DescriptorSources,
    ) -> ExecutionBindingSourceCorpus {
        let mut sources = runtime_binding_sources(values);
        for (reference, bytes) in descriptors {
            sources
                .insert_canonical(reference, bytes)
                .expect("descriptor source");
        }
        sources
    }

    fn runtime_binding_sources(values: &BTreeMap<String, Value>) -> ExecutionBindingSourceCorpus {
        let mut sources = ExecutionBindingSourceCorpus::new();
        for name in [
            "activation",
            "node_subject_relation",
            "subject_platform_relation",
            "node_vantage_relation",
            "role_manifest",
            "cohort_manifest",
            "witness_attachment",
        ] {
            let record = ValidatedRuntimeRecord::validate_value(values[name].clone())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            sources.insert_record(&record).expect("runtime source");
        }
        sources
    }

    fn source_complete_successor() -> (
        BTreeMap<String, Value>,
        RuntimeRecordSet,
        ValidationContext,
        ExecutionBindingSourceCorpus,
    ) {
        let (values, descriptors) = source_complete_successor_values();
        let values = source_qualification_slice(&values);
        let records = record_set(values.clone());
        let context = validation_context(&records);
        let sources = source_corpus_from_materialized(&values, descriptors);
        (values, records, context, sources)
    }

    fn source_complete_successor_values() -> (BTreeMap<String, Value>, DescriptorSources) {
        let mut values = fixture_values();
        let descriptors = materialize_binding_descriptors(&mut values);
        (values, descriptors)
    }

    fn source_qualification_slice(values: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
        const RECORDS: [&str; 28] = [
            "activate_key_authorization",
            "activate_node_authorization",
            "activate_witness_authorization",
            "activation",
            "admin_authorization",
            "admit_witness_authorization",
            "bootstrap_authorization",
            "bootstrap_event",
            "buffer_delivery_policy",
            "cohort_manifest",
            "custody_reservation",
            "enroll_event",
            "enrollment",
            "execution_binding",
            "execution_launch",
            "invocation_authorization",
            "invocation_decision",
            "key_event",
            "lifecycle_event",
            "node_cohort_relation",
            "node_role_relation",
            "node_subject_relation",
            "node_vantage_relation",
            "request",
            "role_manifest",
            "subject_platform_relation",
            "witness_attachment",
            "witness_event",
        ];
        RECORDS
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    values
                        .get(name)
                        .unwrap_or_else(|| panic!("missing source-qualification record {name}"))
                        .clone(),
                )
            })
            .collect()
    }

    fn topology_changed_binding_sources() -> NamedBindingSourceFixture {
        let (values, descriptors) = source_complete_successor_values();
        let mut values = source_qualification_slice(&values);
        let first_sources = source_corpus_from_materialized(&values, descriptors);
        let first_binding =
            ValidatedRuntimeRecord::validate_value(values["execution_binding"].clone())
                .expect("first binding")
                .exact_reference();
        let first_resolver: IdentityRef =
            serde_json::from_value(values["execution_binding"]["resolver"].clone())
                .expect("first resolver");
        let first_resolver_source = first_sources
            .sources
            .values()
            .find(|source| source.reference.bytes_digest == first_resolver.descriptor_digest)
            .expect("first resolver source")
            .reference
            .clone();

        let mut second_binding = values["execution_binding"].clone();
        let mut second_resolver = second_binding["resolver"].clone();
        second_resolver["version"] = json!("2");
        let second_resolver_bytes = identity_descriptor_bytes(&second_resolver);
        let second_resolver_digest = sha256_bytes(&second_resolver_bytes);
        second_resolver["descriptor_digest"] = Value::String(second_resolver_digest.to_string());
        second_binding["resolver"] = second_resolver;
        second_binding["diagnostic"]["artifact_id"] =
            Value::String(sha256_bytes(b"second topology artifact").to_string());
        second_binding["diagnostic"]["file_bytes_digest"] =
            Value::String(sha256_bytes(b"second topology artifact bytes").to_string());
        seal_test_semantic_identity(&mut second_binding, "binding_id");
        let second_binding_record =
            ValidatedRuntimeRecord::validate_value(second_binding.clone()).expect("second binding");
        let second_binding_reference = second_binding_record.exact_reference();
        values.insert("execution_binding_generation_2".to_owned(), second_binding);

        let mut second_sources = first_sources.clone();
        remove_source(&mut second_sources, &first_resolver_source);
        second_sources
            .insert_canonical(
                RecordRef {
                    schema: Token::parse(CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA)
                        .expect("second resolver descriptor schema"),
                    record_id: second_resolver_digest.clone(),
                    bytes_digest: second_resolver_digest,
                },
                second_resolver_bytes,
            )
            .expect("second resolver source");

        let records = record_set(values);
        let context = validation_context(&records);
        (
            records,
            context,
            first_binding,
            first_sources,
            second_binding_reference,
            second_sources,
        )
    }

    fn seal_test_semantic_identity(value: &mut Value, field: &str) {
        let object = value.as_object_mut().expect("semantic identity object");
        object.remove(field);
        let identity =
            semantic_digest(&Value::Object(object.clone())).expect("test semantic identity");
        object.insert(field.to_owned(), Value::String(identity.to_string()));
    }

    fn force_unused_binding_source(corpus: &mut ExecutionBindingSourceCorpus) {
        let bytes = canonical_json_bytes(&json!({
            "schema": PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": "subject",
            "id": "lab/forced-unused",
            "version": "1",
        }))
        .expect("forced unused bytes");
        let reference = RecordRef {
            schema: Token::parse(PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA)
                .expect("forced unused schema"),
            record_id: sha256_bytes(b"forced unused source identity"),
            bytes_digest: sha256_bytes(&bytes),
        };
        let value = serde_json::from_slice(&bytes).expect("forced unused value");
        corpus.total_bytes += bytes.len();
        corpus.sources.insert(
            (reference.schema.to_string(), reference.record_id.clone()),
            CanonicalBindingSource {
                reference,
                canonical_bytes: bytes,
                value,
            },
        );
    }

    fn validation_context(records: &RuntimeRecordSet) -> ValidationContext {
        let local_ids = records
            .records()
            .map(|record| record.record_id().clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut identities = IdentityCatalog::new();
        let mut external_records = ExternalRecordCatalog::new();
        for record in records.records() {
            let mut carriers = Vec::new();
            let mut references = Vec::new();
            collect_carriers(record.record().as_value(), &mut carriers, &mut references)
                .expect("valid record carriers");
            for identity in carriers {
                identities.insert(identity).expect("consistent identity");
            }
            for reference in references {
                if !local_ids.contains(&reference.record_id) {
                    external_records.insert(reference);
                }
            }
        }
        ValidationContext {
            identities,
            external_records,
        }
    }

    fn identity_descriptor_bytes(identity: &Value) -> Vec<u8> {
        canonical_json_bytes(&json!({
            "schema": CONTRACT_SPECIMEN_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": identity["kind"],
            "id": identity["id"],
            "version": identity["version"],
        }))
        .expect("identity descriptor bytes")
    }

    fn remove_source(corpus: &mut ExecutionBindingSourceCorpus, reference: &RecordRef) {
        let key = (reference.schema.to_string(), reference.record_id.clone());
        let removed = corpus.sources.remove(&key).expect("source to remove");
        corpus.total_bytes -= removed.canonical_bytes.len();
    }

    fn record_set(values: BTreeMap<String, Value>) -> RuntimeRecordSet {
        let mut records = RuntimeRecordSet::new();
        for (name, value) in values {
            let record = ValidatedRuntimeRecord::validate_value(value)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            records.insert(record).expect("unique fixture identity");
        }
        records
    }
}
