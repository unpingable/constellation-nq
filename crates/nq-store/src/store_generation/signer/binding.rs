//! Immutable signer roots and evolving current-signer bindings.
//!
//! The types in this module deliberately keep persisted coordinates distinct:
//! an immutable Store-generation root is provenance, while a current binding
//! is derived only by the initial constructor or one adjacent completed
//! transition.  Deserialized values must pass the same verifiers before use.

use std::collections::BTreeSet;

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Identity shared by every signer generation in one Store lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerLifecycleRootIdentityV1 {
    occurrence_id: String,
    physical_store_generation: String,
    lifecycle_root_id: String,
    scope_id: String,
    resident_id: String,
    role_id: String,
    role_manifest_generation: String,
    domain_id: String,
    policy_lineage_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignerLifecycleRootIdentityV1 {
    occurrence_id: String,
    physical_store_generation: String,
    lifecycle_root_id: String,
    scope_id: String,
    resident_id: String,
    role_id: String,
    role_manifest_generation: String,
    domain_id: String,
    policy_lineage_root: String,
}

impl<'de> Deserialize<'de> for SignerLifecycleRootIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawSignerLifecycleRootIdentityV1::deserialize(deserializer)?;
        construct_sb_01_lifecycle_root_identity(
            raw.occurrence_id,
            raw.physical_store_generation,
            raw.lifecycle_root_id,
            raw.scope_id,
            raw.resident_id,
            raw.role_id,
            raw.role_manifest_generation,
            raw.domain_id,
            raw.policy_lineage_root,
        )
        .map_err(de::Error::custom)
    }
}

/// Immutable signer provenance for one physical Store generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreGenerationSignerRootBindingV1 {
    identity: SignerLifecycleRootIdentityV1,
    initial_enrollment_id: String,
    initial_key_generation: String,
    initial_policy_id: String,
    genesis_digest: Sha256Digest,
    generation_commitment_digest: Sha256Digest,
    creation_cut: u64,
    binding_id: Sha256Digest,
}

/// The only three lawful current-binding provenance routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentSignerBindingModeV1 {
    /// Initial signer named by immutable root provenance.
    Initial,
    /// Adjacent predecessor-authorized healthy rotation.
    NormalSuccessor,
    /// Adjacent externally authorized recovery.
    RecoverySuccessor,
}

/// Exact persisted evidence joining receipt, append and resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedCurrentBindingAssociationV1 {
    transition_id: Option<String>,
    receipt_id: String,
    append_id: String,
    resolution_id: String,
    resulting_binding_id: Sha256Digest,
}

/// One completed transition suitable for deriving a current binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletedSignerTransitionV1 {
    pub(super) mode: CurrentSignerBindingModeV1,
    pub(super) root_id: Sha256Digest,
    pub(super) transition_id: String,
    pub(super) predecessor_binding_id: Sha256Digest,
    pub(super) predecessor_key_generation: String,
    pub(super) successor_enrollment_id: String,
    pub(super) successor_key_generation: String,
    pub(super) successor_policy_id: String,
    pub(super) successor_standing_id: String,
    pub(super) receipt_id: String,
    pub(super) append_id: String,
    pub(super) resolution_id: String,
    pub(super) effective_cut: u64,
}

/// The evolving current signer for one immutable lifecycle root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSignerGenerationBindingV1 {
    root: SignerLifecycleRootIdentityV1,
    root_binding_id: Sha256Digest,
    current_enrollment_id: String,
    current_key_generation: String,
    current_policy_id: String,
    current_standing_id: String,
    mode: CurrentSignerBindingModeV1,
    transition_id: Option<String>,
    predecessor_binding_id: Option<Sha256Digest>,
    persisted_resolution_id: String,
    effective_cut: u64,
    binding_id: Sha256Digest,
}

/// Initial-route proof that cannot represent a successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialCurrentSignerBindingV1(CurrentSignerGenerationBindingV1);

/// Normal-route proof that cannot represent an initial or recovery binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalSuccessorCurrentSignerBindingV1(CurrentSignerGenerationBindingV1);

/// Recovery-route proof that cannot represent an initial or normal binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySuccessorCurrentSignerBindingV1(CurrentSignerGenerationBindingV1);

/// Witness that a changed current key retained the immutable root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerRootPreservationWitnessV1 {
    root_binding_id: Sha256Digest,
    current_binding_id: Sha256Digest,
    changed_key: bool,
    transition_id: Option<String>,
}

/// Exhaustive inversion of one accepted current binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentSignerBindingInversionV1 {
    Initial(InitialCurrentSignerBindingV1),
    Normal(NormalSuccessorCurrentSignerBindingV1),
    Recovery(RecoverySuccessorCurrentSignerBindingV1),
}

/// Evidence that a candidate set has one current binding at an exact cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSignerBindingUniquenessV1 {
    root_binding_id: Sha256Digest,
    scope_id: String,
    effective_cut: u64,
    binding_id: Sha256Digest,
}

/// Rejected Store-resident current-binding material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalformedCurrentSignerBindingV1 {
    pub classification: BindingRefusalV1,
}

/// Typed binding refusal; it carries no standing or repair authority.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BindingRefusalV1 {
    #[error("a required binding coordinate is empty")]
    EmptyCoordinate,
    #[error("resident identity violates the exact Gen4 bounded opaque UTF-8 identity law")]
    InvalidResidentIdentity,
    #[error("a cut exceeds the exact I-JSON integer range")]
    UnsafeCut,
    #[error("the root binding identity does not match its canonical preimage")]
    RootIdentityMismatch,
    #[error("the current binding does not preserve the immutable root")]
    RootMismatch,
    #[error("the current binding mode and transition provenance disagree")]
    ModeTransitionMismatch,
    #[error("the initial binding does not use the root initial key and enrollment")]
    InitialProvenanceMismatch,
    #[error("the transition does not consume the exact immediate predecessor")]
    ImmediatePredecessorMismatch,
    #[error("the transition result and current binding disagree")]
    TransitionResultMismatch,
    #[error("the receipt, append and persisted resolution are not one association")]
    PersistedResolutionMismatch,
    #[error("the current binding canonical identity is malformed")]
    MalformedCurrentSignerBinding,
    #[error("more than one binding is current for an exact root, scope and cut")]
    CurrentBindingConflict,
    #[error("canonical identity derivation failed")]
    Canonicalization,
}

#[derive(Serialize)]
struct RootBindingPreimage<'a> {
    schema: &'static str,
    identity: &'a SignerLifecycleRootIdentityV1,
    initial_enrollment_id: &'a str,
    initial_key_generation: &'a str,
    initial_policy_id: &'a str,
    genesis_digest: &'a Sha256Digest,
    generation_commitment_digest: &'a Sha256Digest,
    creation_cut: u64,
}

#[derive(Serialize)]
struct CurrentBindingPreimage<'a> {
    schema: &'static str,
    root: &'a SignerLifecycleRootIdentityV1,
    root_binding_id: &'a Sha256Digest,
    current_enrollment_id: &'a str,
    current_key_generation: &'a str,
    current_policy_id: &'a str,
    current_standing_id: &'a str,
    mode: CurrentSignerBindingModeV1,
    transition_id: &'a Option<String>,
    predecessor_binding_id: &'a Option<Sha256Digest>,
    persisted_resolution_id: &'a str,
    effective_cut: u64,
}

fn require_nonempty(values: &[&str]) -> Result<(), BindingRefusalV1> {
    if values.iter().any(|value| value.is_empty()) {
        Err(BindingRefusalV1::EmptyCoordinate)
    } else {
        Ok(())
    }
}

fn valid_gen4_resident_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn verify_lifecycle_root_identity(
    identity: &SignerLifecycleRootIdentityV1,
) -> Result<(), BindingRefusalV1> {
    require_nonempty(&[
        &identity.occurrence_id,
        &identity.physical_store_generation,
        &identity.lifecycle_root_id,
        &identity.scope_id,
        &identity.resident_id,
        &identity.role_id,
        &identity.role_manifest_generation,
        &identity.domain_id,
        &identity.policy_lineage_root,
    ])?;
    if !valid_gen4_resident_identity(&identity.resident_id) {
        return Err(BindingRefusalV1::InvalidResidentIdentity);
    }
    Ok(())
}

fn root_digest(
    identity: &SignerLifecycleRootIdentityV1,
    initial_enrollment_id: &str,
    initial_key_generation: &str,
    initial_policy_id: &str,
    genesis_digest: &Sha256Digest,
    generation_commitment_digest: &Sha256Digest,
    creation_cut: u64,
) -> Result<Sha256Digest, BindingRefusalV1> {
    semantic_digest(&RootBindingPreimage {
        schema: "nq.c2_store_generation_signer_root_binding.v1",
        identity,
        initial_enrollment_id,
        initial_key_generation,
        initial_policy_id,
        genesis_digest,
        generation_commitment_digest,
        creation_cut,
    })
    .map_err(|_| BindingRefusalV1::Canonicalization)
}

fn current_digest(
    binding: &CurrentSignerGenerationBindingV1,
) -> Result<Sha256Digest, BindingRefusalV1> {
    semantic_digest(&CurrentBindingPreimage {
        schema: "nq.c2_current_signer_generation_binding.v1",
        root: &binding.root,
        root_binding_id: &binding.root_binding_id,
        current_enrollment_id: &binding.current_enrollment_id,
        current_key_generation: &binding.current_key_generation,
        current_policy_id: &binding.current_policy_id,
        current_standing_id: &binding.current_standing_id,
        mode: binding.mode,
        transition_id: &binding.transition_id,
        predecessor_binding_id: &binding.predecessor_binding_id,
        persisted_resolution_id: &binding.persisted_resolution_id,
        effective_cut: binding.effective_cut,
    })
    .map_err(|_| BindingRefusalV1::Canonicalization)
}

/// Construct SB-01's closed lifecycle-root identity.
pub(crate) fn construct_sb_01_lifecycle_root_identity(
    occurrence_id: String,
    physical_store_generation: String,
    lifecycle_root_id: String,
    scope_id: String,
    resident_id: String,
    role_id: String,
    role_manifest_generation: String,
    domain_id: String,
    policy_lineage_root: String,
) -> Result<SignerLifecycleRootIdentityV1, BindingRefusalV1> {
    let identity = SignerLifecycleRootIdentityV1 {
        occurrence_id,
        physical_store_generation,
        lifecycle_root_id,
        scope_id,
        resident_id,
        role_id,
        role_manifest_generation,
        domain_id,
        policy_lineage_root,
    };
    verify_lifecycle_root_identity(&identity)?;
    Ok(identity)
}

/// Construct SB-02's immutable root binding.
pub(crate) fn construct_sb_02_immutable_root_binding(
    identity: SignerLifecycleRootIdentityV1,
    initial_enrollment_id: String,
    initial_key_generation: String,
    initial_policy_id: String,
    genesis_digest: Sha256Digest,
    generation_commitment_digest: Sha256Digest,
    creation_cut: u64,
) -> Result<StoreGenerationSignerRootBindingV1, BindingRefusalV1> {
    verify_lifecycle_root_identity(&identity)?;
    require_nonempty(&[
        &initial_enrollment_id,
        &initial_key_generation,
        &initial_policy_id,
    ])?;
    if creation_cut > MAX_IJSON_INTEGER {
        return Err(BindingRefusalV1::UnsafeCut);
    }
    let binding_id = root_digest(
        &identity,
        &initial_enrollment_id,
        &initial_key_generation,
        &initial_policy_id,
        &genesis_digest,
        &generation_commitment_digest,
        creation_cut,
    )?;
    Ok(StoreGenerationSignerRootBindingV1 {
        identity,
        initial_enrollment_id,
        initial_key_generation,
        initial_policy_id,
        genesis_digest,
        generation_commitment_digest,
        creation_cut,
        binding_id,
    })
}

/// Reverify a deserialized immutable root binding without repairing it.
pub(crate) fn verify_sb_02_immutable_root_binding(
    root: &StoreGenerationSignerRootBindingV1,
) -> Result<(), BindingRefusalV1> {
    verify_lifecycle_root_identity(&root.identity)?;
    if root.creation_cut > MAX_IJSON_INTEGER {
        return Err(BindingRefusalV1::UnsafeCut);
    }
    require_nonempty(&[
        &root.initial_enrollment_id,
        &root.initial_key_generation,
        &root.initial_policy_id,
    ])?;
    let expected = root_digest(
        &root.identity,
        &root.initial_enrollment_id,
        &root.initial_key_generation,
        &root.initial_policy_id,
        &root.genesis_digest,
        &root.generation_commitment_digest,
        root.creation_cut,
    )?;
    if expected == root.binding_id {
        Ok(())
    } else {
        Err(BindingRefusalV1::RootIdentityMismatch)
    }
}

/// Construct SB-04's exact predecessor-free initial binding.
pub(crate) fn construct_sb_04_initial_binding_derivation(
    root: &StoreGenerationSignerRootBindingV1,
    standing_id: String,
    initial_resolution_id: String,
    effective_cut: u64,
) -> Result<InitialCurrentSignerBindingV1, BindingRefusalV1> {
    verify_sb_02_immutable_root_binding(root)?;
    require_nonempty(&[&standing_id, &initial_resolution_id])?;
    if effective_cut < root.creation_cut || effective_cut > MAX_IJSON_INTEGER {
        return Err(BindingRefusalV1::UnsafeCut);
    }
    let mut binding = CurrentSignerGenerationBindingV1 {
        root: root.identity.clone(),
        root_binding_id: root.binding_id.clone(),
        current_enrollment_id: root.initial_enrollment_id.clone(),
        current_key_generation: root.initial_key_generation.clone(),
        current_policy_id: root.initial_policy_id.clone(),
        current_standing_id: standing_id,
        mode: CurrentSignerBindingModeV1::Initial,
        transition_id: None,
        predecessor_binding_id: None,
        persisted_resolution_id: initial_resolution_id,
        effective_cut,
        binding_id: root.binding_id.clone(),
    };
    binding.binding_id = current_digest(&binding)?;
    Ok(InitialCurrentSignerBindingV1(binding))
}

fn construct_successor(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentSignerGenerationBindingV1,
    transition: &CompletedSignerTransitionV1,
    expected_mode: CurrentSignerBindingModeV1,
) -> Result<CurrentSignerGenerationBindingV1, BindingRefusalV1> {
    verify_sb_02_immutable_root_binding(root)?;
    verify_sb_03_evolving_current_binding(root, predecessor)?;
    if transition.mode != expected_mode || transition.mode == CurrentSignerBindingModeV1::Initial {
        return Err(BindingRefusalV1::ModeTransitionMismatch);
    }
    if transition.root_id != root.binding_id
        || transition.predecessor_binding_id != predecessor.binding_id
        || transition.predecessor_key_generation != predecessor.current_key_generation
    {
        return Err(BindingRefusalV1::ImmediatePredecessorMismatch);
    }
    require_nonempty(&[
        &transition.transition_id,
        &transition.successor_enrollment_id,
        &transition.successor_key_generation,
        &transition.successor_policy_id,
        &transition.successor_standing_id,
        &transition.receipt_id,
        &transition.append_id,
        &transition.resolution_id,
    ])?;
    if transition.effective_cut <= predecessor.effective_cut
        || transition.effective_cut > MAX_IJSON_INTEGER
    {
        return Err(BindingRefusalV1::UnsafeCut);
    }
    let mut binding = CurrentSignerGenerationBindingV1 {
        root: root.identity.clone(),
        root_binding_id: root.binding_id.clone(),
        current_enrollment_id: transition.successor_enrollment_id.clone(),
        current_key_generation: transition.successor_key_generation.clone(),
        current_policy_id: transition.successor_policy_id.clone(),
        current_standing_id: transition.successor_standing_id.clone(),
        mode: expected_mode,
        transition_id: Some(transition.transition_id.clone()),
        predecessor_binding_id: Some(predecessor.binding_id.clone()),
        persisted_resolution_id: transition.resolution_id.clone(),
        effective_cut: transition.effective_cut,
        binding_id: root.binding_id.clone(),
    };
    binding.binding_id = current_digest(&binding)?;
    Ok(binding)
}

/// Construct SB-05's adjacent normal-successor binding.
pub(crate) fn construct_sb_05_normal_binding_derivation(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentSignerGenerationBindingV1,
    transition: &CompletedSignerTransitionV1,
) -> Result<NormalSuccessorCurrentSignerBindingV1, BindingRefusalV1> {
    construct_successor(
        root,
        predecessor,
        transition,
        CurrentSignerBindingModeV1::NormalSuccessor,
    )
    .map(NormalSuccessorCurrentSignerBindingV1)
}

/// Construct SB-06's adjacent recovery-successor binding.
pub(crate) fn construct_sb_06_recovery_binding_derivation(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentSignerGenerationBindingV1,
    transition: &CompletedSignerTransitionV1,
) -> Result<RecoverySuccessorCurrentSignerBindingV1, BindingRefusalV1> {
    construct_successor(
        root,
        predecessor,
        transition,
        CurrentSignerBindingModeV1::RecoverySuccessor,
    )
    .map(RecoverySuccessorCurrentSignerBindingV1)
}

/// Verify SB-03's evolving current binding against its immutable root.
pub(crate) fn verify_sb_03_evolving_current_binding(
    root: &StoreGenerationSignerRootBindingV1,
    binding: &CurrentSignerGenerationBindingV1,
) -> Result<(), BindingRefusalV1> {
    verify_sb_02_immutable_root_binding(root)?;
    if binding.root != root.identity || binding.root_binding_id != root.binding_id {
        return Err(BindingRefusalV1::RootMismatch);
    }
    require_nonempty(&[
        &binding.current_enrollment_id,
        &binding.current_key_generation,
        &binding.current_policy_id,
        &binding.current_standing_id,
        &binding.persisted_resolution_id,
    ])?;
    if binding.effective_cut < root.creation_cut || binding.effective_cut > MAX_IJSON_INTEGER {
        return Err(BindingRefusalV1::UnsafeCut);
    }
    match binding.mode {
        CurrentSignerBindingModeV1::Initial => {
            if binding.transition_id.is_some()
                || binding.predecessor_binding_id.is_some()
                || binding.current_enrollment_id != root.initial_enrollment_id
                || binding.current_key_generation != root.initial_key_generation
                || binding.current_policy_id != root.initial_policy_id
            {
                return Err(BindingRefusalV1::InitialProvenanceMismatch);
            }
        }
        CurrentSignerBindingModeV1::NormalSuccessor
        | CurrentSignerBindingModeV1::RecoverySuccessor => {
            if binding.transition_id.as_deref().is_none_or(str::is_empty)
                || binding.predecessor_binding_id.is_none()
            {
                return Err(BindingRefusalV1::ModeTransitionMismatch);
            }
        }
    }
    if current_digest(binding)? != binding.binding_id {
        return Err(BindingRefusalV1::MalformedCurrentSignerBinding);
    }
    Ok(())
}

/// Construct SB-07's root-preservation/key-evolution witness.
pub(crate) fn construct_sb_07_root_preservation_key_evolution(
    root: &StoreGenerationSignerRootBindingV1,
    current: &CurrentSignerGenerationBindingV1,
) -> Result<SignerRootPreservationWitnessV1, BindingRefusalV1> {
    verify_sb_03_evolving_current_binding(root, current)?;
    let changed_key = current.current_key_generation != root.initial_key_generation;
    if changed_key && current.transition_id.is_none() {
        return Err(BindingRefusalV1::ModeTransitionMismatch);
    }
    Ok(SignerRootPreservationWitnessV1 {
        root_binding_id: root.binding_id.clone(),
        current_binding_id: current.binding_id.clone(),
        changed_key,
        transition_id: current.transition_id.clone(),
    })
}

/// Construct SB-08's exhaustive current-binding inversion.
pub(crate) fn construct_sb_08_binding_trichotomy_inversion(
    root: &StoreGenerationSignerRootBindingV1,
    current: CurrentSignerGenerationBindingV1,
) -> Result<CurrentSignerBindingInversionV1, BindingRefusalV1> {
    verify_sb_03_evolving_current_binding(root, &current)?;
    Ok(match current.mode {
        CurrentSignerBindingModeV1::Initial => {
            CurrentSignerBindingInversionV1::Initial(InitialCurrentSignerBindingV1(current))
        }
        CurrentSignerBindingModeV1::NormalSuccessor => {
            CurrentSignerBindingInversionV1::Normal(NormalSuccessorCurrentSignerBindingV1(current))
        }
        CurrentSignerBindingModeV1::RecoverySuccessor => CurrentSignerBindingInversionV1::Recovery(
            RecoverySuccessorCurrentSignerBindingV1(current),
        ),
    })
}

/// Construct SB-09 only when candidate-set completeness yields one current binding.
pub(crate) fn construct_sb_09_binding_uniqueness(
    root: &StoreGenerationSignerRootBindingV1,
    candidates: &[CurrentSignerGenerationBindingV1],
    effective_cut: u64,
) -> Result<CurrentSignerBindingUniquenessV1, BindingRefusalV1> {
    let matching = candidates
        .iter()
        .filter(|candidate| {
            candidate.root_binding_id == root.binding_id && candidate.effective_cut == effective_cut
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(BindingRefusalV1::CurrentBindingConflict);
    }
    for candidate in candidates {
        verify_sb_03_evolving_current_binding(root, candidate)?;
    }
    let distinct = candidates
        .iter()
        .map(|candidate| candidate.binding_id.clone())
        .collect::<BTreeSet<_>>();
    if distinct.len() != candidates.len() {
        return Err(BindingRefusalV1::CurrentBindingConflict);
    }
    let current = matching[0];
    Ok(CurrentSignerBindingUniquenessV1 {
        root_binding_id: root.binding_id.clone(),
        scope_id: root.identity.scope_id.clone(),
        effective_cut,
        binding_id: current.binding_id.clone(),
    })
}

/// Construct SB-10's exact persisted receipt/append/resolution association.
pub(crate) fn construct_sb_10_persisted_association(
    current: &CurrentSignerGenerationBindingV1,
    transition: Option<&CompletedSignerTransitionV1>,
) -> Result<PersistedCurrentBindingAssociationV1, BindingRefusalV1> {
    match (current.mode, transition) {
        (CurrentSignerBindingModeV1::Initial, None) => Ok(PersistedCurrentBindingAssociationV1 {
            transition_id: None,
            receipt_id: current.persisted_resolution_id.clone(),
            append_id: current.persisted_resolution_id.clone(),
            resolution_id: current.persisted_resolution_id.clone(),
            resulting_binding_id: current.binding_id.clone(),
        }),
        (CurrentSignerBindingModeV1::Initial, Some(_)) | (_, None) => {
            Err(BindingRefusalV1::PersistedResolutionMismatch)
        }
        (_, Some(edge))
            if edge.transition_id == current.transition_id.as_deref().unwrap_or_default()
                && edge.resolution_id == current.persisted_resolution_id =>
        {
            Ok(PersistedCurrentBindingAssociationV1 {
                transition_id: Some(edge.transition_id.clone()),
                receipt_id: edge.receipt_id.clone(),
                append_id: edge.append_id.clone(),
                resolution_id: edge.resolution_id.clone(),
                resulting_binding_id: current.binding_id.clone(),
            })
        }
        _ => Err(BindingRefusalV1::PersistedResolutionMismatch),
    }
}

/// Construct SB-11's typed malformation result without skipping resident bytes.
pub(crate) fn construct_sb_11_binding_malformation_refusal(
    root: &StoreGenerationSignerRootBindingV1,
    current: &CurrentSignerGenerationBindingV1,
) -> Result<(), MalformedCurrentSignerBindingV1> {
    verify_sb_03_evolving_current_binding(root, current)
        .map_err(|classification| MalformedCurrentSignerBindingV1 { classification })
}

/// SG-WU-03 delegates to the sole evolving-binding verifier.
pub(crate) fn construct_sg_wu_03_current_binding_resolution_owner(
    root: &StoreGenerationSignerRootBindingV1,
    current: &CurrentSignerGenerationBindingV1,
) -> Result<(), BindingRefusalV1> {
    verify_sb_03_evolving_current_binding(root, current)
}

impl CurrentSignerGenerationBindingV1 {
    #[must_use]
    pub fn binding_id(&self) -> &Sha256Digest {
        &self.binding_id
    }

    #[must_use]
    pub fn root_binding_id(&self) -> &Sha256Digest {
        &self.root_binding_id
    }

    #[must_use]
    pub fn key_generation(&self) -> &str {
        &self.current_key_generation
    }

    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.current_enrollment_id
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.current_policy_id
    }

    #[must_use]
    pub fn standing_id(&self) -> &str {
        &self.current_standing_id
    }

    #[must_use]
    pub fn persisted_resolution_id(&self) -> &str {
        &self.persisted_resolution_id
    }

    #[must_use]
    pub fn transition_id(&self) -> Option<&str> {
        self.transition_id.as_deref()
    }

    #[must_use]
    pub fn predecessor_binding_id(&self) -> Option<&Sha256Digest> {
        self.predecessor_binding_id.as_ref()
    }

    #[must_use]
    pub const fn mode(&self) -> CurrentSignerBindingModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn effective_cut(&self) -> u64 {
        self.effective_cut
    }
}

impl StoreGenerationSignerRootBindingV1 {
    #[must_use]
    pub fn binding_id(&self) -> &Sha256Digest {
        &self.binding_id
    }

    #[must_use]
    pub fn initial_key_generation(&self) -> &str {
        &self.initial_key_generation
    }

    #[must_use]
    pub fn occurrence_id(&self) -> &str {
        &self.identity.occurrence_id
    }

    #[must_use]
    pub fn physical_store_generation(&self) -> &str {
        &self.identity.physical_store_generation
    }

    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.identity.scope_id
    }
}

impl InitialCurrentSignerBindingV1 {
    pub(crate) fn into_inner(self) -> CurrentSignerGenerationBindingV1 {
        self.0
    }
}

impl NormalSuccessorCurrentSignerBindingV1 {
    pub(crate) fn into_inner(self) -> CurrentSignerGenerationBindingV1 {
        self.0
    }
}

impl RecoverySuccessorCurrentSignerBindingV1 {
    pub(crate) fn into_inner(self) -> CurrentSignerGenerationBindingV1 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use nq_protocol::sha256_bytes;

    use super::*;

    fn root() -> StoreGenerationSignerRootBindingV1 {
        construct_sb_02_immutable_root_binding(
            construct_sb_01_lifecycle_root_identity(
                "occurrence".into(),
                "store-generation".into(),
                "lifecycle-root".into(),
                "scope".into(),
                "resident".into(),
                "store-integrity".into(),
                "role-manifest-generation".into(),
                "domain".into(),
                "policy-lineage".into(),
            )
            .unwrap(),
            "enrollment-0".into(),
            "key-0".into(),
            "policy-0".into(),
            sha256_bytes(b"genesis"),
            sha256_bytes(b"commitment"),
            1,
        )
        .unwrap()
    }

    fn initial(root: &StoreGenerationSignerRootBindingV1) -> CurrentSignerGenerationBindingV1 {
        construct_sb_04_initial_binding_derivation(
            root,
            "standing-0".into(),
            "resolution-0".into(),
            2,
        )
        .unwrap()
        .into_inner()
    }

    #[test]
    fn initial_key_is_provenance_not_forever_current() {
        let root = root();
        let initial = initial(&root);
        let transition = CompletedSignerTransitionV1 {
            mode: CurrentSignerBindingModeV1::NormalSuccessor,
            root_id: root.binding_id.clone(),
            transition_id: "transition-1".into(),
            predecessor_binding_id: initial.binding_id.clone(),
            predecessor_key_generation: "key-0".into(),
            successor_enrollment_id: "enrollment-1".into(),
            successor_key_generation: "key-1".into(),
            successor_policy_id: "policy-0".into(),
            successor_standing_id: "standing-1".into(),
            receipt_id: "receipt-1".into(),
            append_id: "append-1".into(),
            resolution_id: "resolution-1".into(),
            effective_cut: 3,
        };
        let successor = construct_sb_05_normal_binding_derivation(&root, &initial, &transition)
            .unwrap()
            .into_inner();
        assert_eq!(successor.key_generation(), "key-1");
        assert_eq!(root.initial_key_generation(), "key-0");
        assert!(
            construct_sb_07_root_preservation_key_evolution(&root, &successor)
                .unwrap()
                .changed_key
        );
    }

    #[test]
    fn stale_predecessor_and_duplicate_current_binding_refuse() {
        let root = root();
        let initial = initial(&root);
        let mut wrong = initial.clone();
        wrong.current_key_generation = "substituted".into();
        assert_eq!(
            verify_sb_03_evolving_current_binding(&root, &wrong),
            Err(BindingRefusalV1::InitialProvenanceMismatch)
        );
        assert_eq!(
            construct_sb_09_binding_uniqueness(&root, &[initial.clone(), initial], 2),
            Err(BindingRefusalV1::CurrentBindingConflict)
        );
    }

    #[test]
    fn lifecycle_root_enforces_exact_raw_gen4_resident_identity() {
        let construct = |resident_id: String| {
            construct_sb_01_lifecycle_root_identity(
                "occurrence".into(),
                "store-generation".into(),
                "lifecycle-root".into(),
                "scope".into(),
                resident_id,
                "store-integrity".into(),
                "role-manifest-generation".into(),
                "domain".into(),
                "policy-lineage".into(),
            )
        };

        assert!(construct("r".repeat(1024)).is_ok());
        assert_eq!(
            construct("r".repeat(1025)),
            Err(BindingRefusalV1::InvalidResidentIdentity)
        );
        assert_eq!(
            construct("é".repeat(513)),
            Err(BindingRefusalV1::InvalidResidentIdentity)
        );
        assert_eq!(
            construct("resident\nnode-a".into()),
            Err(BindingRefusalV1::InvalidResidentIdentity)
        );
    }

    #[test]
    fn deserialization_and_reverification_cannot_bypass_resident_validation() {
        let valid = root();
        let mut malformed_value = serde_json::to_value(&valid).unwrap();
        malformed_value["identity"]["resident_id"] = serde_json::Value::String("é".repeat(513));
        assert!(
            serde_json::from_value::<StoreGenerationSignerRootBindingV1>(malformed_value).is_err()
        );

        let mut forged_inside_module = valid;
        forged_inside_module.identity.resident_id = "resident\nnode-a".into();
        assert_eq!(
            verify_sb_02_immutable_root_binding(&forged_inside_module),
            Err(BindingRefusalV1::InvalidResidentIdentity)
        );
    }
}
