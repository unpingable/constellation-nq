//! Store-owned durable terminal resolution for the C2 signer lifecycle.
//!
//! The resolver in this module consumes only inert SQLite projections.  It
//! verifies every binding, succession, lineage prefix, completion, and the
//! selected terminal enrollment before returning inert evidence.  It never
//! constructs a live signer context, custody, a permit, or standing.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::binding::{
    CurrentSignerBindingModeV1, CurrentSignerGenerationBindingV1,
    PersistenceReadyCurrentSignerBindingV1, StoreGenerationSignerRootBindingV1,
    decode_verified_current_signer_generation_binding_v1, verify_sb_02_immutable_root_binding,
};
use super::coordinator::{
    ConsumedSignedFrameV1, SignedFrameAppendDispositionV1,
    verify_durable_signer_carrier_envelope_v1,
};
use super::external_governance::{
    C2ExternalIngressRefusalV1, refuse_if_current_signer_revoked_v1,
    verify_durable_recovery_grant_identity_v1, verify_durable_restore_authorization_identity_v1,
};
use super::messages::{C2StoreSigningRouteV1, ClosedMessageFamilyV1};
use super::records::{
    FoundationalAdoptionLineageV1, StoreVerifiedDurableSignerEnrollmentV1,
    load_verified_durable_signer_enrollment_v1,
};
use super::result::SignerRefusalV2;

const SUCCESSION_SCHEMA_V1: &str = "nq.c2_signer_succession_projection.v1";
const SUCCESSION_IDENTITY_DOMAIN_V1: &str = "nq.c2.signer_succession_projection.identity.v1";
const LINEAGE_SCHEMA_V1: &str = "nq.c2_signer_lineage_projection.v1";
const LINEAGE_IDENTITY_DOMAIN_V1: &[u8] = b"nq.c2.signer_lineage.identity.v1\0";
const LINEAGE_COMPLETION_IDENTITY_DOMAIN_V1: &[u8] =
    b"nq.c2.signer_lineage_completion.identity.v1\0";

fn discontinuity_foundation_adoption_cut_v1(entry_cut: u64) -> Option<u64> {
    entry_cut.checked_add(2)
}

/// Typed refusal from the inert durable terminal resolver.
#[derive(Debug, Error)]
pub(crate) enum DurableTerminalResolutionRefusalV1 {
    #[error("durable signer terminal state is absent")]
    Absent,
    #[error("durable signer terminal state is incomplete")]
    Incomplete,
    #[error("durable signer graph has a fork")]
    Fork,
    #[error("durable signer graph has a gap")]
    Gap,
    #[error("durable signer graph has a cycle")]
    Cycle,
    #[error("durable signer graph contains disconnected material")]
    Disconnected,
    #[error("durable signer state has more than one structurally maximal complete terminal")]
    MultipleMaximalTerminals,
    #[error("durable signer projection is malformed or substituted")]
    Malformed,
    #[error("terminal binding mode and foundational-adoption lineage disagree")]
    ModeLineageMismatch,
    #[error("terminal signer enrollment evidence refused: {0}")]
    Enrollment(#[from] SignerRefusalV2),
    #[error("durable signer terminal query failed: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Typed refusal from one complete successor-terminal append transaction.
#[derive(Debug, Error)]
pub(crate) enum DurableTerminalAppendRefusalV1 {
    #[error("the prepared successor uses the wrong nominal route")]
    RouteMismatch,
    #[error("the supplied predecessor is no longer the unique current terminal")]
    StalePredecessor,
    #[error("the accepted durable enrollment does not bind the successor")]
    EnrollmentMismatch,
    #[error("the route violates stable-foundation continuity or discontinuity")]
    FoundationMismatch,
    #[error("the pending MSG-12 receipt/append/resolution join is incomplete or substituted")]
    PendingResolutionMismatch,
    #[error("an existing occurrence carries different canonical terminal content")]
    ChangedContentCollision,
    #[error("terminal resolution refused: {0}")]
    Resolution(#[from] DurableTerminalResolutionRefusalV1),
    #[error("durable signer enrollment refused: {0}")]
    Enrollment(#[from] SignerRefusalV2),
    #[error("successor-terminal append query failed: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Inert, fully reverified durable GenerationCurrent evidence.
///
/// This value is intentionally non-serializable and non-cloneable.  Its
/// contents remain evidence; there is no conversion from it into authority.
pub(crate) struct StoreVerifiedDurableGenerationCurrentV1 {
    root: StoreGenerationSignerRootBindingV1,
    initial: CurrentSignerGenerationBindingV1,
    terminal: CurrentSignerGenerationBindingV1,
    terminal_public_key: [u8; 32],
    lineage_identity: Sha256Digest,
    lineage_completion_identity: Sha256Digest,
    terminal_candidate_set_identity: Sha256Digest,
    succession_identities: Vec<Sha256Digest>,
    terminal_resolution_ledger_sequence: u64,
    terminal_resolution_message_identity: [u8; 32],
    terminal_resolution_append_identity: Sha256Digest,
    enrollment: StoreVerifiedDurableSignerEnrollmentV1,
}

impl StoreVerifiedDurableGenerationCurrentV1 {
    pub(crate) const fn root(&self) -> &StoreGenerationSignerRootBindingV1 {
        &self.root
    }

    pub(crate) const fn initial_binding(&self) -> &CurrentSignerGenerationBindingV1 {
        &self.initial
    }

    pub(crate) const fn terminal_binding(&self) -> &CurrentSignerGenerationBindingV1 {
        &self.terminal
    }

    pub(crate) const fn terminal_public_key(&self) -> [u8; 32] {
        self.terminal_public_key
    }

    pub(crate) const fn lineage_identity(&self) -> &Sha256Digest {
        &self.lineage_identity
    }

    pub(crate) const fn lineage_completion_identity(&self) -> &Sha256Digest {
        &self.lineage_completion_identity
    }

    pub(crate) const fn terminal_candidate_set_identity(&self) -> &Sha256Digest {
        &self.terminal_candidate_set_identity
    }

    pub(crate) fn succession_identities(&self) -> &[Sha256Digest] {
        &self.succession_identities
    }

    pub(crate) const fn terminal_resolution_ledger_sequence(&self) -> u64 {
        self.terminal_resolution_ledger_sequence
    }

    pub(crate) const fn terminal_resolution_message_identity(&self) -> [u8; 32] {
        self.terminal_resolution_message_identity
    }

    pub(crate) const fn terminal_resolution_append_identity(&self) -> &Sha256Digest {
        &self.terminal_resolution_append_identity
    }

    pub(crate) const fn enrollment(&self) -> &StoreVerifiedDurableSignerEnrollmentV1 {
        &self.enrollment
    }
}

#[derive(Debug, Eq, PartialEq)]
struct VerifiedDurableEnrollmentReferenceV1 {
    signer_enrollment_identity: Sha256Digest,
    foundation_identity: Sha256Digest,
    foundation_public_key: [u8; 32],
    foundation_key_generation: u64,
    foundation_key_generation_identity: Sha256Digest,
    foundation_custody_identity: Sha256Digest,
    adoption_identity: Sha256Digest,
    lineage: FoundationalAdoptionLineageV1,
    lineage_reference_identity: Sha256Digest,
    authority_reference_identity: Sha256Digest,
    occurrence_identity: Sha256Digest,
    signer_scope_identity: Sha256Digest,
    store_identity: Sha256Digest,
    physical_generation_identity: Sha256Digest,
    lifecycle_root_identity: Sha256Digest,
    frontier_identity: Sha256Digest,
    current_predecessor_identity: Sha256Digest,
    transition_identity: Sha256Digest,
    transaction_identity: Sha256Digest,
    policy_basis_identity: Sha256Digest,
    candidate_identity: Sha256Digest,
    proposal_identity: Sha256Digest,
    challenge_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    proof_of_possession_identity: Sha256Digest,
    applicability_basis_identity: Sha256Digest,
    adoption_pre_effect_store_snapshot_identity: Sha256Digest,
    enrollment_cut: u64,
    accepted_cut: u64,
}

/// Nominal healthy-successor terminal append input.
///
/// Construction consumes an already route-derived persistence-ready binding
/// and snapshots one verified durable accepted enrollment.  There is no mode
/// selector or raw enrollment constructor.
pub(crate) struct HealthySuccessorTerminalAppendV1 {
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: VerifiedDurableEnrollmentReferenceV1,
    pending_msg12: ConsumedSignedFrameV1,
}

/// Nominal historical-restore terminal append input.
pub(crate) struct RestoreSuccessorTerminalAppendV1 {
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: VerifiedDurableEnrollmentReferenceV1,
    pending_msg12: ConsumedSignedFrameV1,
}

/// Nominal externally authorized recovery terminal append input.
pub(crate) struct RecoverySuccessorTerminalAppendV1 {
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: VerifiedDurableEnrollmentReferenceV1,
    pending_msg12: ConsumedSignedFrameV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedSuccessorRouteV1 {
    Healthy,
    Restore,
    Recovery,
}

struct PreparedSuccessorTerminalAppendV1 {
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: VerifiedDurableEnrollmentReferenceV1,
    pending_msg12: ConsumedSignedFrameV1,
    route: PreparedSuccessorRouteV1,
}

#[derive(Debug, Eq, PartialEq)]
struct VerifiedPendingMsg12ReferenceV1 {
    ledger_sequence: u64,
    event_cut: u64,
    message_identity: Sha256Digest,
    append_identity: Sha256Digest,
    effect_receipt_identity: Sha256Digest,
    signer_public_key: [u8; 32],
    signer_key_generation_identity: Sha256Digest,
    occurrence_identity: Sha256Digest,
    physical_generation_identity: Sha256Digest,
    lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    transaction_intent_identity: Sha256Digest,
    active_policy_identity: Sha256Digest,
    attempt_identity: Sha256Digest,
    selected_transition_input_identity: Sha256Digest,
    completed_append_identity: Sha256Digest,
    complete_candidate_set_identity: Sha256Digest,
    pending_successor_resolution_identity: Sha256Digest,
}

struct VerifiedRestoreHistoricalReferenceV1 {
    restore_lineage_identity: Sha256Digest,
    historical_binding_identity: Sha256Digest,
    historical_enrollment_identity: Sha256Digest,
    historical_foundation_identity: Sha256Digest,
    historical_public_key: [u8; 32],
    historical_key_generation: u64,
    historical_key_generation_identity: Sha256Digest,
    historical_custody_identity: Sha256Digest,
}

struct VerifiedSuccessorJoinV1 {
    pending_msg12: VerifiedPendingMsg12ReferenceV1,
    restore: Option<VerifiedRestoreHistoricalReferenceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StableFoundationCoordinatesV1 {
    identity: Sha256Digest,
    public_key: [u8; 32],
    key_generation: u64,
    key_generation_identity: Sha256Digest,
    custody_identity: Sha256Digest,
}

fn verify_stable_foundation_route_law_v1(
    route: &PreparedSuccessorRouteV1,
    predecessor_binding_identity: &Sha256Digest,
    predecessor_adoption_identity: &Sha256Digest,
    predecessor: &StableFoundationCoordinatesV1,
    successor_lineage_reference: &Sha256Digest,
    successor: &StableFoundationCoordinatesV1,
    historical: Option<&StableFoundationCoordinatesV1>,
) -> bool {
    match route {
        PreparedSuccessorRouteV1::Healthy => {
            successor.identity != predecessor.identity
                && predecessor.key_generation.checked_add(1) == Some(successor.key_generation)
                && successor_lineage_reference == predecessor_binding_identity
                && historical.is_none()
        }
        PreparedSuccessorRouteV1::Restore => historical.is_some_and(|historical| {
            successor == historical && successor_lineage_reference == &historical.identity
        }),
        PreparedSuccessorRouteV1::Recovery => {
            successor.identity != predecessor.identity
                && successor.public_key != predecessor.public_key
                && successor.key_generation_identity != predecessor.key_generation_identity
                && successor.custody_identity != predecessor.custody_identity
                && successor_lineage_reference == predecessor_adoption_identity
                && historical.is_none()
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessorCompletionIdentityBodyV1<'identity> {
    schema: &'static str,
    identity_domain: &'static str,
    root_binding_identity: &'identity Sha256Digest,
    predecessor_binding_identity: &'identity Sha256Digest,
    successor_binding_identity: &'identity Sha256Digest,
    signer_enrollment_identity: &'identity Sha256Digest,
    transition_identity: &'identity Sha256Digest,
    receipt_identity: &'identity Sha256Digest,
    append_identity: &'identity Sha256Digest,
    persisted_resolution_identity: &'identity Sha256Digest,
    selected_transition_input_identity: &'identity Sha256Digest,
    completed_append_identity: &'identity Sha256Digest,
    complete_candidate_set_identity: &'identity Sha256Digest,
    pending_successor_resolution_identity: &'identity Sha256Digest,
    effective_cut: u64,
}

struct SuccessorProjectionPlanV1 {
    successor: CurrentSignerGenerationBindingV1,
    successor_public_key: [u8; 32],
    succession: SuccessionProjectionWireV1,
    succession_bytes: Vec<u8>,
    lineage: LineageProjectionWireV1,
    lineage_bytes: Vec<u8>,
    lineage_completion_identity: Sha256Digest,
}

#[derive(Debug)]
struct CurrentBindingProjectionRowV1 {
    binding: CurrentSignerGenerationBindingV1,
    public_key: [u8; 32],
    provenance_identity: Sha256Digest,
    continuity_authorization_identity: Option<Sha256Digest>,
    restore_lineage_identity: Option<Sha256Digest>,
    restore_authority_identity: Option<Sha256Digest>,
    historical_foundation_identity: Option<Sha256Digest>,
    recovery_condition_identity: Option<Sha256Digest>,
    recovery_authority_identity: Option<Sha256Digest>,
    recovery_grant_identity: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessionProjectionBodyV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    root_binding_identity: Sha256Digest,
    succession_mode: String,
    transition_identity: Sha256Digest,
    predecessor_binding_identity: Sha256Digest,
    successor_binding_identity: Sha256Digest,
    authorization_identity: Sha256Digest,
    restore_lineage_identity: Option<Sha256Digest>,
    restore_authority_identity: Option<Sha256Digest>,
    historical_foundation_identity: Option<Sha256Digest>,
    recovery_condition_identity: Option<Sha256Digest>,
    recovery_authority_identity: Option<Sha256Digest>,
    recovery_grant_identity: Option<Sha256Digest>,
    proposal_identity: Sha256Digest,
    successor_pop_identity: Sha256Digest,
    completion_identity: Sha256Digest,
    receipt_identity: Sha256Digest,
    append_identity: Sha256Digest,
    persisted_resolution_identity: Sha256Digest,
    predecessor_cut: u64,
    successor_cut: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessionProjectionWireV1 {
    succession_identity: Sha256Digest,
    #[serde(flatten)]
    body: SuccessionProjectionBodyV1,
}

#[derive(Debug)]
struct VerifiedSuccessionProjectionV1 {
    identity: Sha256Digest,
    mode: CurrentSignerBindingModeV1,
    transition_identity: Sha256Digest,
    predecessor: Sha256Digest,
    successor: Sha256Digest,
    authorization_identity: Sha256Digest,
    historical_foundation_identity: Option<Sha256Digest>,
    proposal_identity: Sha256Digest,
    successor_pop_identity: Sha256Digest,
    completion_identity: Sha256Digest,
    receipt_identity: Sha256Digest,
    append_identity: Sha256Digest,
    persisted_resolution_identity: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LineageProjectionWireV1 {
    schema: String,
    lineage_identity: Sha256Digest,
    root_binding_identity: Sha256Digest,
    initial_binding_identity: Sha256Digest,
    terminal_binding_identity: Sha256Digest,
    edge_count: u64,
    terminal_candidate_set_identity: Sha256Digest,
    effective_cut: u64,
}

#[derive(Debug)]
struct LineageProjectionRowV1 {
    wire: LineageProjectionWireV1,
    edges: Vec<Sha256Digest>,
    completion_identity: Sha256Digest,
}

#[derive(Debug)]
struct TerminalResolutionV1 {
    ledger_sequence: u64,
    message_identity: [u8; 32],
    append_identity: Sha256Digest,
}

#[derive(Debug)]
struct VerifiedTerminalEnrollmentCoordinatesV1 {
    lineage: FoundationalAdoptionLineageV1,
    public_key: [u8; 32],
    key_generation: u64,
}

struct GenericResolvedTerminalV1<Enrollment> {
    root: StoreGenerationSignerRootBindingV1,
    initial: CurrentSignerGenerationBindingV1,
    terminal: CurrentSignerGenerationBindingV1,
    terminal_public_key: [u8; 32],
    lineage_identity: Sha256Digest,
    lineage_completion_identity: Sha256Digest,
    terminal_candidate_set_identity: Sha256Digest,
    succession_identities: Vec<Sha256Digest>,
    terminal_resolution: TerminalResolutionV1,
    enrollment: Enrollment,
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Sha256Digest::parse(format!("sha256:{}", hex::encode(bytes)))
        .expect("SHA-256 bytes always form one algorithm-qualified digest")
}

fn parse_digest(value: &str) -> Result<Sha256Digest, DurableTerminalResolutionRefusalV1> {
    Sha256Digest::parse(value.to_owned()).map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)
}

fn parse_optional_digest(
    value: Option<String>,
) -> Result<Option<Sha256Digest>, DurableTerminalResolutionRefusalV1> {
    value.map(|value| parse_digest(&value)).transpose()
}

fn digest_bytes(value: &Sha256Digest) -> Result<[u8; 32], DurableTerminalResolutionRefusalV1> {
    hex::decode(
        value
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(DurableTerminalResolutionRefusalV1::Malformed)?,
    )
    .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?
    .try_into()
    .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)
}

fn mode_text(mode: CurrentSignerBindingModeV1) -> &'static str {
    match mode {
        CurrentSignerBindingModeV1::Initial => "initial",
        CurrentSignerBindingModeV1::NormalSuccessor => "normal_successor",
        CurrentSignerBindingModeV1::RestoreSuccessor => "restore_successor",
        CurrentSignerBindingModeV1::RecoverySuccessor => "recovery_successor",
    }
}

fn succession_mode(mode: &str) -> Option<CurrentSignerBindingModeV1> {
    match mode {
        "normal" => Some(CurrentSignerBindingModeV1::NormalSuccessor),
        "restore" => Some(CurrentSignerBindingModeV1::RestoreSuccessor),
        "recovery" => Some(CurrentSignerBindingModeV1::RecoverySuccessor),
        _ => None,
    }
}

fn expected_lineage(mode: CurrentSignerBindingModeV1) -> FoundationalAdoptionLineageV1 {
    match mode {
        CurrentSignerBindingModeV1::Initial => FoundationalAdoptionLineageV1::InitialExternal,
        CurrentSignerBindingModeV1::NormalSuccessor => {
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity
        }
        CurrentSignerBindingModeV1::RestoreSuccessor => {
            FoundationalAdoptionLineageV1::RestoreHistorical
        }
        CurrentSignerBindingModeV1::RecoverySuccessor => {
            FoundationalAdoptionLineageV1::RecoveryNewFoundation
        }
    }
}

fn verified_enrollment_reference(
    enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
) -> Result<VerifiedDurableEnrollmentReferenceV1, DurableTerminalAppendRefusalV1> {
    let adoption = enrollment.adoption();
    let physical_generation_identity = adoption
        .physical_generation_identity()
        .ok_or(DurableTerminalAppendRefusalV1::EnrollmentMismatch)?
        .clone();
    let lifecycle_root_identity = adoption
        .lifecycle_root_identity()
        .ok_or(DurableTerminalAppendRefusalV1::EnrollmentMismatch)?
        .clone();
    let current_predecessor_identity = adoption
        .current_predecessor_identity()
        .ok_or(DurableTerminalAppendRefusalV1::EnrollmentMismatch)?
        .clone();
    let transition_identity = adoption
        .transition_identity()
        .ok_or(DurableTerminalAppendRefusalV1::EnrollmentMismatch)?
        .clone();
    let frontier_identity = adoption
        .frontier_identity()
        .ok_or(DurableTerminalAppendRefusalV1::EnrollmentMismatch)?
        .clone();
    Ok(VerifiedDurableEnrollmentReferenceV1 {
        signer_enrollment_identity: enrollment.acceptance().identity().clone(),
        foundation_identity: enrollment.foundation().identity().clone(),
        foundation_public_key: enrollment.foundation().public_key()?,
        foundation_key_generation: enrollment.foundation().key_generation(),
        foundation_key_generation_identity: adoption.key_generation_identity().clone(),
        foundation_custody_identity: enrollment.foundation().custody_evidence_identity().clone(),
        adoption_identity: adoption.identity().clone(),
        lineage: adoption.lineage(),
        lineage_reference_identity: adoption.lineage_reference_identity().clone(),
        authority_reference_identity: adoption.authority_reference_identity().clone(),
        occurrence_identity: adoption.occurrence_identity().clone(),
        signer_scope_identity: adoption.signer_scope_identity().clone(),
        store_identity: adoption.store_identity().clone(),
        physical_generation_identity,
        lifecycle_root_identity,
        frontier_identity,
        current_predecessor_identity,
        transition_identity,
        transaction_identity: adoption.transaction_identity().clone(),
        policy_basis_identity: adoption.policy_basis_identity().clone(),
        candidate_identity: adoption.candidate_identity().clone(),
        proposal_identity: adoption.proposal_identity().clone(),
        challenge_identity: adoption.challenge_identity().clone(),
        attempt_identity: adoption.attempt_identity().clone(),
        proof_of_possession_identity: adoption.proof_of_possession_identity().clone(),
        applicability_basis_identity: adoption.applicability_basis_identity().clone(),
        adoption_pre_effect_store_snapshot_identity: enrollment
            .adoption_pre_effect_store_snapshot_identity()
            .clone(),
        enrollment_cut: adoption.enrollment_cut(),
        accepted_cut: enrollment.acceptance().accepted_cut(),
    })
}

fn verify_prepared_route(
    ready: &PersistenceReadyCurrentSignerBindingV1,
    enrollment: &VerifiedDurableEnrollmentReferenceV1,
    expected_mode: CurrentSignerBindingModeV1,
    expected_foundational_lineage: FoundationalAdoptionLineageV1,
) -> Result<(), DurableTerminalAppendRefusalV1> {
    let current = ready.current();
    let association = ready.association();
    let key_generation = current
        .key_generation()
        .parse::<u64>()
        .map_err(|_| DurableTerminalAppendRefusalV1::EnrollmentMismatch)?;
    if current.mode() != expected_mode
        || enrollment.lineage != expected_foundational_lineage
        || current.enrollment_id() != enrollment.signer_enrollment_identity.as_str()
        || current.key_generation() != enrollment.foundation_key_generation.to_string()
        || key_generation != enrollment.foundation_key_generation
        || current.effective_cut() <= enrollment.accepted_cut
        || association.resulting_binding_id() != current.binding_id()
        || association.transition_id() != current.transition_id()
        || association.resolution_id() != current.persisted_resolution_id()
        || parse_digest(association.receipt_id()).is_err()
        || parse_digest(association.append_id()).is_err()
        || parse_digest(association.resolution_id()).is_err()
    {
        return Err(DurableTerminalAppendRefusalV1::EnrollmentMismatch);
    }
    Ok(())
}

pub(crate) fn prepare_healthy_successor_terminal_append_v1(
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    pending_msg12: ConsumedSignedFrameV1,
) -> Result<HealthySuccessorTerminalAppendV1, DurableTerminalAppendRefusalV1> {
    let enrollment = verified_enrollment_reference(enrollment)?;
    verify_prepared_route(
        &ready,
        &enrollment,
        CurrentSignerBindingModeV1::NormalSuccessor,
        FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
    )?;
    Ok(HealthySuccessorTerminalAppendV1 {
        ready,
        enrollment,
        pending_msg12,
    })
}

pub(crate) fn prepare_restore_successor_terminal_append_v1(
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    pending_msg12: ConsumedSignedFrameV1,
) -> Result<RestoreSuccessorTerminalAppendV1, DurableTerminalAppendRefusalV1> {
    let enrollment = verified_enrollment_reference(enrollment)?;
    verify_prepared_route(
        &ready,
        &enrollment,
        CurrentSignerBindingModeV1::RestoreSuccessor,
        FoundationalAdoptionLineageV1::RestoreHistorical,
    )?;
    Ok(RestoreSuccessorTerminalAppendV1 {
        ready,
        enrollment,
        pending_msg12,
    })
}

pub(crate) fn prepare_recovery_successor_terminal_append_v1(
    ready: PersistenceReadyCurrentSignerBindingV1,
    enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    pending_msg12: ConsumedSignedFrameV1,
) -> Result<RecoverySuccessorTerminalAppendV1, DurableTerminalAppendRefusalV1> {
    let enrollment = verified_enrollment_reference(enrollment)?;
    verify_prepared_route(
        &ready,
        &enrollment,
        CurrentSignerBindingModeV1::RecoverySuccessor,
        FoundationalAdoptionLineageV1::RecoveryNewFoundation,
    )?;
    Ok(RecoverySuccessorTerminalAppendV1 {
        ready,
        enrollment,
        pending_msg12,
    })
}

fn load_bindings(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
) -> Result<BTreeMap<Sha256Digest, CurrentBindingProjectionRowV1>, DurableTerminalResolutionRefusalV1>
{
    let mut statement = transaction.prepare(
        "SELECT current_binding_identity, root_binding_identity,
                occurrence_id, physical_store_generation_identity,
                signer_lifecycle_root_identity, scope_identity,
                resident_identity, resident_generation, host_role,
                role_manifest_generation, authority_domain,
                policy_lineage_root_identity, current_enrollment_identity,
                current_key_generation, current_public_key,
                current_policy_identity, current_standing_identity,
                binding_mode, provenance_identity, transition_identity,
                predecessor_binding_identity,
                continuity_authorization_identity,
                restore_lineage_identity, restore_authority_identity,
                historical_foundation_identity,
                recovery_condition_identity, recovery_authority_identity,
                recovery_grant_identity, persisted_resolution_identity,
                effective_cut, canonical_bytes, canonical_bytes_sha256,
                canonical_bytes_length
         FROM c2_signer_current_binding_projection
         WHERE root_binding_identity = ?1",
    )?;
    let rows = statement
        .query_map([root.binding_id().as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, u64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, u64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, u64>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, String>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
                row.get::<_, Option<String>>(19)?,
                row.get::<_, Option<String>>(20)?,
                row.get::<_, Option<String>>(21)?,
                row.get::<_, Option<String>>(22)?,
                row.get::<_, Option<String>>(23)?,
                row.get::<_, Option<String>>(24)?,
                row.get::<_, Option<String>>(25)?,
                row.get::<_, Option<String>>(26)?,
                row.get::<_, Option<String>>(27)?,
                row.get::<_, String>(28)?,
                row.get::<_, u64>(29)?,
                row.get::<_, Vec<u8>>(30)?,
                row.get::<_, String>(31)?,
                row.get::<_, u64>(32)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Err(DurableTerminalResolutionRefusalV1::Absent);
    }

    let mut bindings = BTreeMap::new();
    for row in rows {
        let current = decode_verified_current_signer_generation_binding_v1(root, &row.30)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let binding_identity = parse_digest(&row.0)?;
        let key_generation = current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let role_generation = root
            .role_manifest_generation()
            .parse::<u64>()
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let public_key: [u8; 32] = row
            .14
            .as_slice()
            .try_into()
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let continuity = parse_optional_digest(row.21)?;
        let restore_lineage = parse_optional_digest(row.22)?;
        let restore_authority = parse_optional_digest(row.23)?;
        let historical_foundation = parse_optional_digest(row.24)?;
        let recovery_condition = parse_optional_digest(row.25)?;
        let recovery_authority = parse_optional_digest(row.26)?;
        let recovery_grant = parse_optional_digest(row.27)?;
        let shape_ok = match current.mode() {
            CurrentSignerBindingModeV1::Initial => {
                row.19.is_none()
                    && row.20.is_none()
                    && continuity.is_none()
                    && restore_lineage.is_none()
                    && restore_authority.is_none()
                    && historical_foundation.is_none()
                    && recovery_condition.is_none()
                    && recovery_authority.is_none()
                    && recovery_grant.is_none()
            }
            CurrentSignerBindingModeV1::NormalSuccessor => {
                row.19.is_some()
                    && row.20.is_some()
                    && continuity.is_some()
                    && restore_lineage.is_none()
                    && restore_authority.is_none()
                    && historical_foundation.is_none()
                    && recovery_condition.is_none()
                    && recovery_authority.is_none()
                    && recovery_grant.is_none()
            }
            CurrentSignerBindingModeV1::RestoreSuccessor => {
                row.19.is_some()
                    && row.20.is_some()
                    && continuity.is_none()
                    && restore_lineage.is_some()
                    && restore_authority.is_some()
                    && historical_foundation.is_some()
                    && recovery_condition.is_none()
                    && recovery_authority.is_none()
                    && recovery_grant.is_none()
            }
            CurrentSignerBindingModeV1::RecoverySuccessor => {
                row.19.is_some()
                    && row.20.is_some()
                    && continuity.is_none()
                    && restore_lineage.is_none()
                    && restore_authority.is_none()
                    && historical_foundation.is_none()
                    && recovery_condition.is_some()
                    && recovery_authority.is_some()
                    && recovery_grant.is_some()
            }
        };
        if row.0 != current.binding_id().as_str()
            || row.1 != root.binding_id().as_str()
            || row.2 != root.occurrence_id()
            || row.3 != root.physical_store_generation()
            || row.4 != root.lifecycle_root_id()
            || row.5 != root.scope_id()
            || row.6 != root.resident_id()
            || row.7 == 0
            || row.8 != root.role_id()
            || row.9 != role_generation
            || row.10 != root.domain_id()
            || row.11 != root.policy_lineage_root()
            || row.12 != current.enrollment_id()
            || row.13 != key_generation
            || row.15 != current.policy_id()
            || row.16 != current.standing_id()
            || row.17 != mode_text(current.mode())
            || row.19.as_deref() != current.transition_id()
            || row.20.as_deref() != current.predecessor_binding_id().map(Sha256Digest::as_str)
            || row.28 != current.persisted_resolution_id()
            || row.29 != current.effective_cut()
            || row.32 != row.30.len() as u64
            || parse_digest(&row.31)? != sha256_bytes(&row.30)
            || !shape_ok
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        let projection = CurrentBindingProjectionRowV1 {
            binding: current,
            public_key,
            provenance_identity: parse_digest(&row.18)?,
            continuity_authorization_identity: continuity,
            restore_lineage_identity: restore_lineage,
            restore_authority_identity: restore_authority,
            historical_foundation_identity: historical_foundation,
            recovery_condition_identity: recovery_condition,
            recovery_authority_identity: recovery_authority,
            recovery_grant_identity: recovery_grant,
        };
        if bindings.insert(binding_identity, projection).is_some() {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
    }
    Ok(bindings)
}

fn load_resolution(
    transaction: &Transaction<'_>,
    binding: &CurrentSignerGenerationBindingV1,
) -> Result<TerminalResolutionV1, DurableTerminalResolutionRefusalV1> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT ledger_sequence, family, route, message_identity,
                    append_identity, effect_receipt_identity
             FROM c2_signer_message_appends
             WHERE effect_receipt_identity = ?1",
        )?;
        statement
            .query_map([binding.persisted_resolution_id()], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != 1 {
        return Err(if rows.is_empty() {
            DurableTerminalResolutionRefusalV1::Incomplete
        } else {
            DurableTerminalResolutionRefusalV1::Malformed
        });
    }
    let row = &rows[0];
    let expected_route = match binding.mode() {
        CurrentSignerBindingModeV1::Initial => "msg10_installation_receipt",
        CurrentSignerBindingModeV1::NormalSuccessor
        | CurrentSignerBindingModeV1::RestoreSuccessor
        | CurrentSignerBindingModeV1::RecoverySuccessor => "msg12_receipt_pending",
    };
    let expected_family = match binding.mode() {
        CurrentSignerBindingModeV1::Initial => "MSG-10",
        _ => "MSG-12",
    };
    if row.1 != expected_family
        || row.2 != expected_route
        || row.5 != binding.persisted_resolution_id()
    {
        return Err(DurableTerminalResolutionRefusalV1::Malformed);
    }
    let message_identity: [u8; 32] = row
        .3
        .as_slice()
        .try_into()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    Ok(TerminalResolutionV1 {
        ledger_sequence: row.0,
        message_identity,
        append_identity: parse_digest(&row.4)?,
    })
}

fn load_successions(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
    bindings: &BTreeMap<Sha256Digest, CurrentBindingProjectionRowV1>,
) -> Result<
    BTreeMap<Sha256Digest, VerifiedSuccessionProjectionV1>,
    DurableTerminalResolutionRefusalV1,
> {
    let mut statement = transaction.prepare(
        "SELECT succession_identity, root_binding_identity, succession_mode,
                transition_identity, predecessor_binding_identity,
                successor_binding_identity, authorization_identity,
                restore_lineage_identity, restore_authority_identity,
                historical_foundation_identity, recovery_condition_identity,
                recovery_authority_identity, recovery_grant_identity,
                proposal_identity, successor_pop_identity, completion_identity,
                receipt_identity, append_identity, persisted_resolution_identity,
                predecessor_cut, successor_cut, canonical_bytes,
                canonical_bytes_sha256, canonical_bytes_length
         FROM c2_signer_succession_projection
         WHERE root_binding_identity = ?1",
    )?;
    let raw = statement
        .query_map([root.binding_id().as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, String>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
                row.get::<_, u64>(19)?,
                row.get::<_, u64>(20)?,
                row.get::<_, Vec<u8>>(21)?,
                row.get::<_, String>(22)?,
                row.get::<_, u64>(23)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut successions = BTreeMap::new();
    for row in raw {
        let wire: SuccessionProjectionWireV1 = serde_json::from_slice(&row.21)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let canonical = canonical_json_bytes(&wire)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let expected_identity = semantic_digest(&wire.body)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let mode = succession_mode(&row.2).ok_or(DurableTerminalResolutionRefusalV1::Malformed)?;
        let predecessor_id = parse_digest(&row.4)?;
        let successor_id = parse_digest(&row.5)?;
        let predecessor = bindings
            .get(&predecessor_id)
            .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
        let successor = bindings
            .get(&successor_id)
            .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
        let authorization = parse_digest(&row.6)?;
        let restore_lineage = parse_optional_digest(row.7.clone())?;
        let restore_authority = parse_optional_digest(row.8.clone())?;
        let historical_foundation = parse_optional_digest(row.9.clone())?;
        let recovery_condition = parse_optional_digest(row.10.clone())?;
        let recovery_authority = parse_optional_digest(row.11.clone())?;
        let recovery_grant = parse_optional_digest(row.12.clone())?;
        let route_shape = match mode {
            CurrentSignerBindingModeV1::NormalSuccessor => {
                successor.continuity_authorization_identity.as_ref() == Some(&authorization)
                    && restore_lineage.is_none()
                    && restore_authority.is_none()
                    && historical_foundation.is_none()
                    && recovery_condition.is_none()
                    && recovery_authority.is_none()
                    && recovery_grant.is_none()
            }
            CurrentSignerBindingModeV1::RestoreSuccessor => {
                restore_lineage.is_some()
                    && restore_authority.as_ref() == Some(&authorization)
                    && historical_foundation.is_some()
                    && successor.restore_lineage_identity == restore_lineage
                    && successor.restore_authority_identity == restore_authority
                    && successor.historical_foundation_identity == historical_foundation
                    && recovery_condition.is_none()
                    && recovery_authority.is_none()
                    && recovery_grant.is_none()
            }
            CurrentSignerBindingModeV1::RecoverySuccessor => {
                restore_lineage.is_none()
                    && restore_authority.is_none()
                    && historical_foundation.is_none()
                    && recovery_grant.as_ref() == Some(&authorization)
                    && successor.recovery_condition_identity == recovery_condition
                    && successor.recovery_authority_identity == recovery_authority
                    && successor.recovery_grant_identity == recovery_grant
                    && recovery_condition.is_some()
                    && recovery_authority.is_some()
                    && recovery_grant.is_some()
            }
            CurrentSignerBindingModeV1::Initial => false,
        };
        let receipt_identity = parse_digest(&row.16)?;
        let append_identity = parse_digest(&row.17)?;
        let persisted_resolution_identity = parse_digest(&row.18)?;
        let resolution = load_resolution(transaction, &successor.binding)?;
        if row.0 != wire.succession_identity.as_str()
            || wire.succession_identity != expected_identity
            || row.1 != root.binding_id().as_str()
            || row.21 != canonical
            || row.23 != row.21.len() as u64
            || parse_digest(&row.22)? != sha256_bytes(&row.21)
            || wire.body.schema != SUCCESSION_SCHEMA_V1
            || wire.body.schema_version != 1
            || wire.body.identity_domain != SUCCESSION_IDENTITY_DOMAIN_V1
            || wire.body.root_binding_identity != *root.binding_id()
            || wire.body.succession_mode != row.2
            || wire.body.transition_identity != parse_digest(&row.3)?
            || wire.body.predecessor_binding_identity != predecessor_id
            || wire.body.successor_binding_identity != successor_id
            || wire.body.authorization_identity != authorization
            || wire.body.restore_lineage_identity != restore_lineage
            || wire.body.restore_authority_identity != restore_authority
            || wire.body.historical_foundation_identity != historical_foundation
            || wire.body.recovery_condition_identity != recovery_condition
            || wire.body.recovery_authority_identity != recovery_authority
            || wire.body.recovery_grant_identity != recovery_grant
            || wire.body.proposal_identity != parse_digest(&row.13)?
            || wire.body.successor_pop_identity != parse_digest(&row.14)?
            || wire.body.completion_identity != parse_digest(&row.15)?
            || wire.body.receipt_identity != receipt_identity
            || wire.body.append_identity != append_identity
            || wire.body.persisted_resolution_identity != persisted_resolution_identity
            || wire.body.predecessor_cut != row.19
            || wire.body.successor_cut != row.20
            || predecessor.binding.effective_cut() != row.19
            || successor.binding.effective_cut() != row.20
            || successor.binding.mode() != mode
            || successor.binding.predecessor_binding_id() != Some(&predecessor_id)
            || successor.binding.transition_id() != Some(row.3.as_str())
            || successor.binding.persisted_resolution_id() != row.18
            || successor.provenance_identity != wire.succession_identity
            || receipt_identity
                != Sha256Digest::parse(format!(
                    "sha256:{}",
                    hex::encode(resolution.message_identity)
                ))
                .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?
            || append_identity != resolution.append_identity
            || !route_shape
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        if successions
            .insert(
                wire.succession_identity.clone(),
                VerifiedSuccessionProjectionV1 {
                    identity: wire.succession_identity,
                    mode,
                    transition_identity: wire.body.transition_identity,
                    predecessor: predecessor_id,
                    successor: successor_id,
                    authorization_identity: wire.body.authorization_identity,
                    historical_foundation_identity: wire.body.historical_foundation_identity,
                    proposal_identity: wire.body.proposal_identity,
                    successor_pop_identity: wire.body.successor_pop_identity,
                    completion_identity: wire.body.completion_identity,
                    receipt_identity,
                    append_identity,
                    persisted_resolution_identity,
                },
            )
            .is_some()
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
    }
    Ok(successions)
}

fn derive_complete_graph(
    root: &StoreGenerationSignerRootBindingV1,
    bindings: &BTreeMap<Sha256Digest, CurrentBindingProjectionRowV1>,
    successions: &BTreeMap<Sha256Digest, VerifiedSuccessionProjectionV1>,
) -> Result<(Sha256Digest, Vec<Sha256Digest>, Vec<Sha256Digest>), DurableTerminalResolutionRefusalV1>
{
    let initials = bindings
        .iter()
        .filter(|(_, row)| row.binding.mode() == CurrentSignerBindingModeV1::Initial)
        .map(|(identity, _)| identity.clone())
        .collect::<Vec<_>>();
    if initials.is_empty() {
        return Err(DurableTerminalResolutionRefusalV1::Gap);
    }
    if initials.len() != 1 {
        return Err(DurableTerminalResolutionRefusalV1::MultipleMaximalTerminals);
    }
    let initial = initials[0].clone();
    let initial_row = &bindings[&initial];
    if initial_row.binding.enrollment_id() != root.initial_enrollment_id()
        || initial_row.binding.key_generation() != root.initial_key_generation()
        || initial_row.provenance_identity != *root.binding_id()
    {
        return Err(DurableTerminalResolutionRefusalV1::Malformed);
    }

    let mut outgoing = BTreeMap::<Sha256Digest, &VerifiedSuccessionProjectionV1>::new();
    let mut incoming = BTreeMap::<Sha256Digest, &VerifiedSuccessionProjectionV1>::new();
    for edge in successions.values() {
        if outgoing.insert(edge.predecessor.clone(), edge).is_some() {
            return Err(DurableTerminalResolutionRefusalV1::Fork);
        }
        if incoming.insert(edge.successor.clone(), edge).is_some() {
            return Err(DurableTerminalResolutionRefusalV1::Fork);
        }
    }
    for (identity, row) in bindings {
        if row.binding.mode() == CurrentSignerBindingModeV1::Initial {
            if incoming.contains_key(identity) {
                return Err(DurableTerminalResolutionRefusalV1::Cycle);
            }
        } else if !incoming.contains_key(identity) {
            return Err(DurableTerminalResolutionRefusalV1::Gap);
        }
    }

    // Classify a closed component as a cycle rather than merely disconnected.
    // In a healthy store this is already excluded by identity-derived bindings;
    // the explicit walk keeps the resolver fail-closed under projection damage.
    for start in bindings.keys() {
        let mut local = BTreeSet::new();
        let mut cursor = start;
        while let Some(edge) = outgoing.get(cursor) {
            if !local.insert(cursor.clone()) {
                return Err(DurableTerminalResolutionRefusalV1::Cycle);
            }
            cursor = &edge.successor;
        }
    }

    let mut visited_bindings = BTreeSet::new();
    let mut visited_edges = BTreeSet::new();
    let mut path_bindings = vec![initial.clone()];
    let mut path_edges = Vec::new();
    let mut cursor = initial;
    loop {
        if !visited_bindings.insert(cursor.clone()) {
            return Err(DurableTerminalResolutionRefusalV1::Cycle);
        }
        let Some(edge) = outgoing.get(&cursor) else {
            break;
        };
        if !visited_edges.insert(edge.identity.clone()) {
            return Err(DurableTerminalResolutionRefusalV1::Cycle);
        }
        path_edges.push(edge.identity.clone());
        cursor = edge.successor.clone();
        path_bindings.push(cursor.clone());
    }
    if visited_bindings.len() != bindings.len() || visited_edges.len() != successions.len() {
        return Err(DurableTerminalResolutionRefusalV1::Disconnected);
    }
    Ok((path_bindings[0].clone(), path_bindings, path_edges))
}

fn load_lineages(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
    initial: &Sha256Digest,
    path_bindings: &[Sha256Digest],
    path_edges: &[Sha256Digest],
    bindings: &BTreeMap<Sha256Digest, CurrentBindingProjectionRowV1>,
    successions: &BTreeMap<Sha256Digest, VerifiedSuccessionProjectionV1>,
) -> Result<LineageProjectionRowV1, DurableTerminalResolutionRefusalV1> {
    let mut statement = transaction.prepare(
        "SELECT l.lineage_identity, l.root_binding_identity,
                l.initial_binding_identity, l.terminal_binding_identity,
                l.edge_count, l.terminal_candidate_set_identity,
                l.effective_cut, l.canonical_bytes,
                l.canonical_bytes_sha256, l.canonical_bytes_length,
                c.completion_identity, c.root_binding_identity,
                c.terminal_binding_identity, c.edge_count
         FROM c2_signer_lineage_projection AS l
         LEFT JOIN c2_signer_lineage_completion_projection AS c
           ON c.lineage_identity = l.lineage_identity
         WHERE l.root_binding_identity = ?1",
    )?;
    let raw = statement
        .query_map([root.binding_id().as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, u64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, u64>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<u64>>(13)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if raw.is_empty() {
        return Err(DurableTerminalResolutionRefusalV1::Incomplete);
    }
    let completion_count: u64 = transaction.query_row(
        "SELECT COUNT(*)
         FROM c2_signer_lineage_completion_projection
         WHERE root_binding_identity = ?1",
        [root.binding_id().as_str()],
        |row| row.get(0),
    )?;
    if usize::try_from(completion_count)
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?
        != raw.len()
    {
        return Err(DurableTerminalResolutionRefusalV1::Malformed);
    }

    let mut verified = Vec::new();
    for row in raw {
        let Some(completion_identity_text) = row.10 else {
            return Err(DurableTerminalResolutionRefusalV1::Incomplete);
        };
        let wire: LineageProjectionWireV1 = serde_json::from_slice(&row.7)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let canonical = canonical_json_bytes(&wire)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let lineage_identity = digest_fields(
            LINEAGE_IDENTITY_DOMAIN_V1,
            &[
                row.1.as_bytes(),
                row.3.as_bytes(),
                row.5.as_bytes(),
                &row.6.to_be_bytes(),
            ],
        );
        let edge_count =
            usize::try_from(row.4).map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        if edge_count >= path_bindings.len() || edge_count > path_edges.len() {
            return Err(DurableTerminalResolutionRefusalV1::Gap);
        }
        let terminal = &path_bindings[edge_count];
        let terminal_binding = bindings
            .get(terminal)
            .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
        let mut edge_statement = transaction.prepare(
            "SELECT edge_ordinal, succession_identity,
                    predecessor_binding_identity, successor_binding_identity,
                    succession_mode
             FROM c2_signer_lineage_edge_projection
             WHERE lineage_identity = ?1
             ORDER BY edge_ordinal",
        )?;
        let edge_rows = edge_statement
            .query_map([row.0.as_str()], |edge| {
                Ok((
                    edge.get::<_, u64>(0)?,
                    edge.get::<_, String>(1)?,
                    edge.get::<_, String>(2)?,
                    edge.get::<_, String>(3)?,
                    edge.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if edge_rows.len() != edge_count {
            return Err(DurableTerminalResolutionRefusalV1::Gap);
        }
        let mut edge_ids = Vec::new();
        for (ordinal, edge_row) in edge_rows.iter().enumerate() {
            let expected_edge = &path_edges[ordinal];
            let edge = successions
                .get(expected_edge)
                .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
            if edge_row.0 != ordinal as u64
                || edge_row.1 != expected_edge.as_str()
                || edge_row.2 != edge.predecessor.as_str()
                || edge_row.3 != edge.successor.as_str()
                || succession_mode(&edge_row.4) != Some(edge.mode)
            {
                return Err(DurableTerminalResolutionRefusalV1::Gap);
            }
            edge_ids.push(expected_edge.clone());
        }
        let completion_identity = parse_digest(&completion_identity_text)?;
        let completion_receipt = if edge_count == 0 {
            let initial_resolution = load_resolution(transaction, &terminal_binding.binding)?;
            Sha256Digest::parse(format!(
                "sha256:{}",
                hex::encode(initial_resolution.message_identity)
            ))
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?
        } else {
            successions[&path_edges[edge_count - 1]]
                .receipt_identity
                .clone()
        };
        let expected_completion = digest_fields(
            LINEAGE_COMPLETION_IDENTITY_DOMAIN_V1,
            &[
                lineage_identity.as_str().as_bytes(),
                root.binding_id().as_str().as_bytes(),
                terminal.as_str().as_bytes(),
                completion_receipt.as_str().as_bytes(),
            ],
        );
        if row.0 != lineage_identity.as_str()
            || row.1 != root.binding_id().as_str()
            || row.2 != initial.as_str()
            || row.3 != terminal.as_str()
            || row.6 != terminal_binding.binding.effective_cut()
            || row.7 != canonical
            || row.9 != row.7.len() as u64
            || parse_digest(&row.8)? != sha256_bytes(&row.7)
            || wire.schema != LINEAGE_SCHEMA_V1
            || wire.lineage_identity != lineage_identity
            || wire.root_binding_identity != *root.binding_id()
            || wire.initial_binding_identity != *initial
            || wire.terminal_binding_identity != *terminal
            || wire.edge_count != row.4
            || wire.terminal_candidate_set_identity != parse_digest(&row.5)?
            || wire.effective_cut != row.6
            || row.11.as_deref() != Some(root.binding_id().as_str())
            || row.12.as_deref() != Some(terminal.as_str())
            || row.13 != Some(row.4)
            || completion_identity != expected_completion
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        verified.push(LineageProjectionRowV1 {
            wire,
            edges: edge_ids,
            completion_identity,
        });
    }

    let maximum = verified
        .iter()
        .map(|lineage| lineage.edges.len())
        .max()
        .ok_or(DurableTerminalResolutionRefusalV1::Incomplete)?;
    if maximum != path_edges.len() {
        return Err(DurableTerminalResolutionRefusalV1::Incomplete);
    }
    let mut maximal = verified
        .into_iter()
        .filter(|lineage| lineage.edges.len() == maximum)
        .collect::<Vec<_>>();
    if maximal.len() != 1 {
        return Err(DurableTerminalResolutionRefusalV1::MultipleMaximalTerminals);
    }
    Ok(maximal.remove(0))
}

fn resolve_with_enrollment_loader<Enrollment>(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
    load_enrollment: impl FnOnce(
        &Transaction<'_>,
        &CurrentSignerGenerationBindingV1,
    ) -> Result<
        (VerifiedTerminalEnrollmentCoordinatesV1, Enrollment),
        DurableTerminalResolutionRefusalV1,
    >,
) -> Result<GenericResolvedTerminalV1<Enrollment>, DurableTerminalResolutionRefusalV1> {
    verify_sb_02_immutable_root_binding(root)
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    let bindings = load_bindings(transaction, root)?;
    let successions = load_successions(transaction, root, &bindings)?;
    let (initial_id, path_bindings, path_edges) =
        derive_complete_graph(root, &bindings, &successions)?;
    let lineage = load_lineages(
        transaction,
        root,
        &initial_id,
        &path_bindings,
        &path_edges,
        &bindings,
        &successions,
    )?;
    let terminal_id = path_bindings
        .last()
        .ok_or(DurableTerminalResolutionRefusalV1::Incomplete)?;
    let initial = bindings[&initial_id].binding.clone();
    let terminal_row = &bindings[terminal_id];
    let terminal = terminal_row.binding.clone();
    let terminal_resolution = load_resolution(transaction, &terminal)?;
    let (enrollment_coordinates, enrollment) = load_enrollment(transaction, &terminal)?;
    let terminal_generation = terminal
        .key_generation()
        .parse::<u64>()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    if enrollment_coordinates.lineage != expected_lineage(terminal.mode()) {
        return Err(DurableTerminalResolutionRefusalV1::ModeLineageMismatch);
    }
    if enrollment_coordinates.public_key != terminal_row.public_key
        || enrollment_coordinates.key_generation != terminal_generation
    {
        return Err(DurableTerminalResolutionRefusalV1::Malformed);
    }

    Ok(GenericResolvedTerminalV1 {
        root: root.clone(),
        initial,
        terminal,
        terminal_public_key: terminal_row.public_key,
        lineage_identity: lineage.wire.lineage_identity,
        lineage_completion_identity: lineage.completion_identity,
        terminal_candidate_set_identity: lineage.wire.terminal_candidate_set_identity,
        succession_identities: lineage.edges,
        terminal_resolution,
        enrollment,
    })
}

/// Resolve one exact structurally maximal completed signer terminal.
///
/// The caller supplies the independently verified immutable root.  All
/// evolving material is loaded from the retained transaction.  Earlier
/// completed lineage prefixes are legal; forks, gaps, cycles, disconnected
/// rows, or multiple maximal completions refuse.
pub(crate) fn resolve_store_verified_durable_generation_current_v1(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
) -> Result<StoreVerifiedDurableGenerationCurrentV1, DurableTerminalResolutionRefusalV1> {
    let resolved = resolve_with_enrollment_loader(transaction, root, |transaction, terminal| {
        let enrollment_identity = parse_digest(terminal.enrollment_id())?;
        let enrollment =
            load_verified_durable_signer_enrollment_v1(transaction, &enrollment_identity)?;
        let public_key = enrollment.foundation().public_key()?;
        let coordinates = VerifiedTerminalEnrollmentCoordinatesV1 {
            lineage: enrollment.adoption().lineage(),
            public_key,
            key_generation: enrollment.foundation().key_generation(),
        };
        Ok((coordinates, enrollment))
    })?;
    verify_production_initial_enrollment_v1(transaction, root, &resolved.initial)?;
    verify_production_successor_completion_identities_v1(transaction, root)?;
    Ok(StoreVerifiedDurableGenerationCurrentV1 {
        root: resolved.root,
        initial: resolved.initial,
        terminal: resolved.terminal,
        terminal_public_key: resolved.terminal_public_key,
        lineage_identity: resolved.lineage_identity,
        lineage_completion_identity: resolved.lineage_completion_identity,
        terminal_candidate_set_identity: resolved.terminal_candidate_set_identity,
        succession_identities: resolved.succession_identities,
        terminal_resolution_ledger_sequence: resolved.terminal_resolution.ledger_sequence,
        terminal_resolution_message_identity: resolved.terminal_resolution.message_identity,
        terminal_resolution_append_identity: resolved.terminal_resolution.append_identity,
        enrollment: resolved.enrollment,
    })
}

fn verify_production_initial_enrollment_v1(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
    initial: &CurrentSignerGenerationBindingV1,
) -> Result<(), DurableTerminalResolutionRefusalV1> {
    let bindings = load_bindings(transaction, root)?;
    let initial_row = bindings
        .get(initial.binding_id())
        .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
    let enrollment_identity = parse_digest(initial.enrollment_id())?;
    let enrollment = load_verified_durable_signer_enrollment_v1(transaction, &enrollment_identity)?;
    let foundation = enrollment.foundation();
    let adoption = enrollment.adoption();
    let key_generation = initial
        .key_generation()
        .parse::<u64>()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    let root_key_generation = root
        .initial_key_generation()
        .parse::<u64>()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    let occurrence = text_coordinate_digest(
        b"nq.c2.store_occurrence.identity.v1\0",
        root.occurrence_id(),
    );
    let scope = parse_digest(root.scope_id())?;
    if initial.mode() != CurrentSignerBindingModeV1::Initial
        || root.initial_enrollment_id() != initial.enrollment_id()
        || root.initial_policy_id() != initial.policy_id()
        || enrollment.acceptance().identity() != &enrollment_identity
        || adoption.lineage() != FoundationalAdoptionLineageV1::InitialExternal
        || adoption.foundation_identity() != foundation.identity()
        || adoption.physical_generation_identity().is_some()
        || adoption.lifecycle_root_identity().is_some()
        || adoption.frontier_identity().is_some()
        || adoption.current_predecessor_identity().is_some()
        || adoption.transition_identity().is_some()
        || adoption.occurrence_identity() != &occurrence
        || adoption.signer_scope_identity() != &scope
        || foundation.public_key()? != initial_row.public_key
        || foundation.key_generation() != key_generation
        || key_generation != root_key_generation
        || enrollment.acceptance().accepted_cut() >= initial.effective_cut()
    {
        return Err(DurableTerminalResolutionRefusalV1::Malformed);
    }
    Ok(())
}

fn load_consumed_pending_msg12_by_effect_v1(
    transaction: &Transaction<'_>,
    effect_receipt_identity: &Sha256Digest,
) -> Result<ConsumedSignedFrameV1, DurableTerminalResolutionRefusalV1> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT ledger_sequence, generation_sequence, append_identity,
                    message_identity, signer_key_generation_identity,
                    resulting_frontier_identity, effect_receipt_identity,
                    event_cut
             FROM c2_signer_message_appends
             WHERE family = 'MSG-12' AND route = 'msg12_receipt_pending'
               AND effect_receipt_identity = ?1",
        )?;
        statement
            .query_map([effect_receipt_identity.as_str()], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u64>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != 1 {
        return Err(if rows.is_empty() {
            DurableTerminalResolutionRefusalV1::Incomplete
        } else {
            DurableTerminalResolutionRefusalV1::Malformed
        });
    }
    let row = &rows[0];
    let message_identity: [u8; 32] = row
        .3
        .as_slice()
        .try_into()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    let signer_key_generation: [u8; 32] = row
        .4
        .as_slice()
        .try_into()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    let resulting_frontier_identity: [u8; 32] = row
        .5
        .as_slice()
        .try_into()
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
    if row.6 != effect_receipt_identity.as_str() {
        return Err(DurableTerminalResolutionRefusalV1::Malformed);
    }
    Ok(ConsumedSignedFrameV1 {
        disposition: SignedFrameAppendDispositionV1::ExactReplay,
        family: ClosedMessageFamilyV1::Msg12PolicyTransitionReceipt,
        route: C2StoreSigningRouteV1::Msg12ReceiptPending,
        message_identity,
        append_identity: row.2.clone(),
        signer_key_generation,
        ledger_sequence: row.0,
        generation_sequence: row.1,
        event_cut: row.7,
        resulting_frontier_identity,
        effect_receipt_identity: row.6.clone(),
    })
}

fn verify_production_successor_completion_identities_v1(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
) -> Result<(), DurableTerminalResolutionRefusalV1> {
    let bindings = load_bindings(transaction, root)?;
    let successions = load_successions(transaction, root, &bindings)?;
    for succession in successions.values() {
        let predecessor = bindings
            .get(&succession.predecessor)
            .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
        let successor = bindings
            .get(&succession.successor)
            .ok_or(DurableTerminalResolutionRefusalV1::Gap)?;
        let predecessor_enrollment = load_verified_durable_signer_enrollment_v1(
            transaction,
            &parse_digest(predecessor.binding.enrollment_id())?,
        )?;
        let successor_enrollment = load_verified_durable_signer_enrollment_v1(
            transaction,
            &parse_digest(successor.binding.enrollment_id())?,
        )?;
        let successor_reference = verified_enrollment_reference(&successor_enrollment)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        let expected_lineage = expected_lineage(succession.mode);
        let physical_generation = parse_digest(root.physical_store_generation())?;
        let lifecycle_root = parse_digest(root.lifecycle_root_id())?;
        let scope = parse_digest(root.scope_id())?;
        let occurrence = text_coordinate_digest(
            b"nq.c2.store_occurrence.identity.v1\0",
            root.occurrence_id(),
        );
        if successor_reference.lineage != expected_lineage
            || successor_reference.physical_generation_identity != physical_generation
            || successor_reference.lifecycle_root_identity != lifecycle_root
            || successor_reference.signer_scope_identity != scope
            || successor_reference.occurrence_identity != occurrence
            || successor_reference.current_predecessor_identity != succession.predecessor
            || successor_reference.transition_identity != succession.transition_identity
            || successor_reference.authority_reference_identity != succession.authorization_identity
            || successor_reference.proposal_identity != succession.proposal_identity
            || successor_reference.proof_of_possession_identity != succession.successor_pop_identity
            || successor_reference.accepted_cut >= successor.binding.effective_cut()
            || successor_reference.foundation_public_key != successor.public_key
            || successor_reference.foundation_key_generation
                != successor
                    .binding
                    .key_generation()
                    .parse::<u64>()
                    .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        let predecessor_coordinates = StableFoundationCoordinatesV1 {
            identity: predecessor_enrollment.foundation().identity().clone(),
            public_key: predecessor_enrollment.foundation().public_key()?,
            key_generation: predecessor_enrollment.foundation().key_generation(),
            key_generation_identity: predecessor_enrollment
                .adoption()
                .key_generation_identity()
                .clone(),
            custody_identity: predecessor_enrollment
                .foundation()
                .custody_evidence_identity()
                .clone(),
        };
        let successor_coordinates = StableFoundationCoordinatesV1 {
            identity: successor_reference.foundation_identity.clone(),
            public_key: successor_reference.foundation_public_key,
            key_generation: successor_reference.foundation_key_generation,
            key_generation_identity: successor_reference
                .foundation_key_generation_identity
                .clone(),
            custody_identity: successor_reference.foundation_custody_identity.clone(),
        };
        let route = match succession.mode {
            CurrentSignerBindingModeV1::NormalSuccessor => PreparedSuccessorRouteV1::Healthy,
            CurrentSignerBindingModeV1::RestoreSuccessor => PreparedSuccessorRouteV1::Restore,
            CurrentSignerBindingModeV1::RecoverySuccessor => PreparedSuccessorRouteV1::Recovery,
            CurrentSignerBindingModeV1::Initial => {
                return Err(DurableTerminalResolutionRefusalV1::Malformed);
            }
        };
        let historical = if succession.mode == CurrentSignerBindingModeV1::RestoreSuccessor {
            let reference = load_restore_historical_reference_v1(
                transaction,
                root,
                &predecessor.binding,
                &predecessor_enrollment,
                root.binding_id(),
                root.generation_commitment_digest(),
                &succession.predecessor,
                predecessor.binding.effective_cut(),
                &successor_reference,
            )
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
            if succession.historical_foundation_identity.as_ref()
                != Some(&reference.historical_foundation_identity)
            {
                return Err(DurableTerminalResolutionRefusalV1::Malformed);
            }
            Some(StableFoundationCoordinatesV1 {
                identity: reference.historical_foundation_identity,
                public_key: reference.historical_public_key,
                key_generation: reference.historical_key_generation,
                key_generation_identity: reference.historical_key_generation_identity,
                custody_identity: reference.historical_custody_identity,
            })
        } else {
            None
        };
        if succession.mode == CurrentSignerBindingModeV1::RecoverySuccessor {
            verify_recovery_grant_reference_v1(
                transaction,
                root,
                &predecessor.binding,
                &predecessor_enrollment,
                &successor_reference,
            )
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        }
        if matches!(
            route,
            PreparedSuccessorRouteV1::Healthy | PreparedSuccessorRouteV1::Recovery
        ) {
            refuse_reused_new_foundation_v1(
                transaction,
                &successor_coordinates.identity,
                &successor_reference.adoption_identity,
            )
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        }
        if !verify_stable_foundation_route_law_v1(
            &route,
            &succession.predecessor,
            predecessor_enrollment.adoption().identity(),
            &predecessor_coordinates,
            &successor_reference.lineage_reference_identity,
            &successor_coordinates,
            historical.as_ref(),
        ) {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        let consumed = load_consumed_pending_msg12_by_effect_v1(
            transaction,
            &succession.persisted_resolution_identity,
        )?;
        let pending = load_verified_pending_msg12_reference_v1(transaction, &consumed)
            .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        match route {
            PreparedSuccessorRouteV1::Healthy => {
                verify_healthy_pending_msg12_completed_append_is_exact_msg11_v1(
                    transaction,
                    &pending,
                )
                .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
            }
            PreparedSuccessorRouteV1::Restore | PreparedSuccessorRouteV1::Recovery => {
                verify_discontinuity_pending_msg12_completed_effect_v1(
                    transaction,
                    route,
                    &successor_reference.authority_reference_identity,
                    &pending,
                )
                .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
            }
        }
        let zero_semantic_input = [
            &pending.selected_transition_input_identity,
            &pending.completed_append_identity,
            &pending.complete_candidate_set_identity,
            &pending.pending_successor_resolution_identity,
        ]
        .into_iter()
        .any(|identity| {
            digest_bytes(identity).is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0))
        });
        let expected_signing_key_generation = signer_message_key_generation_identity_v1(
            &successor_reference.proposal_identity,
            successor_reference.foundation_key_generation,
        );
        if pending.signer_public_key != successor_reference.foundation_public_key
            || pending.signer_key_generation_identity
                != expected_signing_key_generation
            || pending.occurrence_identity != successor_reference.occurrence_identity
            || pending.physical_generation_identity
                != successor_reference.physical_generation_identity
            || pending.lifecycle_root_identity != successor_reference.lifecycle_root_identity
            || pending.scope_identity != successor_reference.signer_scope_identity
            || pending.transaction_intent_identity != successor_reference.transition_identity
            || pending.active_policy_identity != successor_reference.policy_basis_identity
            || pending.attempt_identity != successor_reference.attempt_identity
            || pending.selected_transition_input_identity != successor_reference.transition_identity
            || pending.event_cut <= successor_reference.accepted_cut
            || pending.event_cut >= successor.binding.effective_cut()
            || zero_semantic_input
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        let candidate_sets = {
            let mut statement = transaction.prepare(
                "SELECT terminal_candidate_set_identity
                 FROM c2_signer_lineage_projection
                 WHERE root_binding_identity = ?1
                   AND terminal_binding_identity = ?2",
            )?;
            statement
                .query_map(
                    params![
                        root.binding_id().as_str(),
                        successor.binding.binding_id().as_str()
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        if candidate_sets.len() != 1
            || parse_digest(&candidate_sets[0])? != pending.complete_candidate_set_identity
        {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
        let expected = semantic_digest(&SuccessorCompletionIdentityBodyV1 {
            schema: "nq.c2_signer_succession_completion.v1",
            identity_domain: "nq.c2.signer_succession_completion.identity.v1",
            root_binding_identity: root.binding_id(),
            predecessor_binding_identity: &succession.predecessor,
            successor_binding_identity: &succession.successor,
            signer_enrollment_identity: &parse_digest(successor.binding.enrollment_id())?,
            transition_identity: &succession.transition_identity,
            receipt_identity: &succession.receipt_identity,
            append_identity: &succession.append_identity,
            persisted_resolution_identity: &succession.persisted_resolution_identity,
            selected_transition_input_identity: &pending.selected_transition_input_identity,
            completed_append_identity: &pending.completed_append_identity,
            complete_candidate_set_identity: &pending.complete_candidate_set_identity,
            pending_successor_resolution_identity: &pending.pending_successor_resolution_identity,
            effective_cut: successor.binding.effective_cut(),
        })
        .map_err(|_| DurableTerminalResolutionRefusalV1::Malformed)?;
        if expected != succession.completion_identity {
            return Err(DurableTerminalResolutionRefusalV1::Malformed);
        }
    }
    Ok(())
}

impl From<HealthySuccessorTerminalAppendV1> for PreparedSuccessorTerminalAppendV1 {
    fn from(input: HealthySuccessorTerminalAppendV1) -> Self {
        Self {
            ready: input.ready,
            enrollment: input.enrollment,
            pending_msg12: input.pending_msg12,
            route: PreparedSuccessorRouteV1::Healthy,
        }
    }
}

impl From<RestoreSuccessorTerminalAppendV1> for PreparedSuccessorTerminalAppendV1 {
    fn from(input: RestoreSuccessorTerminalAppendV1) -> Self {
        Self {
            ready: input.ready,
            enrollment: input.enrollment,
            pending_msg12: input.pending_msg12,
            route: PreparedSuccessorRouteV1::Restore,
        }
    }
}

impl From<RecoverySuccessorTerminalAppendV1> for PreparedSuccessorTerminalAppendV1 {
    fn from(input: RecoverySuccessorTerminalAppendV1) -> Self {
        Self {
            ready: input.ready,
            enrollment: input.enrollment,
            pending_msg12: input.pending_msg12,
            route: PreparedSuccessorRouteV1::Recovery,
        }
    }
}

fn text_coordinate_digest(domain: &[u8], value: &str) -> Sha256Digest {
    let mut preimage = Vec::with_capacity(domain.len() + value.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(value.as_bytes());
    sha256_bytes(&preimage)
}

/// Re-derive the key-generation identity carried by typed signer messages.
///
/// This is deliberately distinct from the stable foundation's
/// `(public-key, ordinal)` identity. Custody binds each signing generation to
/// the exact proposal which created it, while the stable foundation record
/// separately records the semantic key-generation coordinate. The terminal
/// join must verify both identities without conflating them.
fn signer_message_key_generation_identity_v1(
    proposal_identity: &Sha256Digest,
    key_generation: u64,
) -> Sha256Digest {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"nq.c2.store_integrity_key_generation.identity.v1\0");
    preimage.extend_from_slice(proposal_identity.as_str().as_bytes());
    preimage.extend_from_slice(&key_generation.to_be_bytes());
    sha256_bytes(&preimage)
}

fn digest_from_identity_bytes(
    bytes: &[u8],
) -> Result<Sha256Digest, DurableTerminalAppendRefusalV1> {
    let identity: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    Sha256Digest::parse(format!("sha256:{}", hex::encode(identity)))
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
}

fn pending_input_digest(
    input: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Sha256Digest, DurableTerminalAppendRefusalV1> {
    let value = input
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    Sha256Digest::parse(value.to_owned())
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
}

/// Reload and cryptographically reverify the exact durable pending MSG-12.
///
/// The consumed frame is only an inert lookup receipt. Candidate selection
/// and completion coordinates are always recovered from the authenticated
/// canonical carrier; callers cannot supply them as digest parameters.
fn load_verified_pending_msg12_reference_v1(
    transaction: &Transaction<'_>,
    consumed: &ConsumedSignedFrameV1,
) -> Result<VerifiedPendingMsg12ReferenceV1, DurableTerminalAppendRefusalV1> {
    if consumed.family != ClosedMessageFamilyV1::Msg12PolicyTransitionReceipt
        || consumed.route != C2StoreSigningRouteV1::Msg12ReceiptPending
    {
        return Err(DurableTerminalAppendRefusalV1::RouteMismatch);
    }
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT ledger_sequence, generation_sequence, append_identity,
                    message_identity, family, route,
                    signer_key_generation_identity, resulting_frontier_identity,
                    effect_receipt_identity, canonical_message,
                    canonical_message_sha256, physical_carrier_bytes,
                    physical_carrier_sha256, physical_carrier_length
             FROM c2_signer_message_appends
             WHERE ledger_sequence = ?1 AND effect_receipt_identity = ?2",
        )?;
        statement
            .query_map(
                params![consumed.ledger_sequence, consumed.effect_receipt_identity],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<u64>>(13)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != 1 {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let row = &rows[0];
    let carrier = row
        .11
        .as_deref()
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let verified_carrier = verify_durable_signer_carrier_envelope_v1(carrier)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let message_identity = digest_from_identity_bytes(&row.3)?;
    let signer_key_generation = digest_from_identity_bytes(&row.6)?;
    let resulting_frontier = digest_from_identity_bytes(&row.7)?;
    let consumed_message = digest_from_identity_bytes(&consumed.message_identity)?;
    let consumed_key_generation = digest_from_identity_bytes(&consumed.signer_key_generation)?;
    let consumed_frontier = digest_from_identity_bytes(&consumed.resulting_frontier_identity)?;
    let verified_message = digest_from_identity_bytes(&verified_carrier.message_identity())?;
    let verified_key_generation =
        digest_from_identity_bytes(&verified_carrier.signer_key_generation_identity())?;
    let verified_frontier =
        digest_from_identity_bytes(&verified_carrier.resulting_frontier_identity())?;
    let append_identity = parse_digest(&row.2)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let effect_receipt_identity = parse_digest(&row.8)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    if row.0 != consumed.ledger_sequence
        || row.1 != consumed.generation_sequence
        || row.2 != consumed.append_identity
        || message_identity != consumed_message
        || row.4 != ClosedMessageFamilyV1::Msg12PolicyTransitionReceipt.as_str()
        || row.5 != C2StoreSigningRouteV1::Msg12ReceiptPending.as_str()
        || signer_key_generation != consumed_key_generation
        || resulting_frontier != consumed_frontier
        || row.8 != consumed.effect_receipt_identity
        || verified_carrier.route() != C2StoreSigningRouteV1::Msg12ReceiptPending
        || verified_carrier.ledger_sequence() != row.0
        || verified_carrier.generation_sequence() != row.1
        || verified_carrier.append_identity() != row.2
        || verified_message != message_identity
        || verified_key_generation != signer_key_generation
        || verified_frontier != resulting_frontier
        || verified_carrier.effect_receipt_identity() != row.8
        || verified_carrier.canonical_message() != row.9
        || parse_digest(&row.10)
            .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?
            != sha256_bytes(&row.9)
        || row.12.as_deref() != Some(sha256_bytes(carrier).as_str())
        || row.13 != Some(carrier.len() as u64)
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let message: Value = serde_json::from_slice(&row.9)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    if canonical_json_bytes(&message)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?
        != row.9
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let input = message
        .get("verified_input")
        .and_then(Value::as_object)
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let expected_fields = BTreeSet::from([
        "input_kind",
        "selected_transition_input_identity",
        "completed_append_identity",
        "complete_candidate_set_identity",
        "pending_successor_resolution_identity",
    ]);
    if input.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields
        || input.get("input_kind").and_then(Value::as_str)
            != Some("transition_receipt_pending_facts")
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let coordinates = message
        .get("coordinates")
        .and_then(Value::as_object)
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let coordinate_digest = |field: &str| {
        coordinates
            .get(field)
            .and_then(Value::as_str)
            .and_then(|identity| Sha256Digest::parse(identity.to_owned()).ok())
            .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
    };
    let pending_input = |field: &str| pending_input_digest(input, field);
    Ok(VerifiedPendingMsg12ReferenceV1 {
        ledger_sequence: row.0,
        event_cut: verified_carrier.event_cut(),
        message_identity,
        append_identity,
        effect_receipt_identity,
        signer_public_key: verified_carrier.signer_public_key(),
        signer_key_generation_identity: verified_key_generation,
        occurrence_identity: coordinate_digest("occurrence")?,
        physical_generation_identity: coordinate_digest("physical_generation")?,
        lifecycle_root_identity: coordinate_digest("lifecycle_root")?,
        scope_identity: coordinate_digest("scope_identity")?,
        transaction_intent_identity: coordinate_digest("transaction_intent_identity")?,
        active_policy_identity: coordinate_digest("active_store_policy_identity")?,
        attempt_identity: coordinate_digest("attempt_identity")?,
        selected_transition_input_identity: pending_input("selected_transition_input_identity")?,
        completed_append_identity: pending_input("completed_append_identity")?,
        complete_candidate_set_identity: pending_input("complete_candidate_set_identity")?,
        pending_successor_resolution_identity: pending_input(
            "pending_successor_resolution_identity",
        )?,
    })
}

/// Re-resolve the healthy route's MSG-12 completed-append coordinate to one
/// exact authenticated durable MSG-11.  MSG-12 is not allowed to make an
/// arbitrary nonzero append digest terminal merely by naming it: the named
/// row must be the closed current-predecessor policy-transition-intent route,
/// carry the same transition and Store scope, and precede the pending
/// successor receipt.
fn verify_healthy_pending_msg12_completed_append_is_exact_msg11_v1(
    transaction: &Transaction<'_>,
    pending: &VerifiedPendingMsg12ReferenceV1,
) -> Result<(), DurableTerminalAppendRefusalV1> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT ledger_sequence, generation_sequence, append_identity,
                    message_identity, family, route,
                    signer_key_generation_identity, resulting_frontier_identity,
                    effect_receipt_identity, canonical_message,
                    canonical_message_sha256, physical_carrier_bytes,
                    physical_carrier_sha256, physical_carrier_length
             FROM c2_signer_message_appends
             WHERE append_identity = ?1",
        )?;
        statement
            .query_map([pending.completed_append_identity.as_str()], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<u64>>(13)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != 1 {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let row = &rows[0];
    if row.2 != pending.completed_append_identity.as_str()
        || row.4 != ClosedMessageFamilyV1::Msg11PolicyTransitionIntent.as_str()
        || row.5 != C2StoreSigningRouteV1::Msg11PolicyTransitionIntent.as_str()
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let carrier = row
        .11
        .as_deref()
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let verified_carrier = verify_durable_signer_carrier_envelope_v1(carrier)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let message_identity = digest_from_identity_bytes(&row.3)?;
    let signer_key_generation = digest_from_identity_bytes(&row.6)?;
    let resulting_frontier = digest_from_identity_bytes(&row.7)?;
    let verified_message = digest_from_identity_bytes(&verified_carrier.message_identity())?;
    let verified_key_generation =
        digest_from_identity_bytes(&verified_carrier.signer_key_generation_identity())?;
    let verified_frontier =
        digest_from_identity_bytes(&verified_carrier.resulting_frontier_identity())?;
    if verified_carrier.route() != C2StoreSigningRouteV1::Msg11PolicyTransitionIntent
        || verified_carrier.ledger_sequence() != row.0
        || verified_carrier.generation_sequence() != row.1
        || verified_carrier.append_identity() != row.2
        || verified_message != message_identity
        || verified_key_generation != signer_key_generation
        || verified_frontier != resulting_frontier
        || verified_carrier.effect_receipt_identity() != row.8
        || verified_carrier.canonical_message() != row.9
        || parse_digest(&row.10)
            .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?
            != sha256_bytes(&row.9)
        || row.12.as_deref() != Some(sha256_bytes(carrier).as_str())
        || row.13 != Some(carrier.len() as u64)
        || verified_carrier.event_cut() >= pending.event_cut
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }

    let message: Value = serde_json::from_slice(&row.9)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    if canonical_json_bytes(&message)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?
        != row.9
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let input = message
        .get("verified_input")
        .and_then(Value::as_object)
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let expected_fields = BTreeSet::from([
        "input_kind",
        "transition_mode_identity",
        "mandatory_rotation_continuity_message_identity",
        "policy_continuity_or_unchanged_proof_identity",
        "predecessor_successor_keys_identity",
        "exact_transition_frontier_and_cuts_identity",
    ]);
    if input.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields
        || input.get("input_kind").and_then(Value::as_str)
            != Some("policy_transition_intent_facts")
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    let mandatory_msg06 = pending_input_digest(
        input,
        "mandatory_rotation_continuity_message_identity",
    )?;
    let policy_continuity = pending_input_digest(
        input,
        "policy_continuity_or_unchanged_proof_identity",
    )?;
    let coordinates = message
        .get("coordinates")
        .and_then(Value::as_object)
        .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let coordinate_digest = |field: &str| {
        coordinates
            .get(field)
            .and_then(Value::as_str)
            .and_then(|identity| Sha256Digest::parse(identity.to_owned()).ok())
            .ok_or(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
    };
    if coordinate_digest("occurrence")? != pending.occurrence_identity
        || coordinate_digest("physical_generation")? != pending.physical_generation_identity
        || coordinate_digest("lifecycle_root")? != pending.lifecycle_root_identity
        || coordinate_digest("scope_identity")? != pending.scope_identity
        || coordinate_digest("transaction_intent_identity")?
            != pending.transaction_intent_identity
        || [mandatory_msg06, policy_continuity]
            .iter()
            .any(|identity| {
                digest_bytes(identity).is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0))
            })
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    Ok(())
}

/// Re-resolve a discontinuity MSG-12 completed-effect coordinate to the one
/// exact governed ingress effect consumed by its adopted foundation.  A
/// nonzero digest, an effect from the sibling route, or another occurrence of
/// the same route is never a sufficient terminal referent.
fn verify_discontinuity_pending_msg12_completed_effect_v1(
    transaction: &Transaction<'_>,
    route: PreparedSuccessorRouteV1,
    authority_reference_identity: &Sha256Digest,
    pending: &VerifiedPendingMsg12ReferenceV1,
) -> Result<(), DurableTerminalAppendRefusalV1> {
    let (expected_route, expected_family) = match route {
        PreparedSuccessorRouteV1::Restore => ("msg13_restore_authorization", "MSG-13"),
        PreparedSuccessorRouteV1::Recovery => ("msg15_recovery_grant", "MSG-15"),
        PreparedSuccessorRouteV1::Healthy => {
            return Err(DurableTerminalAppendRefusalV1::RouteMismatch);
        }
    };
    let authority_bytes = digest_bytes(authority_reference_identity)
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT route, family, effect_identity
             FROM c2_external_carrier_ingress
             WHERE route = ?1 AND carrier_identity = ?2",
        )?;
        statement
            .query_map(params![expected_route, authority_bytes.as_slice()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != 1
        || rows[0].0 != expected_route
        || rows[0].1 != expected_family
        || parse_digest(&rows[0].2)
            .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?
            != pending.completed_append_identity
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    Ok(())
}

fn required_json_digest(
    value: &Value,
    field: &str,
) -> Result<Sha256Digest, DurableTerminalAppendRefusalV1> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|identity| Sha256Digest::parse(identity.to_owned()).ok())
        .ok_or(DurableTerminalAppendRefusalV1::FoundationMismatch)
}

fn refuse_reused_new_foundation_v1(
    transaction: &Transaction<'_>,
    proposed_foundation_identity: &Sha256Digest,
    proposed_adoption_identity: &Sha256Digest,
) -> Result<(), DurableTerminalAppendRefusalV1> {
    let adoptions = {
        let mut statement = transaction.prepare(
            "SELECT adoption_identity, lineage
             FROM c2_foundational_enrollment_adoptions
             WHERE foundation_identity = ?1
             ORDER BY adoption_sequence",
        )?;
        statement
            .query_map([proposed_foundation_identity.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if adoptions.len() != 1
        || adoptions[0].0 != proposed_adoption_identity.as_str()
        || !matches!(
            adoptions[0].1.as_str(),
            "ordinarySuccessorContinuity" | "recoveryNewFoundation"
        )
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    Ok(())
}

/// Recompute the durable semantic identity of the Store-derived
/// discontinuity condition.  Process-local entry authority is intentionally
/// absent; this verifies only the exact durable premise retained by the
/// adoption.  Revoked branches must still resolve one exact validated MSG-14
/// effect.  The active-lost branch is an operational custody observation made
/// by the live actor and is represented durably by its closed semantic tag.
fn durable_discontinuity_condition_identity_v1(
    transaction: &Transaction<'_>,
    route: PreparedSuccessorRouteV1,
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentSignerGenerationBindingV1,
    predecessor_enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    predecessor_status: Option<&str>,
) -> Result<Sha256Digest, DurableTerminalAppendRefusalV1> {
    let current_public_key = predecessor_enrollment.foundation().public_key()?;
    let current_key_generation = predecessor
        .key_generation()
        .parse::<u64>()
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    if current_key_generation != predecessor_enrollment.foundation().key_generation()
        || predecessor.enrollment_id() != predecessor_enrollment.acceptance().identity().as_str()
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let current_binding = digest_bytes(predecessor.binding_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let (route_coordinate, condition_coordinate) = match (route, predecessor_status) {
        (PreparedSuccessorRouteV1::Restore, None)
        | (PreparedSuccessorRouteV1::Recovery, Some("inactive_revoked")) => {
            match refuse_if_current_signer_revoked_v1(
                transaction,
                root.physical_store_generation(),
                root.lifecycle_root_id(),
                root.scope_id(),
                predecessor.enrollment_id(),
                &current_public_key,
                current_key_generation,
                predecessor.standing_id(),
            ) {
                Err(C2ExternalIngressRefusalV1::CurrentSignerRevoked) => {}
                _ => return Err(DurableTerminalAppendRefusalV1::FoundationMismatch),
            }
            let rows = {
                let mut statement = transaction.prepare(
                    "SELECT effect_receipt_identity FROM c2_revocation_effects
                     WHERE physical_generation_identity = ?1
                       AND lifecycle_root_identity = ?2 AND scope_identity = ?3
                       AND target_enrollment_identity = ?4 AND target_public_key = ?5
                       AND target_key_generation = ?6 AND target_standing_identity = ?7",
                )?;
                statement
                    .query_map(
                        params![
                            root.physical_store_generation(),
                            root.lifecycle_root_id(),
                            root.scope_id(),
                            predecessor.enrollment_id(),
                            current_public_key.as_slice(),
                            current_key_generation,
                            predecessor.standing_id(),
                        ],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?
            };
            if rows.len() != 1 {
                return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
            }
            let effect = parse_digest(&rows[0])
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
            (
                match route {
                    PreparedSuccessorRouteV1::Restore => b"restore".as_slice(),
                    PreparedSuccessorRouteV1::Recovery => b"recovery".as_slice(),
                    PreparedSuccessorRouteV1::Healthy => unreachable!(),
                },
                effect.as_str().as_bytes().to_vec(),
            )
        }
        (PreparedSuccessorRouteV1::Recovery, Some("active_lost")) => (
            b"recovery".as_slice(),
            b"ordinary_current_custody_unavailable".to_vec(),
        ),
        _ => return Err(DurableTerminalAppendRefusalV1::RouteMismatch),
    };
    Ok(digest_fields(
        b"nq.c2.store_verified_discontinuity_eligibility.identity.v1\0",
        &[
            route_coordinate,
            condition_coordinate.as_slice(),
            &current_binding,
        ],
    ))
}

/// Resolve the exact historical terminal selected by the durable MSG-13
/// occurrence. The displaced current terminal is only the adjacent graph
/// predecessor; it is not silently treated as the historical foundation.
fn load_restore_historical_reference_v1(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentSignerGenerationBindingV1,
    predecessor_enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    root_binding_identity: &Sha256Digest,
    generation_commitment_identity: &Sha256Digest,
    predecessor_binding_identity: &Sha256Digest,
    predecessor_cut: u64,
    adoption: &VerifiedDurableEnrollmentReferenceV1,
) -> Result<VerifiedRestoreHistoricalReferenceV1, DurableTerminalAppendRefusalV1> {
    verify_durable_restore_authorization_identity_v1(
        transaction,
        adoption.authority_reference_identity.as_str(),
    )
    .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let authority_bytes = digest_bytes(&adoption.authority_reference_identity)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT request_identity, carrier_identity, canonical_request,
                    canonical_request_sha256, canonical_carrier,
                    canonical_carrier_sha256, family, route
             FROM c2_external_carrier_ingress
             WHERE route = 'msg13_restore_authorization'
               AND carrier_identity = ?1",
        )?;
        statement
            .query_map([authority_bytes.as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != 1 {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let row = &rows[0];
    if row.0.len() != 32
        || row.1.as_slice() != authority_bytes
        || row.6 != "MSG-13"
        || row.7 != "msg13_restore_authorization"
        || parse_digest(&row.3).map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
            != sha256_bytes(&row.2)
        || parse_digest(&row.5).map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
            != sha256_bytes(&row.4)
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let request: Value = serde_json::from_slice(&row.2)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let carrier: Value = serde_json::from_slice(&row.4)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    if canonical_json_bytes(&request)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
        != row.2
        || canonical_json_bytes(&carrier)
            .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
            != row.4
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let request_identity = required_json_digest(&request, "restore_request_identity")?;
    let row_request_identity = digest_from_identity_bytes(&row.0)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    if request_identity != row_request_identity
        || required_json_digest(&carrier, "restore_request_identity")? != request_identity
        || required_json_digest(&carrier, "restore_authorization_identity")?
            != adoption.authority_reference_identity
        || [
            "target_signer_enrollment_identity",
            "predecessor_current_signer_binding_identity",
            "restore_declaration_identity",
        ]
        .into_iter()
        .any(|field| carrier.get(field) != request.get(field))
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let historical_enrollment_identity =
        required_json_digest(&request, "target_signer_enrollment_identity")?;
    let restore_lineage_identity = required_json_digest(&request, "restore_declaration_identity")?;
    if required_json_digest(&request, "predecessor_current_signer_binding_identity")?
        != *predecessor_binding_identity
    {
        return Err(DurableTerminalAppendRefusalV1::StalePredecessor);
    }
    let restore_cut = required_json_u64(&request, "restore_cut")?;
    let authority_identity_bytes = digest_bytes(&adoption.authority_reference_identity)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let proposal_identity_bytes = digest_bytes(&adoption.proposal_identity)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let transition_identity_bytes = digest_bytes(&adoption.transition_identity)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let expected_challenge = digest_fields(
        b"nq.c2.restore.successor_pop_challenge.identity.v1\0",
        &[
            &authority_identity_bytes,
            &proposal_identity_bytes,
            &transition_identity_bytes,
        ],
    );
    let expected_discontinuity_condition = durable_discontinuity_condition_identity_v1(
        transaction,
        PreparedSuccessorRouteV1::Restore,
        root,
        predecessor,
        predecessor_enrollment,
        None,
    )?;
    let expected_transaction = digest_fields(
        b"nq.c2.restore.foundation_transaction.identity.v1\0",
        &[
            &digest_bytes(&request_identity)
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?,
            &authority_identity_bytes,
            &digest_bytes(&restore_lineage_identity)
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?,
            adoption.lineage_reference_identity.as_str().as_bytes(),
            adoption
                .adoption_pre_effect_store_snapshot_identity
                .as_str()
                .as_bytes(),
        ],
    );
    if required_json_digest(&request, "physical_store_generation_identity")?
        != adoption.physical_generation_identity
        || required_json_digest(&request, "signer_lifecycle_root_identity")?
            != adoption.lifecycle_root_identity
        || required_json_digest(&request, "scope_identity")? != adoption.signer_scope_identity
        || required_json_digest(&request, "active_store_policy_identity")?
            != adoption.policy_basis_identity
        || required_json_digest(&request, "predecessor_physical_store_generation_identity")?
            != adoption.physical_generation_identity
        || required_json_digest(&request, "predecessor_generation_commitment_identity")?
            != *generation_commitment_identity
        || required_json_digest(&request, "target_restore_proposal_identity")?
            != adoption.transition_identity
        || required_json_digest(&request, "target_signer_proposal_identity")?
            != adoption.proposal_identity
        || required_json_digest(&request, "target_custody_binding_identity")?
            != adoption.foundation_custody_identity
        || expected_discontinuity_condition != adoption.applicability_basis_identity
        || expected_challenge != adoption.challenge_identity
        || expected_transaction != adoption.transaction_identity
        || required_json_u64(&request, "proposed_effect_cut")? != restore_cut
        // MSG-13/15 entry is R, MSG-07 is signed at R+1, and the
        // foundational adoption occurs at R+2. Signer acceptance is the
        // distinct later R+3 cut and is checked through the durable
        // enrollment reference, not conflated with the adoption event.
        || discontinuity_foundation_adoption_cut_v1(restore_cut)
            != Some(adoption.enrollment_cut)
        || request.get("disposition").and_then(Value::as_str)
            != Some("restore_successor_authorized")
        || request
            .get("quarantine_remains_closed")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }

    let historical_bindings = {
        let mut statement = transaction.prepare(
            "SELECT binding.current_binding_identity, binding.effective_cut
             FROM c2_signer_current_binding_projection AS binding
             JOIN c2_signer_lineage_completion_projection AS completion
               ON completion.terminal_binding_identity = binding.current_binding_identity
             WHERE binding.root_binding_identity = ?1
               AND binding.current_enrollment_identity = ?2",
        )?;
        statement
            .query_map(
                params![
                    root_binding_identity.as_str(),
                    historical_enrollment_identity.as_str(),
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if historical_bindings.len() != 1 {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    if historical_bindings[0].1 > predecessor_cut {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let historical_binding_identity = parse_digest(&historical_bindings[0].0)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    if historical_binding_identity != *predecessor_binding_identity
        || historical_enrollment_identity
            != parse_digest(predecessor.enrollment_id())
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
    {
        return Err(DurableTerminalAppendRefusalV1::StalePredecessor);
    }
    let historical =
        load_verified_durable_signer_enrollment_v1(transaction, &historical_enrollment_identity)?;
    if adoption.lineage_reference_identity != *historical.foundation().identity() {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    Ok(VerifiedRestoreHistoricalReferenceV1 {
        restore_lineage_identity,
        historical_binding_identity,
        historical_enrollment_identity,
        historical_foundation_identity: historical.foundation().identity().clone(),
        historical_public_key: historical.foundation().public_key()?,
        historical_key_generation: historical.foundation().key_generation(),
        historical_key_generation_identity: historical.adoption().key_generation_identity().clone(),
        historical_custody_identity: historical.foundation().custody_evidence_identity().clone(),
    })
}

fn required_json_u64(value: &Value, field: &str) -> Result<u64, DurableTerminalAppendRefusalV1> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(DurableTerminalAppendRefusalV1::FoundationMismatch)
}

fn required_json_public_key(
    value: &Value,
    field: &str,
) -> Result<[u8; 32], DurableTerminalAppendRefusalV1> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|key| hex::decode(key).ok())
        .and_then(|key| key.try_into().ok())
        .ok_or(DurableTerminalAppendRefusalV1::FoundationMismatch)
}

/// Rejoin the durably authenticated MSG-15 grant to the exact displaced
/// predecessor and exact newly adopted recovery foundation.
///
/// The sibling verifier establishes canonical request/carrier identity,
/// pair correspondence, route and signature.  These checks establish the
/// lifecycle-specific joins that cannot be inferred from possession of the
/// grant digest alone.
fn verify_recovery_grant_reference_v1(
    transaction: &Transaction<'_>,
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentSignerGenerationBindingV1,
    predecessor_enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    adoption: &VerifiedDurableEnrollmentReferenceV1,
) -> Result<(), DurableTerminalAppendRefusalV1> {
    verify_durable_recovery_grant_identity_v1(
        transaction,
        adoption.authority_reference_identity.as_str(),
    )
    .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let authority_bytes = digest_bytes(&adoption.authority_reference_identity)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let request_bytes: Vec<u8> = transaction
        .query_row(
            "SELECT canonical_request FROM c2_external_carrier_ingress
             WHERE route = 'msg15_recovery_grant' AND carrier_identity = ?1",
            [authority_bytes.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let request: Value = serde_json::from_slice(&request_bytes)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    if canonical_json_bytes(&request)
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
        != request_bytes
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    let predecessor_enrollment_identity = parse_digest(predecessor.enrollment_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let predecessor_standing_identity = parse_digest(predecessor.standing_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let predecessor_key_generation = predecessor
        .key_generation()
        .parse::<u64>()
        .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let predecessor_public_key = predecessor_enrollment.foundation().public_key()?;
    let predecessor_status = request
        .get("predecessor_status")
        .and_then(Value::as_str)
        .ok_or(DurableTerminalAppendRefusalV1::FoundationMismatch)?;
    let expected_recovery_condition = durable_discontinuity_condition_identity_v1(
        transaction,
        PreparedSuccessorRouteV1::Recovery,
        root,
        predecessor,
        predecessor_enrollment,
        Some(predecessor_status),
    )?;
    let recovery_request_identity = required_json_digest(&request, "recovery_request_identity")?;
    let expected_transaction = digest_fields(
        b"nq.c2.recovery.foundation_transaction.identity.v1\0",
        &[
            &digest_bytes(&recovery_request_identity)
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?,
            &authority_bytes,
            &digest_bytes(&expected_recovery_condition)
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?,
            &digest_bytes(&adoption.proposal_identity)
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?,
            adoption
                .adoption_pre_effect_store_snapshot_identity
                .as_str()
                .as_bytes(),
        ],
    );
    if required_json_digest(&request, "physical_store_generation_identity")?
        != adoption.physical_generation_identity
        || required_json_digest(&request, "signer_lifecycle_root_identity")?
            != adoption.lifecycle_root_identity
        || required_json_digest(&request, "scope_identity")? != adoption.signer_scope_identity
        || required_json_digest(&request, "recovery_predecessor_binding_identity")?
            != *predecessor.binding_id()
        || required_json_digest(&request, "predecessor_enrollment_identity")?
            != predecessor_enrollment_identity
        || required_json_public_key(&request, "predecessor_public_key")? != predecessor_public_key
        || required_json_u64(&request, "predecessor_key_generation")? != predecessor_key_generation
        || required_json_digest(&request, "predecessor_standing_identity")?
            != predecessor_standing_identity
        || required_json_digest(&request, "last_completed_lifecycle_receipt_identity")?
            != parse_digest(predecessor.persisted_resolution_id())
                .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
        || required_json_digest(&request, "successor_proposal_identity")?
            != adoption.proposal_identity
        || required_json_digest(&request, "successor_custody_binding_identity")?
            != adoption.foundation_custody_identity
        || required_json_public_key(&request, "successor_public_key")?
            != adoption.foundation_public_key
        || required_json_u64(&request, "successor_key_generation")?
            != adoption.foundation_key_generation
        || required_json_digest(&request, "successor_pop_challenge_identity")?
            != adoption.challenge_identity
        || required_json_digest(&request, "recovery_successor_projection_identity")?
            != adoption.transition_identity
        || required_json_digest(&request, "active_store_policy_identity")?
            != adoption.policy_basis_identity
        || expected_recovery_condition != adoption.applicability_basis_identity
        || expected_transaction != adoption.transaction_identity
        || discontinuity_foundation_adoption_cut_v1(required_json_u64(
            &request,
            "proposed_effect_cut",
        )?)
            != Some(adoption.enrollment_cut)
        || request.get("successor_pop_family").and_then(Value::as_str)
            != Some("nq.c2_store_integrity_successor_pop.v1")
        || !matches!(predecessor_status, "active_lost" | "inactive_revoked")
        || request.get("disposition").and_then(Value::as_str) != Some("recovery_authorized")
        || parse_digest(root.physical_store_generation())
            .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
            != adoption.physical_generation_identity
        || parse_digest(root.lifecycle_root_id())
            .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
            != adoption.lifecycle_root_identity
        || parse_digest(root.scope_id())
            .map_err(|_| DurableTerminalAppendRefusalV1::FoundationMismatch)?
            != adoption.signer_scope_identity
    {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }
    Ok(())
}

fn same_durable_terminal(
    left: &StoreVerifiedDurableGenerationCurrentV1,
    right: &StoreVerifiedDurableGenerationCurrentV1,
) -> bool {
    left.root().binding_id() == right.root().binding_id()
        && left.initial_binding().binding_id() == right.initial_binding().binding_id()
        && left.terminal_binding().binding_id() == right.terminal_binding().binding_id()
        && left.terminal_public_key() == right.terminal_public_key()
        && left.lineage_identity() == right.lineage_identity()
        && left.lineage_completion_identity() == right.lineage_completion_identity()
        && left.terminal_candidate_set_identity() == right.terminal_candidate_set_identity()
        && left.succession_identities() == right.succession_identities()
        && left.terminal_resolution_ledger_sequence() == right.terminal_resolution_ledger_sequence()
        && left.terminal_resolution_message_identity()
            == right.terminal_resolution_message_identity()
        && left.terminal_resolution_append_identity() == right.terminal_resolution_append_identity()
        && left.enrollment().foundation().identity() == right.enrollment().foundation().identity()
        && left.enrollment().adoption().identity() == right.enrollment().adoption().identity()
        && left.enrollment().acceptance().identity() == right.enrollment().acceptance().identity()
}

fn verify_successor_enrollment_join(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    input: &PreparedSuccessorTerminalAppendV1,
) -> Result<VerifiedSuccessorJoinV1, DurableTerminalAppendRefusalV1> {
    let current = input.ready.current();
    let association = input.ready.association();
    let durable = load_verified_durable_signer_enrollment_v1(
        transaction,
        &input.enrollment.signer_enrollment_identity,
    )?;
    if verified_enrollment_reference(&durable)? != input.enrollment {
        return Err(DurableTerminalAppendRefusalV1::ChangedContentCollision);
    }
    let expected_mode = match input.route {
        PreparedSuccessorRouteV1::Healthy => CurrentSignerBindingModeV1::NormalSuccessor,
        PreparedSuccessorRouteV1::Restore => CurrentSignerBindingModeV1::RestoreSuccessor,
        PreparedSuccessorRouteV1::Recovery => CurrentSignerBindingModeV1::RecoverySuccessor,
    };
    verify_prepared_route(
        &input.ready,
        &input.enrollment,
        expected_mode,
        expected_lineage(expected_mode),
    )?;
    let predecessor = prior.terminal_binding();
    let transition_identity = current
        .transition_id()
        .ok_or(DurableTerminalAppendRefusalV1::RouteMismatch)
        .and_then(|identity| {
            parse_digest(identity).map_err(|_| DurableTerminalAppendRefusalV1::RouteMismatch)
        })?;
    let physical_generation = parse_digest(prior.root().physical_store_generation())
        .map_err(|_| DurableTerminalAppendRefusalV1::EnrollmentMismatch)?;
    let lifecycle_root = parse_digest(prior.root().lifecycle_root_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::EnrollmentMismatch)?;
    let scope = parse_digest(prior.root().scope_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::EnrollmentMismatch)?;
    let occurrence = text_coordinate_digest(
        b"nq.c2.store_occurrence.identity.v1\0",
        prior.root().occurrence_id(),
    );
    if current.root_binding_id() != prior.root().binding_id()
        || current.predecessor_binding_id() != Some(predecessor.binding_id())
        || input.enrollment.current_predecessor_identity != *predecessor.binding_id()
        || input.enrollment.transition_identity != transition_identity
        || input.enrollment.physical_generation_identity != physical_generation
        || input.enrollment.lifecycle_root_identity != lifecycle_root
        || input.enrollment.signer_scope_identity != scope
        || input.enrollment.occurrence_identity != occurrence
        || current.effective_cut() <= predecessor.effective_cut()
        || association.resulting_binding_id() != current.binding_id()
    {
        return Err(DurableTerminalAppendRefusalV1::EnrollmentMismatch);
    }

    let predecessor_foundation = prior.enrollment().foundation();
    let successor_foundation = durable.foundation();
    let restore = if matches!(input.route, PreparedSuccessorRouteV1::Restore) {
        Some(load_restore_historical_reference_v1(
            transaction,
            prior.root(),
            predecessor,
            prior.enrollment(),
            prior.root().binding_id(),
            prior.root().generation_commitment_digest(),
            predecessor.binding_id(),
            predecessor.effective_cut(),
            &input.enrollment,
        )?)
    } else {
        None
    };
    let predecessor_coordinates = StableFoundationCoordinatesV1 {
        identity: predecessor_foundation.identity().clone(),
        public_key: predecessor_foundation.public_key()?,
        key_generation: predecessor_foundation.key_generation(),
        key_generation_identity: prior
            .enrollment()
            .adoption()
            .key_generation_identity()
            .clone(),
        custody_identity: predecessor_foundation.custody_evidence_identity().clone(),
    };
    let successor_coordinates = StableFoundationCoordinatesV1 {
        identity: successor_foundation.identity().clone(),
        public_key: successor_foundation.public_key()?,
        key_generation: successor_foundation.key_generation(),
        key_generation_identity: input.enrollment.foundation_key_generation_identity.clone(),
        custody_identity: successor_foundation.custody_evidence_identity().clone(),
    };
    if matches!(input.route, PreparedSuccessorRouteV1::Recovery) {
        verify_recovery_grant_reference_v1(
            transaction,
            prior.root(),
            predecessor,
            prior.enrollment(),
            &input.enrollment,
        )?;
    }
    let historical_coordinates = restore
        .as_ref()
        .map(|historical| StableFoundationCoordinatesV1 {
            identity: historical.historical_foundation_identity.clone(),
            public_key: historical.historical_public_key,
            key_generation: historical.historical_key_generation,
            key_generation_identity: historical.historical_key_generation_identity.clone(),
            custody_identity: historical.historical_custody_identity.clone(),
        });
    if matches!(
        input.route,
        PreparedSuccessorRouteV1::Healthy | PreparedSuccessorRouteV1::Recovery
    ) {
        refuse_reused_new_foundation_v1(
            transaction,
            &successor_coordinates.identity,
            &input.enrollment.adoption_identity,
        )?;
    }
    let foundation_ok = verify_stable_foundation_route_law_v1(
        &input.route,
        predecessor.binding_id(),
        prior.enrollment().adoption().identity(),
        &predecessor_coordinates,
        &input.enrollment.lineage_reference_identity,
        &successor_coordinates,
        historical_coordinates.as_ref(),
    );
    if !foundation_ok {
        return Err(DurableTerminalAppendRefusalV1::FoundationMismatch);
    }

    let resolution = load_verified_pending_msg12_reference_v1(transaction, &input.pending_msg12)?;
    match input.route {
        PreparedSuccessorRouteV1::Healthy => {
            verify_healthy_pending_msg12_completed_append_is_exact_msg11_v1(
                transaction,
                &resolution,
            )?;
        }
        PreparedSuccessorRouteV1::Restore | PreparedSuccessorRouteV1::Recovery => {
            verify_discontinuity_pending_msg12_completed_effect_v1(
                transaction,
                input.route,
                &input.enrollment.authority_reference_identity,
                &resolution,
            )?;
        }
    }
    let receipt_identity = parse_digest(association.receipt_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let zero_semantic_input = [
        &resolution.selected_transition_input_identity,
        &resolution.completed_append_identity,
        &resolution.complete_candidate_set_identity,
        &resolution.pending_successor_resolution_identity,
    ]
    .into_iter()
    .any(|identity| digest_bytes(identity).is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0)));
    let expected_signing_key_generation = signer_message_key_generation_identity_v1(
        &input.enrollment.proposal_identity,
        input.enrollment.foundation_key_generation,
    );
    if receipt_identity != resolution.message_identity
        || association.append_id() != resolution.append_identity.as_str()
        || association.resolution_id() != resolution.effect_receipt_identity.as_str()
        || association.resolution_id() != current.persisted_resolution_id()
        || resolution.signer_public_key != input.enrollment.foundation_public_key
        || resolution.signer_key_generation_identity
            != expected_signing_key_generation
        || resolution.occurrence_identity != input.enrollment.occurrence_identity
        || resolution.physical_generation_identity != input.enrollment.physical_generation_identity
        || resolution.lifecycle_root_identity != input.enrollment.lifecycle_root_identity
        || resolution.scope_identity != input.enrollment.signer_scope_identity
        || resolution.transaction_intent_identity != input.enrollment.transition_identity
        || resolution.active_policy_identity != input.enrollment.policy_basis_identity
        || resolution.attempt_identity != input.enrollment.attempt_identity
        || resolution.selected_transition_input_identity != input.enrollment.transition_identity
        || resolution.event_cut <= input.enrollment.accepted_cut
        || resolution.event_cut >= current.effective_cut()
        || zero_semantic_input
    {
        return Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch);
    }
    Ok(VerifiedSuccessorJoinV1 {
        pending_msg12: resolution,
        restore,
    })
}

fn prepare_successor_projection_plan(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    input: &PreparedSuccessorTerminalAppendV1,
) -> Result<SuccessorProjectionPlanV1, DurableTerminalAppendRefusalV1> {
    let verified = verify_successor_enrollment_join(transaction, prior, input)?;
    let pending_msg12 = &verified.pending_msg12;
    let successor = input.ready.current().clone();
    let association = input.ready.association();
    let transition_identity = parse_digest(
        successor
            .transition_id()
            .ok_or(DurableTerminalAppendRefusalV1::RouteMismatch)?,
    )
    .map_err(|_| DurableTerminalAppendRefusalV1::RouteMismatch)?;
    let receipt_identity = parse_digest(association.receipt_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let append_identity = parse_digest(association.append_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let persisted_resolution_identity = parse_digest(association.resolution_id())
        .map_err(|_| DurableTerminalAppendRefusalV1::PendingResolutionMismatch)?;
    let completion_identity = semantic_digest(&SuccessorCompletionIdentityBodyV1 {
        schema: "nq.c2_signer_succession_completion.v1",
        identity_domain: "nq.c2.signer_succession_completion.identity.v1",
        root_binding_identity: prior.root().binding_id(),
        predecessor_binding_identity: prior.terminal_binding().binding_id(),
        successor_binding_identity: successor.binding_id(),
        signer_enrollment_identity: &input.enrollment.signer_enrollment_identity,
        transition_identity: &transition_identity,
        receipt_identity: &receipt_identity,
        append_identity: &append_identity,
        persisted_resolution_identity: &persisted_resolution_identity,
        selected_transition_input_identity: &pending_msg12.selected_transition_input_identity,
        completed_append_identity: &pending_msg12.completed_append_identity,
        complete_candidate_set_identity: &pending_msg12.complete_candidate_set_identity,
        pending_successor_resolution_identity: &pending_msg12.pending_successor_resolution_identity,
        effective_cut: successor.effective_cut(),
    })
    .map_err(|_| DurableTerminalAppendRefusalV1::ChangedContentCollision)?;
    let (
        succession_mode,
        restore_lineage_identity,
        restore_authority_identity,
        historical_foundation_identity,
        recovery_condition_identity,
        recovery_authority_identity,
        recovery_grant_identity,
    ) = match &input.route {
        PreparedSuccessorRouteV1::Healthy => ("normal", None, None, None, None, None, None),
        PreparedSuccessorRouteV1::Restore => (
            "restore",
            Some(
                verified
                    .restore
                    .as_ref()
                    .ok_or(DurableTerminalAppendRefusalV1::FoundationMismatch)?
                    .restore_lineage_identity
                    .clone(),
            ),
            Some(input.enrollment.authority_reference_identity.clone()),
            Some(input.enrollment.foundation_identity.clone()),
            None,
            None,
            None,
        ),
        PreparedSuccessorRouteV1::Recovery => (
            "recovery",
            None,
            None,
            None,
            Some(input.enrollment.applicability_basis_identity.clone()),
            Some(input.enrollment.authority_reference_identity.clone()),
            Some(input.enrollment.authority_reference_identity.clone()),
        ),
    };
    let body = SuccessionProjectionBodyV1 {
        schema: SUCCESSION_SCHEMA_V1.to_owned(),
        schema_version: 1,
        identity_domain: SUCCESSION_IDENTITY_DOMAIN_V1.to_owned(),
        root_binding_identity: prior.root().binding_id().clone(),
        succession_mode: succession_mode.to_owned(),
        transition_identity,
        predecessor_binding_identity: prior.terminal_binding().binding_id().clone(),
        successor_binding_identity: successor.binding_id().clone(),
        authorization_identity: input.enrollment.authority_reference_identity.clone(),
        restore_lineage_identity,
        restore_authority_identity,
        historical_foundation_identity,
        recovery_condition_identity,
        recovery_authority_identity,
        recovery_grant_identity,
        proposal_identity: input.enrollment.proposal_identity.clone(),
        successor_pop_identity: input.enrollment.proof_of_possession_identity.clone(),
        completion_identity,
        receipt_identity: receipt_identity.clone(),
        append_identity,
        persisted_resolution_identity,
        predecessor_cut: prior.terminal_binding().effective_cut(),
        successor_cut: successor.effective_cut(),
    };
    let succession_identity = semantic_digest(&body)
        .map_err(|_| DurableTerminalAppendRefusalV1::ChangedContentCollision)?;
    let succession = SuccessionProjectionWireV1 {
        succession_identity,
        body,
    };
    let succession_bytes = canonical_json_bytes(&succession)
        .map_err(|_| DurableTerminalAppendRefusalV1::ChangedContentCollision)?;
    let lineage_identity = digest_fields(
        LINEAGE_IDENTITY_DOMAIN_V1,
        &[
            prior.root().binding_id().as_str().as_bytes(),
            successor.binding_id().as_str().as_bytes(),
            pending_msg12
                .complete_candidate_set_identity
                .as_str()
                .as_bytes(),
            &successor.effective_cut().to_be_bytes(),
        ],
    );
    let edge_count = prior
        .succession_identities()
        .len()
        .checked_add(1)
        .ok_or(DurableTerminalAppendRefusalV1::ChangedContentCollision)?;
    let lineage = LineageProjectionWireV1 {
        schema: LINEAGE_SCHEMA_V1.to_owned(),
        lineage_identity: lineage_identity.clone(),
        root_binding_identity: prior.root().binding_id().clone(),
        initial_binding_identity: prior.initial_binding().binding_id().clone(),
        terminal_binding_identity: successor.binding_id().clone(),
        edge_count: u64::try_from(edge_count)
            .map_err(|_| DurableTerminalAppendRefusalV1::ChangedContentCollision)?,
        terminal_candidate_set_identity: pending_msg12.complete_candidate_set_identity.clone(),
        effective_cut: successor.effective_cut(),
    };
    let lineage_bytes = canonical_json_bytes(&lineage)
        .map_err(|_| DurableTerminalAppendRefusalV1::ChangedContentCollision)?;
    let lineage_completion_identity = digest_fields(
        LINEAGE_COMPLETION_IDENTITY_DOMAIN_V1,
        &[
            lineage_identity.as_str().as_bytes(),
            prior.root().binding_id().as_str().as_bytes(),
            successor.binding_id().as_str().as_bytes(),
            receipt_identity.as_str().as_bytes(),
        ],
    );
    Ok(SuccessorProjectionPlanV1 {
        successor,
        successor_public_key: input.enrollment.foundation_public_key,
        succession,
        succession_bytes,
        lineage,
        lineage_bytes,
        lineage_completion_identity,
    })
}

fn resolved_terminal_matches_plan(
    resolved: &StoreVerifiedDurableGenerationCurrentV1,
    plan: &SuccessorProjectionPlanV1,
    enrollment: &VerifiedDurableEnrollmentReferenceV1,
) -> bool {
    resolved.terminal_binding() == &plan.successor
        && resolved.terminal_public_key() == plan.successor_public_key
        && resolved.lineage_identity() == &plan.lineage.lineage_identity
        && resolved.lineage_completion_identity() == &plan.lineage_completion_identity
        && resolved.terminal_candidate_set_identity()
            == &plan.lineage.terminal_candidate_set_identity
        && resolved.succession_identities().last() == Some(&plan.succession.succession_identity)
        && resolved.enrollment().foundation().identity() == &enrollment.foundation_identity
        && resolved.enrollment().adoption().identity() == &enrollment.adoption_identity
        && resolved.enrollment().acceptance().identity() == &enrollment.signer_enrollment_identity
}

fn insert_successor_projection_plan_v1(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    plan: &SuccessorProjectionPlanV1,
) -> Result<(), rusqlite::Error> {
    let (resident_generation, current_resident_generation): (u64, u64) = transaction.query_row(
        "SELECT root.resident_generation, current.resident_generation
         FROM c2_signer_root_binding_projection AS root
         JOIN c2_signer_current_binding_projection AS current
           ON current.current_binding_identity = ?2
          AND current.root_binding_identity = root.root_binding_identity
         WHERE root.root_binding_identity = ?1",
        params![
            prior.root().binding_id().as_str(),
            prior.terminal_binding().binding_id().as_str(),
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if resident_generation == 0 || resident_generation != current_resident_generation {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let current = &plan.successor;
    let body = &plan.succession.body;
    let canonical_current = canonical_json_bytes(current)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let role_manifest_generation = prior
        .root()
        .role_manifest_generation()
        .parse::<u64>()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let current_key_generation = current
        .key_generation()
        .parse::<u64>()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let projected_at = Utc::now().to_rfc3339();
    let continuity_authorization = (current.mode() == CurrentSignerBindingModeV1::NormalSuccessor)
        .then_some(body.authorization_identity.as_str());
    transaction.execute(
        "INSERT INTO c2_signer_current_binding_projection (
            current_binding_identity, root_binding_identity, occurrence_id,
            physical_store_generation_identity, signer_lifecycle_root_identity,
            scope_identity, resident_identity, resident_generation, host_role,
            role_manifest_generation, authority_domain,
            policy_lineage_root_identity, current_enrollment_identity,
            current_key_generation, current_public_key, current_policy_identity,
            current_standing_identity, binding_mode, provenance_identity,
            transition_identity, predecessor_binding_identity,
            continuity_authorization_identity, restore_lineage_identity,
            restore_authority_identity, historical_foundation_identity,
            recovery_condition_identity, recovery_authority_identity,
            recovery_grant_identity, persisted_resolution_identity,
            effective_cut, canonical_bytes, canonical_bytes_sha256,
            canonical_bytes_length, projected_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                   ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                   ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
                   ?31, ?32, ?33, ?34)",
        params![
            current.binding_id().as_str(),
            prior.root().binding_id().as_str(),
            prior.root().occurrence_id(),
            prior.root().physical_store_generation(),
            prior.root().lifecycle_root_id(),
            prior.root().scope_id(),
            prior.root().resident_id(),
            resident_generation,
            prior.root().role_id(),
            role_manifest_generation,
            prior.root().domain_id(),
            prior.root().policy_lineage_root(),
            current.enrollment_id(),
            current_key_generation,
            plan.successor_public_key.as_slice(),
            current.policy_id(),
            current.standing_id(),
            mode_text(current.mode()),
            plan.succession.succession_identity.as_str(),
            current.transition_id(),
            current.predecessor_binding_id().map(Sha256Digest::as_str),
            continuity_authorization,
            body.restore_lineage_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.restore_authority_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.historical_foundation_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.recovery_condition_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.recovery_authority_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.recovery_grant_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            current.persisted_resolution_id(),
            current.effective_cut(),
            &canonical_current,
            sha256_bytes(&canonical_current).as_str(),
            canonical_current.len() as u64,
            &projected_at,
        ],
    )?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-60");
    transaction.execute(
        "INSERT INTO c2_signer_succession_projection (
            succession_identity, root_binding_identity, succession_mode,
            transition_identity, predecessor_binding_identity,
            successor_binding_identity, authorization_identity,
            restore_lineage_identity, restore_authority_identity,
            historical_foundation_identity, recovery_condition_identity,
            recovery_authority_identity, recovery_grant_identity,
            proposal_identity, successor_pop_identity, completion_identity,
            receipt_identity, append_identity, persisted_resolution_identity,
            predecessor_cut, successor_cut, canonical_bytes,
            canonical_bytes_sha256, canonical_bytes_length, projected_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                   ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                   ?21, ?22, ?23, ?24, ?25)",
        params![
            plan.succession.succession_identity.as_str(),
            body.root_binding_identity.as_str(),
            &body.succession_mode,
            body.transition_identity.as_str(),
            body.predecessor_binding_identity.as_str(),
            body.successor_binding_identity.as_str(),
            body.authorization_identity.as_str(),
            body.restore_lineage_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.restore_authority_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.historical_foundation_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.recovery_condition_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.recovery_authority_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.recovery_grant_identity
                .as_ref()
                .map(Sha256Digest::as_str),
            body.proposal_identity.as_str(),
            body.successor_pop_identity.as_str(),
            body.completion_identity.as_str(),
            body.receipt_identity.as_str(),
            body.append_identity.as_str(),
            body.persisted_resolution_identity.as_str(),
            body.predecessor_cut,
            body.successor_cut,
            &plan.succession_bytes,
            sha256_bytes(&plan.succession_bytes).as_str(),
            plan.succession_bytes.len() as u64,
            &projected_at,
        ],
    )?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-61");
    transaction.execute(
        "INSERT INTO c2_signer_lineage_projection (
            lineage_identity, root_binding_identity, initial_binding_identity,
            terminal_binding_identity, edge_count,
            terminal_candidate_set_identity, effective_cut, canonical_bytes,
            canonical_bytes_sha256, canonical_bytes_length, projected_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            plan.lineage.lineage_identity.as_str(),
            plan.lineage.root_binding_identity.as_str(),
            plan.lineage.initial_binding_identity.as_str(),
            plan.lineage.terminal_binding_identity.as_str(),
            plan.lineage.edge_count,
            plan.lineage.terminal_candidate_set_identity.as_str(),
            plan.lineage.effective_cut,
            &plan.lineage_bytes,
            sha256_bytes(&plan.lineage_bytes).as_str(),
            plan.lineage_bytes.len() as u64,
            &projected_at,
        ],
    )?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-62");
    transaction.execute(
        "INSERT INTO c2_signer_lineage_edge_projection (
            lineage_identity, edge_ordinal, succession_identity,
            predecessor_binding_identity, successor_binding_identity,
            succession_mode
         ) SELECT ?1, edge_ordinal, succession_identity,
                  predecessor_binding_identity, successor_binding_identity,
                  succession_mode
           FROM c2_signer_lineage_edge_projection
           WHERE lineage_identity = ?2 ORDER BY edge_ordinal",
        params![
            plan.lineage.lineage_identity.as_str(),
            prior.lineage_identity().as_str(),
        ],
    )?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-63");
    transaction.execute(
        "INSERT INTO c2_signer_lineage_edge_projection (
            lineage_identity, edge_ordinal, succession_identity,
            predecessor_binding_identity, successor_binding_identity,
            succession_mode
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            plan.lineage.lineage_identity.as_str(),
            plan.lineage.edge_count - 1,
            plan.succession.succession_identity.as_str(),
            body.predecessor_binding_identity.as_str(),
            body.successor_binding_identity.as_str(),
            &body.succession_mode,
        ],
    )?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-64");
    transaction.execute(
        "INSERT INTO c2_signer_lineage_completion_projection (
            lineage_identity, completion_identity, root_binding_identity,
            terminal_binding_identity, edge_count, completed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            plan.lineage.lineage_identity.as_str(),
            plan.lineage_completion_identity.as_str(),
            plan.lineage.root_binding_identity.as_str(),
            plan.lineage.terminal_binding_identity.as_str(),
            plan.lineage.edge_count,
            &projected_at,
        ],
    )?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-65");
    Ok(())
}

fn append_successor_terminal_v1(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    input: PreparedSuccessorTerminalAppendV1,
) -> Result<StoreVerifiedDurableGenerationCurrentV1, DurableTerminalAppendRefusalV1> {
    let plan = prepare_successor_projection_plan(transaction, prior, &input)?;
    let observed = resolve_store_verified_durable_generation_current_v1(transaction, prior.root())?;
    if !same_durable_terminal(&observed, prior) {
        return if resolved_terminal_matches_plan(&observed, &plan, &input.enrollment) {
            Ok(observed)
        } else if observed.terminal_binding().binding_id() == plan.successor.binding_id() {
            Err(DurableTerminalAppendRefusalV1::ChangedContentCollision)
        } else {
            Err(DurableTerminalAppendRefusalV1::StalePredecessor)
        };
    }
    transaction.execute_batch("SAVEPOINT nq_c2_successor_terminal_append_v1")?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-66");
    if let Err(error) = insert_successor_projection_plan_v1(transaction, prior, &plan) {
        let _ = transaction.execute_batch(
            "ROLLBACK TO nq_c2_successor_terminal_append_v1;
             RELEASE nq_c2_successor_terminal_append_v1",
        );
        #[cfg(test)]
        crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-67");
        return Err(DurableTerminalAppendRefusalV1::Sql(error));
    }
    let resolved =
        match resolve_store_verified_durable_generation_current_v1(transaction, prior.root()) {
            Ok(resolved) if resolved_terminal_matches_plan(&resolved, &plan, &input.enrollment) => {
                resolved
            }
            Ok(_) => {
                transaction.execute_batch(
                    "ROLLBACK TO nq_c2_successor_terminal_append_v1;
                 RELEASE nq_c2_successor_terminal_append_v1",
                )?;
                #[cfg(test)]
                crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-68");
                return Err(DurableTerminalAppendRefusalV1::ChangedContentCollision);
            }
            Err(refusal) => {
                transaction.execute_batch(
                    "ROLLBACK TO nq_c2_successor_terminal_append_v1;
                 RELEASE nq_c2_successor_terminal_append_v1",
                )?;
                #[cfg(test)]
                crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-69");
                return Err(DurableTerminalAppendRefusalV1::Resolution(refusal));
            }
        };
    transaction.execute_batch("RELEASE nq_c2_successor_terminal_append_v1")?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-70");
    Ok(resolved)
}

/// Atomically append and re-resolve one healthy successor terminal.
pub(crate) fn append_healthy_successor_terminal_v1(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    input: HealthySuccessorTerminalAppendV1,
) -> Result<StoreVerifiedDurableGenerationCurrentV1, DurableTerminalAppendRefusalV1> {
    append_successor_terminal_v1(transaction, prior, input.into())
}

/// Atomically append and re-resolve one exact historical restore terminal.
pub(crate) fn append_restore_successor_terminal_v1(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    input: RestoreSuccessorTerminalAppendV1,
) -> Result<StoreVerifiedDurableGenerationCurrentV1, DurableTerminalAppendRefusalV1> {
    append_successor_terminal_v1(transaction, prior, input.into())
}

/// Atomically append and re-resolve one externally authorized recovery terminal.
pub(crate) fn append_recovery_successor_terminal_v1(
    transaction: &Transaction<'_>,
    prior: &StoreVerifiedDurableGenerationCurrentV1,
    input: RecoverySuccessorTerminalAppendV1,
) -> Result<StoreVerifiedDurableGenerationCurrentV1, DurableTerminalAppendRefusalV1> {
    append_successor_terminal_v1(transaction, prior, input.into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
    use rusqlite::{Connection, params};

    use super::*;
    use crate::store_generation::signer::binding::{
        CompletedSignerTransitionV1, construct_sb_01_lifecycle_root_identity,
        construct_sb_02_immutable_root_binding, construct_sb_04_initial_binding_derivation,
        construct_sb_05_normal_binding_derivation, construct_sb_06_recovery_binding_derivation,
        construct_sb_06_restore_binding_derivation,
    };

    const TEST_SCHEMA: &str = r#"
        CREATE TABLE c2_signer_current_binding_projection (
            current_binding_identity TEXT, root_binding_identity TEXT,
            occurrence_id TEXT, physical_store_generation_identity TEXT,
            signer_lifecycle_root_identity TEXT, scope_identity TEXT,
            resident_identity TEXT, resident_generation INTEGER, host_role TEXT,
            role_manifest_generation INTEGER, authority_domain TEXT,
            policy_lineage_root_identity TEXT, current_enrollment_identity TEXT,
            current_key_generation INTEGER, current_public_key BLOB,
            current_policy_identity TEXT, current_standing_identity TEXT,
            binding_mode TEXT, provenance_identity TEXT, transition_identity TEXT,
            predecessor_binding_identity TEXT, continuity_authorization_identity TEXT,
            restore_lineage_identity TEXT, restore_authority_identity TEXT,
            historical_foundation_identity TEXT, recovery_condition_identity TEXT,
            recovery_authority_identity TEXT, recovery_grant_identity TEXT,
            persisted_resolution_identity TEXT, effective_cut INTEGER,
            canonical_bytes BLOB, canonical_bytes_sha256 TEXT,
            canonical_bytes_length INTEGER
        );
        CREATE TABLE c2_signer_succession_projection (
            succession_identity TEXT, root_binding_identity TEXT, succession_mode TEXT,
            transition_identity TEXT, predecessor_binding_identity TEXT,
            successor_binding_identity TEXT, authorization_identity TEXT,
            restore_lineage_identity TEXT, restore_authority_identity TEXT,
            historical_foundation_identity TEXT, recovery_condition_identity TEXT,
            recovery_authority_identity TEXT, recovery_grant_identity TEXT,
            proposal_identity TEXT, successor_pop_identity TEXT,
            completion_identity TEXT, receipt_identity TEXT, append_identity TEXT,
            persisted_resolution_identity TEXT, predecessor_cut INTEGER,
            successor_cut INTEGER, canonical_bytes BLOB,
            canonical_bytes_sha256 TEXT, canonical_bytes_length INTEGER
        );
        CREATE TABLE c2_signer_lineage_projection (
            lineage_identity TEXT, root_binding_identity TEXT,
            initial_binding_identity TEXT, terminal_binding_identity TEXT,
            edge_count INTEGER, terminal_candidate_set_identity TEXT,
            effective_cut INTEGER, canonical_bytes BLOB,
            canonical_bytes_sha256 TEXT, canonical_bytes_length INTEGER
        );
        CREATE TABLE c2_signer_lineage_edge_projection (
            lineage_identity TEXT, edge_ordinal INTEGER, succession_identity TEXT,
            predecessor_binding_identity TEXT, successor_binding_identity TEXT,
            succession_mode TEXT
        );
        CREATE TABLE c2_signer_lineage_completion_projection (
            lineage_identity TEXT, completion_identity TEXT,
            root_binding_identity TEXT, terminal_binding_identity TEXT,
            edge_count INTEGER
        );
        CREATE TABLE c2_signer_message_appends (
            ledger_sequence INTEGER, generation_sequence INTEGER,
            family TEXT, route TEXT, message_identity BLOB,
            append_identity TEXT, signer_key_generation_identity BLOB,
            resulting_frontier_identity BLOB, effect_receipt_identity TEXT,
            canonical_message BLOB, canonical_message_sha256 TEXT,
            physical_carrier_bytes BLOB, physical_carrier_sha256 TEXT,
            physical_carrier_length INTEGER
        );
        CREATE TABLE c2_external_carrier_ingress (
            route TEXT NOT NULL, family TEXT NOT NULL,
            carrier_identity BLOB NOT NULL, effect_identity TEXT NOT NULL
        );
    "#;

    #[derive(Clone)]
    struct EnrollmentFixtureV1 {
        lineage: FoundationalAdoptionLineageV1,
        public_key: [u8; 32],
        key_generation: u64,
    }

    #[derive(Clone)]
    struct EdgeFixtureV1 {
        identity: Sha256Digest,
        mode: CurrentSignerBindingModeV1,
        predecessor: Sha256Digest,
        successor: Sha256Digest,
        receipt_identity: Sha256Digest,
    }

    struct ResolverFixtureV1 {
        connection: Connection,
        root: StoreGenerationSignerRootBindingV1,
        bindings: Vec<CurrentSignerGenerationBindingV1>,
        public_keys: Vec<[u8; 32]>,
        enrollments: BTreeMap<String, EnrollmentFixtureV1>,
        edges: Vec<EdgeFixtureV1>,
        terminal_candidate_set_identity: Sha256Digest,
        next_ledger_sequence: u64,
    }

    fn id(label: &str) -> Sha256Digest {
        sha256_bytes(label.as_bytes())
    }

    fn digest_string(label: &str) -> String {
        id(label).as_str().to_owned()
    }

    impl ResolverFixtureV1 {
        fn new() -> Self {
            let connection = Connection::open_in_memory().expect("open fixture SQLite");
            connection
                .execute_batch(TEST_SCHEMA)
                .expect("install resolver fixture schema");
            let identity = construct_sb_01_lifecycle_root_identity(
                "occurrence-1".to_owned(),
                digest_string("physical-generation"),
                digest_string("lifecycle-root"),
                digest_string("scope"),
                "resident-1".to_owned(),
                "writer".to_owned(),
                "1".to_owned(),
                "authority-domain".to_owned(),
                digest_string("policy-lineage-root"),
            )
            .expect("valid lifecycle root");
            let root = construct_sb_02_immutable_root_binding(
                identity,
                digest_string("enrollment-initial"),
                "0".to_owned(),
                digest_string("policy-initial"),
                id("genesis"),
                id("generation-commitment"),
                10,
            )
            .expect("valid immutable root");
            let initial = construct_sb_04_initial_binding_derivation(
                &root,
                digest_string("standing-initial"),
                digest_string("resolution-initial"),
                11,
            )
            .expect("valid initial binding")
            .into_inner();
            let public_key = [1; 32];
            let terminal_candidate_set_identity = id("candidate-set");
            let mut fixture = Self {
                connection,
                root,
                bindings: vec![initial.clone()],
                public_keys: vec![public_key],
                enrollments: BTreeMap::from([(
                    initial.enrollment_id().to_owned(),
                    EnrollmentFixtureV1 {
                        lineage: FoundationalAdoptionLineageV1::InitialExternal,
                        public_key,
                        key_generation: 0,
                    },
                )]),
                edges: Vec::new(),
                terminal_candidate_set_identity,
                next_ledger_sequence: 1,
            };
            fixture.insert_binding(&initial, public_key, fixture.root.binding_id(), None);
            fixture.insert_resolution(&initial, id("receipt-initial"), id("append-initial"));
            fixture.insert_lineage_prefix(0);
            fixture
        }

        fn insert_binding(
            &self,
            current: &CurrentSignerGenerationBindingV1,
            public_key: [u8; 32],
            provenance: &Sha256Digest,
            route: Option<&SuccessionProjectionBodyV1>,
        ) {
            let canonical = canonical_json_bytes(current).expect("canonical binding");
            let mode = mode_text(current.mode());
            let (
                continuity,
                restore_lineage,
                restore_authority,
                historical_foundation,
                recovery_condition,
                recovery_authority,
                recovery_grant,
            ) = route.map_or(
                (None, None, None, None, None, None, None),
                |route| match current.mode() {
                    CurrentSignerBindingModeV1::NormalSuccessor => (
                        Some(route.authorization_identity.as_str()),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                    CurrentSignerBindingModeV1::RestoreSuccessor => (
                        None,
                        route
                            .restore_lineage_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        route
                            .restore_authority_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        route
                            .historical_foundation_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        None,
                        None,
                        None,
                    ),
                    CurrentSignerBindingModeV1::RecoverySuccessor => (
                        None,
                        None,
                        None,
                        None,
                        route
                            .recovery_condition_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        route
                            .recovery_authority_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        route
                            .recovery_grant_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                    ),
                    CurrentSignerBindingModeV1::Initial => {
                        (None, None, None, None, None, None, None)
                    }
                },
            );
            self.connection
                .execute(
                    "INSERT INTO c2_signer_current_binding_projection VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11,
                        ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                        ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32
                    )",
                    params![
                        current.binding_id().as_str(),
                        self.root.binding_id().as_str(),
                        self.root.occurrence_id(),
                        self.root.physical_store_generation(),
                        self.root.lifecycle_root_id(),
                        self.root.scope_id(),
                        self.root.resident_id(),
                        self.root.role_id(),
                        self.root.role_manifest_generation().parse::<u64>().unwrap(),
                        self.root.domain_id(),
                        self.root.policy_lineage_root(),
                        current.enrollment_id(),
                        current.key_generation().parse::<u64>().unwrap(),
                        &public_key[..],
                        current.policy_id(),
                        current.standing_id(),
                        mode,
                        provenance.as_str(),
                        current.transition_id(),
                        current.predecessor_binding_id().map(Sha256Digest::as_str),
                        continuity,
                        restore_lineage,
                        restore_authority,
                        historical_foundation,
                        recovery_condition,
                        recovery_authority,
                        recovery_grant,
                        current.persisted_resolution_id(),
                        current.effective_cut(),
                        &canonical,
                        sha256_bytes(&canonical).as_str(),
                        canonical.len() as u64,
                    ],
                )
                .expect("insert canonical current binding");
        }

        fn insert_resolution(
            &mut self,
            binding: &CurrentSignerGenerationBindingV1,
            receipt_identity: Sha256Digest,
            append_identity: Sha256Digest,
        ) {
            let (family, route) = match binding.mode() {
                CurrentSignerBindingModeV1::Initial => ("MSG-10", "msg10_installation_receipt"),
                _ => ("MSG-12", "msg12_receipt_pending"),
            };
            self.connection
                .execute(
                    "INSERT INTO c2_signer_message_appends (
                        ledger_sequence, generation_sequence, family, route,
                        message_identity, append_identity,
                        signer_key_generation_identity,
                        resulting_frontier_identity, effect_receipt_identity,
                        canonical_message, canonical_message_sha256
                     ) VALUES (?1, 1, ?2, ?3, ?4, ?5, zeroblob(32),
                               zeroblob(32), ?6, X'7b7d', ?7)",
                    params![
                        self.next_ledger_sequence,
                        family,
                        route,
                        digest_bytes(&receipt_identity).unwrap().as_slice(),
                        append_identity.as_str(),
                        binding.persisted_resolution_id(),
                        sha256_bytes(b"{}").as_str(),
                    ],
                )
                .expect("insert terminal resolution");
            self.next_ledger_sequence += 1;
        }

        fn add_successor(
            &mut self,
            predecessor_index: usize,
            mode: CurrentSignerBindingModeV1,
            label: &str,
        ) -> usize {
            assert_ne!(mode, CurrentSignerBindingModeV1::Initial);
            let predecessor = self.bindings[predecessor_index].clone();
            let predecessor_generation = predecessor.key_generation().parse::<u64>().unwrap();
            let key_generation = match mode {
                CurrentSignerBindingModeV1::RestoreSuccessor => predecessor_generation,
                _ => predecessor_generation + 1,
            };
            let transition_identity = id(&format!("{label}-transition"));
            let receipt_identity = id(&format!("{label}-receipt"));
            let append_identity = id(&format!("{label}-append"));
            let resolution_identity = id(&format!("{label}-resolution"));
            let enrollment_identity = id(&format!("{label}-enrollment"));
            let policy_identity = id(&format!("{label}-policy"));
            let standing_identity = id(&format!("{label}-standing"));
            let completed = CompletedSignerTransitionV1 {
                mode,
                root_id: self.root.binding_id().clone(),
                transition_id: transition_identity.as_str().to_owned(),
                predecessor_binding_id: predecessor.binding_id().clone(),
                predecessor_key_generation: predecessor.key_generation().to_owned(),
                successor_enrollment_id: enrollment_identity.as_str().to_owned(),
                successor_key_generation: key_generation.to_string(),
                successor_policy_id: policy_identity.as_str().to_owned(),
                successor_standing_id: standing_identity.as_str().to_owned(),
                receipt_id: receipt_identity.as_str().to_owned(),
                append_id: append_identity.as_str().to_owned(),
                resolution_id: resolution_identity.as_str().to_owned(),
                effective_cut: predecessor.effective_cut() + 10,
            };
            let successor = match mode {
                CurrentSignerBindingModeV1::NormalSuccessor => {
                    construct_sb_05_normal_binding_derivation(&self.root, &predecessor, &completed)
                        .unwrap()
                        .into_inner()
                }
                CurrentSignerBindingModeV1::RestoreSuccessor => {
                    construct_sb_06_restore_binding_derivation(&self.root, &predecessor, &completed)
                        .unwrap()
                        .into_inner()
                }
                CurrentSignerBindingModeV1::RecoverySuccessor => {
                    construct_sb_06_recovery_binding_derivation(
                        &self.root,
                        &predecessor,
                        &completed,
                    )
                    .unwrap()
                    .into_inner()
                }
                CurrentSignerBindingModeV1::Initial => unreachable!(),
            };
            let authorization_identity = id(&format!("{label}-authorization"));
            let restore_lineage_identity = (mode == CurrentSignerBindingModeV1::RestoreSuccessor)
                .then(|| id(&format!("{label}-restore-lineage")));
            let restore_authority_identity = (mode == CurrentSignerBindingModeV1::RestoreSuccessor)
                .then(|| authorization_identity.clone());
            let historical_foundation_identity = (mode
                == CurrentSignerBindingModeV1::RestoreSuccessor)
                .then(|| id(&format!("{label}-historical-foundation")));
            let recovery_condition_identity = (mode
                == CurrentSignerBindingModeV1::RecoverySuccessor)
                .then(|| id(&format!("{label}-recovery-condition")));
            let recovery_authority_identity = (mode
                == CurrentSignerBindingModeV1::RecoverySuccessor)
                .then(|| id(&format!("{label}-recovery-authority")));
            let recovery_grant_identity = (mode == CurrentSignerBindingModeV1::RecoverySuccessor)
                .then(|| authorization_identity.clone());
            let body = SuccessionProjectionBodyV1 {
                schema: SUCCESSION_SCHEMA_V1.to_owned(),
                schema_version: 1,
                identity_domain: SUCCESSION_IDENTITY_DOMAIN_V1.to_owned(),
                root_binding_identity: self.root.binding_id().clone(),
                succession_mode: match mode {
                    CurrentSignerBindingModeV1::NormalSuccessor => "normal",
                    CurrentSignerBindingModeV1::RestoreSuccessor => "restore",
                    CurrentSignerBindingModeV1::RecoverySuccessor => "recovery",
                    CurrentSignerBindingModeV1::Initial => unreachable!(),
                }
                .to_owned(),
                transition_identity,
                predecessor_binding_identity: predecessor.binding_id().clone(),
                successor_binding_identity: successor.binding_id().clone(),
                authorization_identity,
                restore_lineage_identity,
                restore_authority_identity,
                historical_foundation_identity,
                recovery_condition_identity,
                recovery_authority_identity,
                recovery_grant_identity,
                proposal_identity: id(&format!("{label}-proposal")),
                successor_pop_identity: id(&format!("{label}-pop")),
                completion_identity: id(&format!("{label}-completion")),
                receipt_identity: receipt_identity.clone(),
                append_identity: append_identity.clone(),
                persisted_resolution_identity: resolution_identity,
                predecessor_cut: predecessor.effective_cut(),
                successor_cut: successor.effective_cut(),
            };
            let succession_identity = semantic_digest(&body).expect("succession identity");
            let wire = SuccessionProjectionWireV1 {
                succession_identity: succession_identity.clone(),
                body: body.clone(),
            };
            let canonical = canonical_json_bytes(&wire).expect("canonical succession");
            let public_key = match mode {
                CurrentSignerBindingModeV1::RestoreSuccessor => self.public_keys[predecessor_index],
                _ => [u8::try_from(self.bindings.len() + 1).unwrap(); 32],
            };
            self.insert_binding(&successor, public_key, &succession_identity, Some(&body));
            self.insert_resolution(
                &successor,
                receipt_identity.clone(),
                append_identity.clone(),
            );
            self.connection
                .execute(
                    "INSERT INTO c2_signer_succession_projection VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
                    )",
                    params![
                        succession_identity.as_str(),
                        self.root.binding_id().as_str(),
                        body.succession_mode,
                        body.transition_identity.as_str(),
                        body.predecessor_binding_identity.as_str(),
                        body.successor_binding_identity.as_str(),
                        body.authorization_identity.as_str(),
                        body.restore_lineage_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        body.restore_authority_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        body.historical_foundation_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        body.recovery_condition_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        body.recovery_authority_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        body.recovery_grant_identity
                            .as_ref()
                            .map(Sha256Digest::as_str),
                        body.proposal_identity.as_str(),
                        body.successor_pop_identity.as_str(),
                        body.completion_identity.as_str(),
                        body.receipt_identity.as_str(),
                        body.append_identity.as_str(),
                        body.persisted_resolution_identity.as_str(),
                        body.predecessor_cut,
                        body.successor_cut,
                        &canonical,
                        sha256_bytes(&canonical).as_str(),
                        canonical.len() as u64,
                    ],
                )
                .expect("insert canonical succession");
            let lineage = expected_lineage(mode);
            self.enrollments.insert(
                successor.enrollment_id().to_owned(),
                EnrollmentFixtureV1 {
                    lineage,
                    public_key,
                    key_generation,
                },
            );
            self.bindings.push(successor);
            self.public_keys.push(public_key);
            self.edges.push(EdgeFixtureV1 {
                identity: succession_identity,
                mode,
                predecessor: predecessor.binding_id().clone(),
                successor: self.bindings.last().unwrap().binding_id().clone(),
                receipt_identity,
            });
            self.bindings.len() - 1
        }

        fn insert_lineage_prefix(&self, edge_count: usize) {
            self.insert_lineage_prefix_with_candidate(
                edge_count,
                &self.terminal_candidate_set_identity,
            );
        }

        fn insert_lineage_prefix_with_candidate(
            &self,
            edge_count: usize,
            terminal_candidate_set_identity: &Sha256Digest,
        ) {
            let terminal = &self.bindings[edge_count];
            let lineage_identity = digest_fields(
                LINEAGE_IDENTITY_DOMAIN_V1,
                &[
                    self.root.binding_id().as_str().as_bytes(),
                    terminal.binding_id().as_str().as_bytes(),
                    terminal_candidate_set_identity.as_str().as_bytes(),
                    &terminal.effective_cut().to_be_bytes(),
                ],
            );
            let wire = LineageProjectionWireV1 {
                schema: LINEAGE_SCHEMA_V1.to_owned(),
                lineage_identity: lineage_identity.clone(),
                root_binding_identity: self.root.binding_id().clone(),
                initial_binding_identity: self.bindings[0].binding_id().clone(),
                terminal_binding_identity: terminal.binding_id().clone(),
                edge_count: edge_count as u64,
                terminal_candidate_set_identity: terminal_candidate_set_identity.clone(),
                effective_cut: terminal.effective_cut(),
            };
            let canonical = canonical_json_bytes(&wire).expect("canonical lineage");
            self.connection
                .execute(
                    "INSERT INTO c2_signer_lineage_projection VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
                    )",
                    params![
                        lineage_identity.as_str(),
                        self.root.binding_id().as_str(),
                        self.bindings[0].binding_id().as_str(),
                        terminal.binding_id().as_str(),
                        edge_count as u64,
                        terminal_candidate_set_identity.as_str(),
                        terminal.effective_cut(),
                        &canonical,
                        sha256_bytes(&canonical).as_str(),
                        canonical.len() as u64,
                    ],
                )
                .expect("insert lineage prefix");
            for (ordinal, edge) in self.edges.iter().take(edge_count).enumerate() {
                self.connection
                    .execute(
                        "INSERT INTO c2_signer_lineage_edge_projection VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            lineage_identity.as_str(),
                            ordinal as u64,
                            edge.identity.as_str(),
                            edge.predecessor.as_str(),
                            edge.successor.as_str(),
                            match edge.mode {
                                CurrentSignerBindingModeV1::NormalSuccessor => "normal",
                                CurrentSignerBindingModeV1::RestoreSuccessor => "restore",
                                CurrentSignerBindingModeV1::RecoverySuccessor => "recovery",
                                CurrentSignerBindingModeV1::Initial => unreachable!(),
                            },
                        ],
                    )
                    .expect("insert lineage edge");
            }
            let completion_receipt = if edge_count == 0 {
                id("receipt-initial")
            } else {
                self.edges[edge_count - 1].receipt_identity.clone()
            };
            let completion_identity = digest_fields(
                LINEAGE_COMPLETION_IDENTITY_DOMAIN_V1,
                &[
                    lineage_identity.as_str().as_bytes(),
                    self.root.binding_id().as_str().as_bytes(),
                    terminal.binding_id().as_str().as_bytes(),
                    completion_receipt.as_str().as_bytes(),
                ],
            );
            self.connection
                .execute(
                    "INSERT INTO c2_signer_lineage_completion_projection VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        lineage_identity.as_str(),
                        completion_identity.as_str(),
                        self.root.binding_id().as_str(),
                        terminal.binding_id().as_str(),
                        edge_count as u64,
                    ],
                )
                .expect("insert lineage completion");
        }

        fn add_completed_successor(&mut self, mode: CurrentSignerBindingModeV1, label: &str) {
            let predecessor = self.bindings.len() - 1;
            self.add_successor(predecessor, mode, label);
            self.insert_lineage_prefix(self.edges.len());
        }

        fn resolve(
            &mut self,
        ) -> Result<GenericResolvedTerminalV1<()>, DurableTerminalResolutionRefusalV1> {
            let enrollments = self.enrollments.clone();
            let transaction = self.connection.transaction().unwrap();
            resolve_with_enrollment_loader(&transaction, &self.root, move |_, terminal| {
                let enrollment = enrollments
                    .get(terminal.enrollment_id())
                    .ok_or(DurableTerminalResolutionRefusalV1::Incomplete)?;
                Ok((
                    VerifiedTerminalEnrollmentCoordinatesV1 {
                        lineage: enrollment.lineage,
                        public_key: enrollment.public_key,
                        key_generation: enrollment.key_generation,
                    },
                    (),
                ))
            })
        }
    }

    #[test]
    fn structural_terminal_accepts_two_rotations_and_completed_prefixes() {
        let mut fixture = ResolverFixtureV1::new();
        fixture.add_completed_successor(CurrentSignerBindingModeV1::NormalSuccessor, "a-to-b");
        fixture.add_completed_successor(CurrentSignerBindingModeV1::NormalSuccessor, "b-to-c");

        let expected = fixture.bindings.last().unwrap().binding_id().clone();
        let resolved = fixture.resolve().expect("two rotations resolve");
        assert_eq!(resolved.terminal.binding_id(), &expected);
        assert_eq!(resolved.succession_identities.len(), 2);
    }

    #[test]
    fn all_four_terminal_modes_require_their_exact_foundational_lineage() {
        for (mode, label) in [
            (CurrentSignerBindingModeV1::Initial, "bootstrap"),
            (CurrentSignerBindingModeV1::NormalSuccessor, "normal"),
            (CurrentSignerBindingModeV1::RestoreSuccessor, "restore"),
            (CurrentSignerBindingModeV1::RecoverySuccessor, "recovery"),
        ] {
            let mut fixture = ResolverFixtureV1::new();
            if mode != CurrentSignerBindingModeV1::Initial {
                fixture.add_completed_successor(mode, label);
            }
            let resolved = fixture
                .resolve()
                .unwrap_or_else(|error| panic!("{label} terminal should resolve: {error:?}"));
            assert_eq!(resolved.terminal.mode(), mode);
        }
    }

    #[test]
    fn fork_and_gap_are_refused_before_terminal_selection() {
        let mut fork = ResolverFixtureV1::new();
        fork.add_successor(0, CurrentSignerBindingModeV1::NormalSuccessor, "fork-b");
        fork.add_successor(0, CurrentSignerBindingModeV1::NormalSuccessor, "fork-c");
        assert!(matches!(
            fork.resolve(),
            Err(DurableTerminalResolutionRefusalV1::Fork)
        ));

        let mut gap = ResolverFixtureV1::new();
        gap.add_successor(0, CurrentSignerBindingModeV1::NormalSuccessor, "gap-b");
        gap.connection
            .execute("DELETE FROM c2_signer_succession_projection", [])
            .unwrap();
        assert!(matches!(
            gap.resolve(),
            Err(DurableTerminalResolutionRefusalV1::Gap)
        ));
    }

    #[test]
    fn duplicate_structurally_maximal_completion_is_refused() {
        let mut fixture = ResolverFixtureV1::new();
        fixture.add_completed_successor(CurrentSignerBindingModeV1::NormalSuccessor, "a-to-b");
        fixture.insert_lineage_prefix_with_candidate(1, &id("substituted-candidate-set"));
        assert!(matches!(
            fixture.resolve(),
            Err(DurableTerminalResolutionRefusalV1::MultipleMaximalTerminals)
        ));
    }

    #[test]
    fn binding_mode_cannot_substitute_foundational_lineage() {
        let mut fixture = ResolverFixtureV1::new();
        fixture.add_completed_successor(CurrentSignerBindingModeV1::NormalSuccessor, "a-to-b");
        let terminal = fixture.bindings.last().unwrap().enrollment_id().to_owned();
        fixture.enrollments.get_mut(&terminal).unwrap().lineage =
            FoundationalAdoptionLineageV1::RestoreHistorical;
        assert!(matches!(
            fixture.resolve(),
            Err(DurableTerminalResolutionRefusalV1::ModeLineageMismatch)
        ));
    }

    #[test]
    fn successor_requires_pending_msg12_resolution_route() {
        let mut fixture = ResolverFixtureV1::new();
        fixture.add_completed_successor(CurrentSignerBindingModeV1::NormalSuccessor, "a-to-b");
        fixture
            .connection
            .execute(
                "UPDATE c2_signer_message_appends SET route = 'msg12_receipt_current' WHERE family = 'MSG-12'",
                [],
            )
            .unwrap();
        assert!(matches!(
            fixture.resolve(),
            Err(DurableTerminalResolutionRefusalV1::Malformed)
        ));
    }

    #[test]
    fn healthy_completion_requires_one_exact_msg11_append_referent() {
        let mut fixture = ResolverFixtureV1::new();
        let mut pending = VerifiedPendingMsg12ReferenceV1 {
            ledger_sequence: 2,
            event_cut: 20,
            message_identity: id("pending-msg12"),
            append_identity: id("pending-msg12-append"),
            effect_receipt_identity: id("pending-msg12-effect"),
            signer_public_key: [2; 32],
            signer_key_generation_identity: id("successor-key-generation"),
            occurrence_identity: id("occurrence"),
            physical_generation_identity: id("physical-generation"),
            lifecycle_root_identity: id("lifecycle-root"),
            scope_identity: id("scope"),
            transaction_intent_identity: id("transition"),
            active_policy_identity: id("policy"),
            attempt_identity: id("attempt"),
            selected_transition_input_identity: id("transition"),
            completed_append_identity: id("missing-msg11-append"),
            complete_candidate_set_identity: id("candidate-set"),
            pending_successor_resolution_identity: id("pending-resolution"),
        };
        let transaction = fixture.connection.transaction().unwrap();
        assert!(matches!(
            verify_healthy_pending_msg12_completed_append_is_exact_msg11_v1(
                &transaction,
                &pending,
            ),
            Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
        ));

        // A real durable row of another family is not a referent either.
        pending.completed_append_identity = id("append-initial");
        assert!(matches!(
            verify_healthy_pending_msg12_completed_append_is_exact_msg11_v1(
                &transaction,
                &pending,
            ),
            Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
        ));
    }

    #[test]
    fn discontinuity_foundation_adoption_cut_is_exactly_r_plus_two() {
        assert_eq!(discontinuity_foundation_adoption_cut_v1(41), Some(43));
        assert_eq!(
            discontinuity_foundation_adoption_cut_v1(u64::MAX - 1),
            None,
            "overflow must refuse instead of collapsing adoption into another cut"
        );
    }

    #[test]
    fn discontinuity_completion_requires_the_exact_route_effect_referent() {
        let mut fixture = ResolverFixtureV1::new();
        let restore_authority = id("restore-authority");
        let recovery_authority = id("recovery-authority");
        let restore_effect = id("restore-effect");
        let recovery_effect = id("recovery-effect");
        fixture
            .connection
            .execute(
                "INSERT INTO c2_external_carrier_ingress
                 (route, family, carrier_identity, effect_identity)
                 VALUES ('msg13_restore_authorization', 'MSG-13', ?1, ?2)",
                params![
                    digest_bytes(&restore_authority).unwrap().as_slice(),
                    restore_effect.as_str(),
                ],
            )
            .unwrap();
        fixture
            .connection
            .execute(
                "INSERT INTO c2_external_carrier_ingress
                 (route, family, carrier_identity, effect_identity)
                 VALUES ('msg15_recovery_grant', 'MSG-15', ?1, ?2)",
                params![
                    digest_bytes(&recovery_authority).unwrap().as_slice(),
                    recovery_effect.as_str(),
                ],
            )
            .unwrap();
        let mut pending = VerifiedPendingMsg12ReferenceV1 {
            ledger_sequence: 2,
            event_cut: 20,
            message_identity: id("pending-msg12"),
            append_identity: id("pending-msg12-append"),
            effect_receipt_identity: id("pending-msg12-effect"),
            signer_public_key: [2; 32],
            signer_key_generation_identity: id("successor-key-generation"),
            occurrence_identity: id("occurrence"),
            physical_generation_identity: id("physical-generation"),
            lifecycle_root_identity: id("lifecycle-root"),
            scope_identity: id("scope"),
            transaction_intent_identity: id("transition"),
            active_policy_identity: id("policy"),
            attempt_identity: id("attempt"),
            selected_transition_input_identity: id("transition"),
            completed_append_identity: restore_effect.clone(),
            complete_candidate_set_identity: id("candidate-set"),
            pending_successor_resolution_identity: id("pending-resolution"),
        };
        let transaction = fixture.connection.transaction().unwrap();

        verify_discontinuity_pending_msg12_completed_effect_v1(
            &transaction,
            PreparedSuccessorRouteV1::Restore,
            &restore_authority,
            &pending,
        )
        .expect("the exact MSG-13 effect is the restore completion referent");
        assert!(matches!(
            verify_discontinuity_pending_msg12_completed_effect_v1(
                &transaction,
                PreparedSuccessorRouteV1::Recovery,
                &restore_authority,
                &pending,
            ),
            Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
        ));

        pending.completed_append_identity = recovery_effect;
        verify_discontinuity_pending_msg12_completed_effect_v1(
            &transaction,
            PreparedSuccessorRouteV1::Recovery,
            &recovery_authority,
            &pending,
        )
        .expect("the exact MSG-15 effect is the recovery completion referent");
        pending.completed_append_identity = id("substituted-effect");
        assert!(matches!(
            verify_discontinuity_pending_msg12_completed_effect_v1(
                &transaction,
                PreparedSuccessorRouteV1::Recovery,
                &recovery_authority,
                &pending,
            ),
            Err(DurableTerminalAppendRefusalV1::PendingResolutionMismatch)
        ));
    }

    fn foundation(label: &str, public_key: u8, generation: u64) -> StableFoundationCoordinatesV1 {
        StableFoundationCoordinatesV1 {
            identity: id(&format!("foundation-{label}")),
            public_key: [public_key; 32],
            key_generation: generation,
            key_generation_identity: id(&format!("key-generation-{label}")),
            custody_identity: id(&format!("custody-{label}")),
        }
    }

    #[test]
    fn restore_uses_exact_historical_foundation_not_displaced_predecessor() {
        let historical_a = foundation("a", 1, 0);
        let displaced_b = foundation("b", 2, 1);
        let restored_a = historical_a.clone();
        assert!(verify_stable_foundation_route_law_v1(
            &PreparedSuccessorRouteV1::Restore,
            &id("binding-b"),
            &id("adoption-b"),
            &displaced_b,
            &historical_a.identity,
            &restored_a,
            Some(&historical_a),
        ));
        assert!(!verify_stable_foundation_route_law_v1(
            &PreparedSuccessorRouteV1::Restore,
            &id("binding-b"),
            &id("adoption-b"),
            &displaced_b,
            &displaced_b.identity,
            &displaced_b,
            Some(&historical_a),
        ));
    }

    #[test]
    fn healthy_and_recovery_enforce_only_their_frozen_foundation_laws() {
        let predecessor = foundation("a", 1, 4);
        let mut healthy = foundation("healthy", 1, 5);
        healthy.custody_identity = predecessor.custody_identity.clone();
        assert!(verify_stable_foundation_route_law_v1(
            &PreparedSuccessorRouteV1::Healthy,
            &id("binding-a"),
            &id("adoption-a"),
            &predecessor,
            &id("binding-a"),
            &healthy,
            None,
        ));

        let mut recovery = foundation("recovery", 9, 4);
        recovery.key_generation = predecessor.key_generation;
        assert!(verify_stable_foundation_route_law_v1(
            &PreparedSuccessorRouteV1::Recovery,
            &id("binding-a"),
            &id("adoption-a"),
            &predecessor,
            &id("adoption-a"),
            &recovery,
            None,
        ));
    }

    #[test]
    fn new_foundation_routes_refuse_any_prior_or_parallel_adoption_event() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE c2_foundational_enrollment_adoptions (
                    adoption_sequence INTEGER PRIMARY KEY,
                    adoption_identity TEXT NOT NULL,
                    foundation_identity TEXT NOT NULL,
                    lineage TEXT NOT NULL
                );",
            )
            .unwrap();
        let foundation = id("globally-new-foundation");
        let adoption = id("first-and-only-adoption");
        let transaction = connection.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO c2_foundational_enrollment_adoptions
                 (adoption_sequence, adoption_identity, foundation_identity, lineage)
                 VALUES (1, ?1, ?2, 'ordinarySuccessorContinuity')",
                params![adoption.as_str(), foundation.as_str()],
            )
            .unwrap();
        refuse_reused_new_foundation_v1(&transaction, &foundation, &adoption).unwrap();

        transaction
            .execute(
                "INSERT INTO c2_foundational_enrollment_adoptions
                 (adoption_sequence, adoption_identity, foundation_identity, lineage)
                 VALUES (2, ?1, ?2, 'restoreHistorical')",
                params![id("later-restore-adoption").as_str(), foundation.as_str()],
            )
            .unwrap();
        assert!(matches!(
            refuse_reused_new_foundation_v1(&transaction, &foundation, &adoption),
            Err(DurableTerminalAppendRefusalV1::FoundationMismatch)
        ));
    }
}
