//! Closed post-completion C2 global-refusal (`G`) journal.
//!
//! `G` is not an authority ledger.  It retains one closed class of signed,
//! per-candidate refusal evidence after installation completion.  Before that
//! boundary, failure is explicitly no-write and cannot fabricate a G frame.

use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{CanonicalizationError, Sha256Digest, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact G carrier schema.
pub const C2_GLOBAL_REFUSAL_SCHEMA_V1: &str = "nq.c2_global_refusal.v1";
/// Exact G carrier identity domain.
pub const C2_GLOBAL_REFUSAL_IDENTITY_DOMAIN_V1: &str = "nq.c2.global_refusal.identity.v1";
/// Exact Store-integrity signature domain for G records.
pub const C2_GLOBAL_REFUSAL_SIGNATURE_DOMAIN_V1: &str =
    "nq.c2.global_refusal.store_integrity_signature.v1";
/// Exact reservation schema.
pub const C2_G_RESERVATION_SCHEMA_V1: &str = "nq.c2_g_reservation.v1";
const IJSON_SAFE_U64: u64 = 9_007_199_254_740_991;
const SCHEMA_FAILURE_BYTES_MAX_V1: usize = 65_536;

/// Frozen, closed G vocabulary.  No `Other` or string-selected variant exists.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2GlobalFailureClassV1 {
    /// Custody budget exhaustion or a bounded write refusal.
    CustodyBudgetOrWriteRefusal,
    /// Failure to allocate an exact candidate carrier.
    FailedCandidateCarrierAllocation,
    /// Store pressure or an authenticated permanent write fence.
    StorePressureOrWriteFence,
    /// Reconciliation failed and no candidate M became valid.
    CapacityReconciliationFailure,
}

/// All exact source coordinates of one G refusal, excluding identity/signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2GlobalRefusalInputV1 {
    pub occurrence_id: String,
    pub physical_store_generation_identity: Sha256Digest,
    pub signer_lifecycle_root_identity: Sha256Digest,
    pub scope_identity: Sha256Digest,
    pub resident_identity: Sha256Digest,
    pub resident_generation: u64,
    pub host_role: String,
    pub role_manifest_generation: u64,
    pub authority_domain: String,
    pub signer_scope_policy_identity: Sha256Digest,
    pub signer_scope_policy_version: u64,
    pub active_store_policy_identity: Sha256Digest,
    pub predecessor_g_root_identity: Sha256Digest,
    pub predecessor_g_cursor: u64,
    pub failure_class: C2GlobalFailureClassV1,
    /// Exact canonical failure bytes before base64 wire encoding.
    pub bounded_canonical_failure_bytes: Vec<u8>,
    pub failure_cut: u64,
    pub signer_key_generation: u64,
}

/// Store-private proof that currentness, standing, policy, and the active key
/// were already verified.  There is no public constructor.
#[derive(Clone)]
pub(crate) struct VerifiedGlobalRefusalSignerV1 {
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    signer_lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    active_store_policy_identity: Sha256Digest,
    signer_key_generation: u64,
    verifying_key: [u8; 32],
}

impl VerifiedGlobalRefusalSignerV1 {
    /// Store-owned bridge used only after exact current-binding verification.
    pub(crate) fn bind_after_current_signer_verification(
        occurrence_id: String,
        physical_store_generation_identity: Sha256Digest,
        signer_lifecycle_root_identity: Sha256Digest,
        scope_identity: Sha256Digest,
        active_store_policy_identity: Sha256Digest,
        signer_key_generation: u64,
        verifying_key: [u8; 32],
    ) -> Result<Self, C2GlobalRefusalRefusalV1> {
        validate_text(&occurrence_id)?;
        if signer_key_generation > IJSON_SAFE_U64
            || VerifyingKey::from_bytes(&verifying_key).is_err()
        {
            return Err(C2GlobalRefusalRefusalV1::SignerMismatch);
        }
        Ok(Self {
            occurrence_id,
            physical_store_generation_identity,
            signer_lifecycle_root_identity,
            scope_identity,
            active_store_policy_identity,
            signer_key_generation,
            verifying_key,
        })
    }
}

#[derive(Serialize)]
struct C2GlobalRefusalUnsignedBodyV1<'a> {
    schema: &'static str,
    schema_version: u8,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    signer_lifecycle_root_identity: &'a Sha256Digest,
    scope_identity: &'a Sha256Digest,
    resident_identity: &'a Sha256Digest,
    resident_generation: u64,
    host_role: &'a str,
    role_manifest_generation: u64,
    authority_domain: &'a str,
    signer_scope_policy_identity: &'a Sha256Digest,
    signer_scope_policy_version: u64,
    active_store_policy_identity: &'a Sha256Digest,
    predecessor_g_root_identity: &'a Sha256Digest,
    predecessor_g_cursor: u64,
    failure_class: C2GlobalFailureClassV1,
    bounded_canonical_failure_bytes: String,
    failure_cut: u64,
    signer_key_generation: u64,
    signature_algorithm: &'static str,
}

#[derive(Serialize)]
struct C2GlobalRefusalIdentityPreimageV1<'a> {
    domain: &'static str,
    body: &'a C2GlobalRefusalUnsignedBodyV1<'a>,
}

#[derive(Serialize)]
struct C2GlobalRefusalSignedBodyV1<'a> {
    refusal_identity: &'a Sha256Digest,
    body: &'a C2GlobalRefusalUnsignedBodyV1<'a>,
}

/// Canonical closed-vocabulary G carrier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2GlobalRefusalV1 {
    schema: &'static str,
    schema_version: u8,
    refusal_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    signer_lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    resident_identity: Sha256Digest,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    signer_scope_policy_identity: Sha256Digest,
    signer_scope_policy_version: u64,
    active_store_policy_identity: Sha256Digest,
    predecessor_g_root_identity: Sha256Digest,
    predecessor_g_cursor: u64,
    failure_class: C2GlobalFailureClassV1,
    bounded_canonical_failure_bytes: String,
    failure_cut: u64,
    signer_key_generation: u64,
    signature_algorithm: &'static str,
    signature: String,
}

impl C2GlobalRefusalV1 {
    /// Exact refusal identity.
    #[must_use]
    pub const fn identity(&self) -> &Sha256Digest {
        &self.refusal_identity
    }

    /// Exact Store occurrence bound into this verified G refusal.
    #[must_use]
    pub fn occurrence_id(&self) -> &str {
        &self.occurrence_id
    }

    /// Exact physical Store generation bound into this verified G refusal.
    #[must_use]
    pub const fn physical_store_generation_identity(&self) -> &Sha256Digest {
        &self.physical_store_generation_identity
    }

    /// Exact predecessor G root.
    #[must_use]
    pub const fn predecessor_g_root(&self) -> &Sha256Digest {
        &self.predecessor_g_root_identity
    }

    /// Exact predecessor G cursor.
    #[must_use]
    pub const fn predecessor_g_cursor(&self) -> u64 {
        self.predecessor_g_cursor
    }

    /// One of the four frozen failure classes.
    #[must_use]
    pub const fn failure_class(&self) -> C2GlobalFailureClassV1 {
        self.failure_class
    }
}

/// Exact success markers used by the matrix rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2GlobalRefusalDispositionV1 {
    GVocabularyIsExactlyFourClosedClassesOccurrenceGenerationPolicyVerified,
    GContainsNoBootstrapKeyPolicyGenerationRecordsBContainsVerified,
    PostCompletionCandidateFailurePersistedUnderG,
}

/// Typed refusal for G construction and verification.
#[derive(Debug, Error)]
pub enum C2GlobalRefusalRefusalV1 {
    #[error("a bounded text coordinate is empty or noncanonical")]
    InvalidText,
    #[error("a structural generation, version, cursor, or cut is outside its exact range")]
    InvalidStructuralCoordinate,
    #[error("failure bytes are empty, noncanonical, or exceed the installed/schema bound")]
    FailureBytesOutOfBounds,
    #[error("the purported signer does not match the exact active current signer coordinates")]
    SignerMismatch,
    #[error("the Store-integrity signature is malformed or invalid in the global-refusal domain")]
    SignatureInvalid,
    #[error("the record identity or canonical fields were substituted")]
    IdentityMismatch,
    #[error("a record family was placed in the wrong B/G vocabulary")]
    CrossPlacement,
    #[error("canonical identity computation failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
}

fn validate_text(value: &str) -> Result<(), C2GlobalRefusalRefusalV1> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@-".contains(&byte))
    {
        Err(C2GlobalRefusalRefusalV1::InvalidText)
    } else {
        Ok(())
    }
}

fn validate_input(
    input: &C2GlobalRefusalInputV1,
    installed_entry_max_bytes: u32,
) -> Result<(), C2GlobalRefusalRefusalV1> {
    validate_text(&input.occurrence_id)?;
    validate_text(&input.host_role)?;
    validate_text(&input.authority_domain)?;
    if input.resident_generation == 0
        || input.resident_generation > IJSON_SAFE_U64
        || input.role_manifest_generation == 0
        || input.role_manifest_generation > IJSON_SAFE_U64
        || input.signer_scope_policy_version == 0
        || input.signer_scope_policy_version > IJSON_SAFE_U64
        || input.predecessor_g_cursor > IJSON_SAFE_U64
        || input.failure_cut == 0
        || input.failure_cut > IJSON_SAFE_U64
        || input.signer_key_generation > IJSON_SAFE_U64
    {
        return Err(C2GlobalRefusalRefusalV1::InvalidStructuralCoordinate);
    }
    let bytes_len = input.bounded_canonical_failure_bytes.len();
    if bytes_len == 0
        || bytes_len > usize::try_from(installed_entry_max_bytes).unwrap_or(usize::MAX)
        || base64_encoded_len(bytes_len) > SCHEMA_FAILURE_BYTES_MAX_V1
    {
        return Err(C2GlobalRefusalRefusalV1::FailureBytesOutOfBounds);
    }
    Ok(())
}

fn unsigned_body(input: &C2GlobalRefusalInputV1) -> C2GlobalRefusalUnsignedBodyV1<'_> {
    C2GlobalRefusalUnsignedBodyV1 {
        schema: C2_GLOBAL_REFUSAL_SCHEMA_V1,
        schema_version: 1,
        occurrence_id: &input.occurrence_id,
        physical_store_generation_identity: &input.physical_store_generation_identity,
        signer_lifecycle_root_identity: &input.signer_lifecycle_root_identity,
        scope_identity: &input.scope_identity,
        resident_identity: &input.resident_identity,
        resident_generation: input.resident_generation,
        host_role: &input.host_role,
        role_manifest_generation: input.role_manifest_generation,
        authority_domain: &input.authority_domain,
        signer_scope_policy_identity: &input.signer_scope_policy_identity,
        signer_scope_policy_version: input.signer_scope_policy_version,
        active_store_policy_identity: &input.active_store_policy_identity,
        predecessor_g_root_identity: &input.predecessor_g_root_identity,
        predecessor_g_cursor: input.predecessor_g_cursor,
        failure_class: input.failure_class,
        bounded_canonical_failure_bytes: base64_encode(&input.bounded_canonical_failure_bytes),
        failure_cut: input.failure_cut,
        signer_key_generation: input.signer_key_generation,
        signature_algorithm: "ed25519",
    }
}

fn refusal_identity(
    body: &C2GlobalRefusalUnsignedBodyV1<'_>,
) -> Result<Sha256Digest, CanonicalizationError> {
    semantic_digest(&C2GlobalRefusalIdentityPreimageV1 {
        domain: C2_GLOBAL_REFUSAL_IDENTITY_DOMAIN_V1,
        body,
    })
}

/// Exact domain-separated bytes consumed by the typed transition coordinator.
pub(crate) fn global_refusal_signature_preimage_v1(
    input: &C2GlobalRefusalInputV1,
) -> Result<Vec<u8>, C2GlobalRefusalRefusalV1> {
    let body = unsigned_body(input);
    let identity = refusal_identity(&body)?;
    let canonical = canonical_json_bytes(&C2GlobalRefusalSignedBodyV1 {
        refusal_identity: &identity,
        body: &body,
    })?;
    let mut preimage =
        Vec::with_capacity(C2_GLOBAL_REFUSAL_SIGNATURE_DOMAIN_V1.len() + 1 + canonical.len());
    preimage.extend_from_slice(C2_GLOBAL_REFUSAL_SIGNATURE_DOMAIN_V1.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

/// N-43: construct one exact signed member of the four-class G vocabulary.
pub(crate) fn construct_n_43_g_vocabulary_is_exactly_four_closed_classes(
    input: C2GlobalRefusalInputV1,
    installed_entry_max_bytes: u32,
    signer: &VerifiedGlobalRefusalSignerV1,
    signature: [u8; 64],
) -> Result<C2GlobalRefusalV1, C2GlobalRefusalRefusalV1> {
    validate_input(&input, installed_entry_max_bytes)?;
    if input.occurrence_id != signer.occurrence_id
        || input.physical_store_generation_identity != signer.physical_store_generation_identity
        || input.signer_lifecycle_root_identity != signer.signer_lifecycle_root_identity
        || input.scope_identity != signer.scope_identity
        || input.active_store_policy_identity != signer.active_store_policy_identity
        || input.signer_key_generation != signer.signer_key_generation
    {
        return Err(C2GlobalRefusalRefusalV1::SignerMismatch);
    }
    let preimage = global_refusal_signature_preimage_v1(&input)?;
    VerifyingKey::from_bytes(&signer.verifying_key)
        .map_err(|_| C2GlobalRefusalRefusalV1::SignatureInvalid)?
        .verify_strict(&preimage, &Signature::from_bytes(&signature))
        .map_err(|_| C2GlobalRefusalRefusalV1::SignatureInvalid)?;
    let body = unsigned_body(&input);
    let identity = refusal_identity(&body)?;
    let schema = body.schema;
    let schema_version = body.schema_version;
    let bounded_canonical_failure_bytes = body.bounded_canonical_failure_bytes.clone();
    let signature_algorithm = body.signature_algorithm;
    drop(body);
    let record = C2GlobalRefusalV1 {
        schema,
        schema_version,
        refusal_identity: identity,
        occurrence_id: input.occurrence_id,
        physical_store_generation_identity: input.physical_store_generation_identity,
        signer_lifecycle_root_identity: input.signer_lifecycle_root_identity,
        scope_identity: input.scope_identity,
        resident_identity: input.resident_identity,
        resident_generation: input.resident_generation,
        host_role: input.host_role,
        role_manifest_generation: input.role_manifest_generation,
        authority_domain: input.authority_domain,
        signer_scope_policy_identity: input.signer_scope_policy_identity,
        signer_scope_policy_version: input.signer_scope_policy_version,
        active_store_policy_identity: input.active_store_policy_identity,
        predecessor_g_root_identity: input.predecessor_g_root_identity,
        predecessor_g_cursor: input.predecessor_g_cursor,
        failure_class: input.failure_class,
        bounded_canonical_failure_bytes,
        failure_cut: input.failure_cut,
        signer_key_generation: input.signer_key_generation,
        signature_algorithm,
        signature: hex::encode(signature),
    };
    verify_n_43_g_vocabulary_is_exactly_four_closed_classes(
        &record,
        installed_entry_max_bytes,
        signer,
    )?;
    Ok(record)
}

fn record_as_input(
    record: &C2GlobalRefusalV1,
) -> Result<C2GlobalRefusalInputV1, C2GlobalRefusalRefusalV1> {
    let bytes = base64_decode(&record.bounded_canonical_failure_bytes)
        .ok_or(C2GlobalRefusalRefusalV1::FailureBytesOutOfBounds)?;
    Ok(C2GlobalRefusalInputV1 {
        occurrence_id: record.occurrence_id.clone(),
        physical_store_generation_identity: record.physical_store_generation_identity.clone(),
        signer_lifecycle_root_identity: record.signer_lifecycle_root_identity.clone(),
        scope_identity: record.scope_identity.clone(),
        resident_identity: record.resident_identity.clone(),
        resident_generation: record.resident_generation,
        host_role: record.host_role.clone(),
        role_manifest_generation: record.role_manifest_generation,
        authority_domain: record.authority_domain.clone(),
        signer_scope_policy_identity: record.signer_scope_policy_identity.clone(),
        signer_scope_policy_version: record.signer_scope_policy_version,
        active_store_policy_identity: record.active_store_policy_identity.clone(),
        predecessor_g_root_identity: record.predecessor_g_root_identity.clone(),
        predecessor_g_cursor: record.predecessor_g_cursor,
        failure_class: record.failure_class,
        bounded_canonical_failure_bytes: bytes,
        failure_cut: record.failure_cut,
        signer_key_generation: record.signer_key_generation,
    })
}

/// N-43: verify identity, closed class, exact active signer, and signature.
pub(crate) fn verify_n_43_g_vocabulary_is_exactly_four_closed_classes(
    record: &C2GlobalRefusalV1,
    installed_entry_max_bytes: u32,
    signer: &VerifiedGlobalRefusalSignerV1,
) -> Result<C2GlobalRefusalDispositionV1, C2GlobalRefusalRefusalV1> {
    let input = record_as_input(record)?;
    validate_input(&input, installed_entry_max_bytes)?;
    if record.schema != C2_GLOBAL_REFUSAL_SCHEMA_V1
        || record.schema_version != 1
        || record.signature_algorithm != "ed25519"
        || input.occurrence_id != signer.occurrence_id
        || input.physical_store_generation_identity != signer.physical_store_generation_identity
        || input.signer_lifecycle_root_identity != signer.signer_lifecycle_root_identity
        || input.scope_identity != signer.scope_identity
        || input.active_store_policy_identity != signer.active_store_policy_identity
        || input.signer_key_generation != signer.signer_key_generation
    {
        return Err(C2GlobalRefusalRefusalV1::SignerMismatch);
    }
    let body = unsigned_body(&input);
    if refusal_identity(&body)? != record.refusal_identity {
        return Err(C2GlobalRefusalRefusalV1::IdentityMismatch);
    }
    let signature_bytes: [u8; 64] = hex::decode(&record.signature)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(C2GlobalRefusalRefusalV1::SignatureInvalid)?;
    VerifyingKey::from_bytes(&signer.verifying_key)
        .map_err(|_| C2GlobalRefusalRefusalV1::SignatureInvalid)?
        .verify_strict(
            &global_refusal_signature_preimage_v1(&input)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| C2GlobalRefusalRefusalV1::SignatureInvalid)?;
    Ok(C2GlobalRefusalDispositionV1::GVocabularyIsExactlyFourClosedClassesOccurrenceGenerationPolicyVerified)
}

/// Families used solely to prove the fixed B/G placement partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2JournalRecordFamilyV1 {
    Bootstrap,
    KeyEnrollment,
    ActivePolicy,
    StoreGeneration,
    GlobalRefusal,
    PerInvocationOutcomeOutsideGlobalRefusal,
}

/// Closed carrier placement target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2JournalCarrierV1 {
    BootstrapB,
    GlobalRefusalG,
}

/// N-44: construct only an allowed fixed-vocabulary placement.
pub fn construct_n_44_g_contains_no_bootstrap_key_policy_generation(
    carrier: C2JournalCarrierV1,
    family: C2JournalRecordFamilyV1,
) -> Result<C2GlobalRefusalDispositionV1, C2GlobalRefusalRefusalV1> {
    let permitted = matches!(
        (carrier, family),
        (
            C2JournalCarrierV1::BootstrapB,
            C2JournalRecordFamilyV1::Bootstrap
                | C2JournalRecordFamilyV1::KeyEnrollment
                | C2JournalRecordFamilyV1::ActivePolicy
                | C2JournalRecordFamilyV1::StoreGeneration
        ) | (
            C2JournalCarrierV1::GlobalRefusalG,
            C2JournalRecordFamilyV1::GlobalRefusal
        )
    );
    if permitted {
        Ok(C2GlobalRefusalDispositionV1::GContainsNoBootstrapKeyPolicyGenerationRecordsBContainsVerified)
    } else {
        Err(C2GlobalRefusalRefusalV1::CrossPlacement)
    }
}

/// N-44 verifier target.
pub fn verify_n_44_g_contains_no_bootstrap_key_policy_generation(
    carrier: C2JournalCarrierV1,
    family: C2JournalRecordFamilyV1,
) -> Result<C2GlobalRefusalDispositionV1, C2GlobalRefusalRefusalV1> {
    construct_n_44_g_contains_no_bootstrap_key_policy_generation(carrier, family)
}

/// Exact pre-G stages for which no G record or G-derived standing exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreGInstallationStageV1 {
    S0PreFilesystem,
    S1PreGAllocation,
    S2GAllocatedUnauthenticated,
}

/// Inert proof that an infrastructure failure attempted no G write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreGFailureDispositionV1 {
    PreGFailureNoFabricatedG,
}

/// N-45: classify the exact pre-G no-write branch.
#[must_use]
pub const fn construct_n_45_pre_g_failure_disposition(
    _stage: PreGInstallationStageV1,
) -> PreGFailureDispositionV1 {
    PreGFailureDispositionV1::PreGFailureNoFabricatedG
}

/// N-45: verify the branch contains no fabricated G effect.
pub const fn verify_n_45_pre_g_no_fabricated_g(
    disposition: PreGFailureDispositionV1,
) -> Result<(), C2GReservationRefusalV1> {
    match disposition {
        PreGFailureDispositionV1::PreGFailureNoFabricatedG => Ok(()),
    }
}

/// Exact authenticated G frontier before a candidate effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2GFrontierV1 {
    pub occurrence_id: String,
    pub physical_store_generation_identity: Sha256Digest,
    pub signer_lifecycle_root_identity: Sha256Digest,
    pub scope_identity: Sha256Digest,
    pub resident_identity: Sha256Digest,
    pub resident_generation: u64,
    pub host_role: String,
    pub role_manifest_generation: u64,
    pub authority_domain: String,
    pub signer_scope_policy_identity: Sha256Digest,
    pub signer_scope_policy_version: u64,
    pub active_store_policy_identity: Sha256Digest,
    pub g_root_identity: Sha256Digest,
    pub g_cursor: u64,
    pub used_slots: u32,
    pub used_payload_bytes: u64,
    pub payload_bound: u64,
    pub max_entries: u32,
    pub entry_max_bytes: u32,
}

/// Closed reservation state.  A reserved value is consumed by value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2GReservationStateV1 {
    Reserved,
    Released,
    ConsumedFailure,
}

/// Exact pre-effect G reservation record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2GReservationV1 {
    schema: &'static str,
    schema_version: u8,
    reservation_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    signer_lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    resident_identity: Sha256Digest,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    signer_scope_policy_identity: Sha256Digest,
    signer_scope_policy_version: u64,
    active_store_policy_identity: Sha256Digest,
    g_root_identity: Sha256Digest,
    g_cursor: u64,
    reserved_slot: u32,
    reservation_state: C2GReservationStateV1,
    reserved_before_candidate_effect: bool,
    reservation_cut: u64,
    #[serde(skip)]
    entry_max_bytes: u32,
}

#[derive(Serialize)]
struct ReservationPreimage<'a> {
    domain: &'static str,
    schema: &'static str,
    schema_version: u8,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    signer_lifecycle_root_identity: &'a Sha256Digest,
    scope_identity: &'a Sha256Digest,
    resident_identity: &'a Sha256Digest,
    resident_generation: u64,
    host_role: &'a str,
    role_manifest_generation: u64,
    authority_domain: &'a str,
    signer_scope_policy_identity: &'a Sha256Digest,
    signer_scope_policy_version: u64,
    active_store_policy_identity: &'a Sha256Digest,
    g_root_identity: &'a Sha256Digest,
    g_cursor: u64,
    reserved_slot: u32,
    reservation_state: C2GReservationStateV1,
    reserved_before_candidate_effect: bool,
    reservation_cut: u64,
}

/// Permanent fence derived only from an authenticated exhausted frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2GPermanentWriteFenceV1 {
    pub g_root_identity: Sha256Digest,
    pub g_cursor: u64,
    pub active_store_policy_identity: Sha256Digest,
    pub fence_identity: Sha256Digest,
}

/// Reservation lifecycle success markers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2GReservationDispositionV1 {
    ReservedBeforeCandidateEffect,
    ReleasedOnCandidateSuccess,
    ConsumedByExactlyOneFailure,
    ExhaustionFencedBeforeCandidateEffect,
}

/// Exact reservation/refusal failures.
#[derive(Debug, Error)]
pub enum C2GReservationRefusalV1 {
    #[error("the G frontier is malformed or outside its installed bounds")]
    MalformedFrontier,
    #[error("G cannot reserve one maximum entry and one slot; permanent fence required")]
    Exhausted(C2GPermanentWriteFenceV1),
    #[error("the reservation is stale, already consumed, or associated with another G frontier")]
    ReservationMismatch,
    #[error("the post-completion refusal does not bind the exact reserved G predecessor")]
    RefusalReservationSplice,
    #[error("canonical identity computation failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
}

fn validate_frontier(frontier: &C2GFrontierV1) -> Result<(), C2GReservationRefusalV1> {
    validate_text(&frontier.occurrence_id)
        .and_then(|()| validate_text(&frontier.host_role))
        .and_then(|()| validate_text(&frontier.authority_domain))
        .map_err(|_| C2GReservationRefusalV1::MalformedFrontier)?;
    if frontier.resident_generation == 0
        || frontier.resident_generation > IJSON_SAFE_U64
        || frontier.role_manifest_generation == 0
        || frontier.role_manifest_generation > IJSON_SAFE_U64
        || frontier.signer_scope_policy_version == 0
        || frontier.signer_scope_policy_version > IJSON_SAFE_U64
        || frontier.g_cursor > IJSON_SAFE_U64
        || frontier.used_payload_bytes > frontier.payload_bound
        || frontier.used_slots > frontier.max_entries
        || frontier.max_entries == 0
        || frontier.entry_max_bytes == 0
    {
        Err(C2GReservationRefusalV1::MalformedFrontier)
    } else {
        Ok(())
    }
}

fn reservation_identity(
    reservation: &C2GReservationV1,
) -> Result<Sha256Digest, CanonicalizationError> {
    semantic_digest(&ReservationPreimage {
        domain: "nq.c2.g_reservation.identity.v1",
        schema: reservation.schema,
        schema_version: reservation.schema_version,
        occurrence_id: &reservation.occurrence_id,
        physical_store_generation_identity: &reservation.physical_store_generation_identity,
        signer_lifecycle_root_identity: &reservation.signer_lifecycle_root_identity,
        scope_identity: &reservation.scope_identity,
        resident_identity: &reservation.resident_identity,
        resident_generation: reservation.resident_generation,
        host_role: &reservation.host_role,
        role_manifest_generation: reservation.role_manifest_generation,
        authority_domain: &reservation.authority_domain,
        signer_scope_policy_identity: &reservation.signer_scope_policy_identity,
        signer_scope_policy_version: reservation.signer_scope_policy_version,
        active_store_policy_identity: &reservation.active_store_policy_identity,
        g_root_identity: &reservation.g_root_identity,
        g_cursor: reservation.g_cursor,
        reserved_slot: reservation.reserved_slot,
        reservation_state: reservation.reservation_state,
        reserved_before_candidate_effect: reservation.reserved_before_candidate_effect,
        reservation_cut: reservation.reservation_cut,
    })
}

fn exhaustion_fence(
    frontier: &C2GFrontierV1,
) -> Result<C2GPermanentWriteFenceV1, CanonicalizationError> {
    #[derive(Serialize)]
    struct FencePreimage<'a> {
        domain: &'static str,
        g_root_identity: &'a Sha256Digest,
        g_cursor: u64,
        active_store_policy_identity: &'a Sha256Digest,
        reason: &'static str,
    }
    let fence_identity = semantic_digest(&FencePreimage {
        domain: "nq.c2.g_write_fence.identity.v1",
        g_root_identity: &frontier.g_root_identity,
        g_cursor: frontier.g_cursor,
        active_store_policy_identity: &frontier.active_store_policy_identity,
        reason: "insufficient_maximum_entry_or_slot",
    })?;
    Ok(C2GPermanentWriteFenceV1 {
        g_root_identity: frontier.g_root_identity.clone(),
        g_cursor: frontier.g_cursor,
        active_store_policy_identity: frontier.active_store_policy_identity.clone(),
        fence_identity,
    })
}

/// N-87: reserve one maximum G entry and one slot before candidate effect.
pub fn reserve_n_87_before_candidate_effect(
    frontier: &C2GFrontierV1,
    reservation_cut: u64,
) -> Result<C2GReservationV1, C2GReservationRefusalV1> {
    validate_frontier(frontier)?;
    if reservation_cut == 0 || reservation_cut > IJSON_SAFE_U64 {
        return Err(C2GReservationRefusalV1::MalformedFrontier);
    }
    let remaining_bytes = frontier.payload_bound - frontier.used_payload_bytes;
    if frontier.used_slots >= frontier.max_entries
        || remaining_bytes < u64::from(frontier.entry_max_bytes)
    {
        return Err(C2GReservationRefusalV1::Exhausted(exhaustion_fence(
            frontier,
        )?));
    }
    let mut reservation = C2GReservationV1 {
        schema: C2_G_RESERVATION_SCHEMA_V1,
        schema_version: 1,
        reservation_identity: semantic_digest(&"nq.c2.g_reservation.uninitialized.v1")?,
        occurrence_id: frontier.occurrence_id.clone(),
        physical_store_generation_identity: frontier.physical_store_generation_identity.clone(),
        signer_lifecycle_root_identity: frontier.signer_lifecycle_root_identity.clone(),
        scope_identity: frontier.scope_identity.clone(),
        resident_identity: frontier.resident_identity.clone(),
        resident_generation: frontier.resident_generation,
        host_role: frontier.host_role.clone(),
        role_manifest_generation: frontier.role_manifest_generation,
        authority_domain: frontier.authority_domain.clone(),
        signer_scope_policy_identity: frontier.signer_scope_policy_identity.clone(),
        signer_scope_policy_version: frontier.signer_scope_policy_version,
        active_store_policy_identity: frontier.active_store_policy_identity.clone(),
        g_root_identity: frontier.g_root_identity.clone(),
        g_cursor: frontier.g_cursor,
        reserved_slot: frontier.used_slots,
        reservation_state: C2GReservationStateV1::Reserved,
        reserved_before_candidate_effect: true,
        reservation_cut,
        entry_max_bytes: frontier.entry_max_bytes,
    };
    reservation.reservation_identity = reservation_identity(&reservation)?;
    verify_n_87_reserve_release_consume_and_exhaustion_fence(&reservation, frontier)?;
    Ok(reservation)
}

/// N-87: verify exact frontier association and one of the three lifecycle states.
pub fn verify_n_87_reserve_release_consume_and_exhaustion_fence(
    reservation: &C2GReservationV1,
    frontier: &C2GFrontierV1,
) -> Result<C2GReservationDispositionV1, C2GReservationRefusalV1> {
    validate_frontier(frontier)?;
    if reservation.schema != C2_G_RESERVATION_SCHEMA_V1
        || reservation.schema_version != 1
        || !reservation.reserved_before_candidate_effect
        || reservation.occurrence_id != frontier.occurrence_id
        || reservation.physical_store_generation_identity
            != frontier.physical_store_generation_identity
        || reservation.signer_lifecycle_root_identity != frontier.signer_lifecycle_root_identity
        || reservation.scope_identity != frontier.scope_identity
        || reservation.active_store_policy_identity != frontier.active_store_policy_identity
        || reservation.g_root_identity != frontier.g_root_identity
        || reservation.g_cursor != frontier.g_cursor
        || reservation.reserved_slot != frontier.used_slots
        || reservation.entry_max_bytes != frontier.entry_max_bytes
        || reservation_identity(reservation)? != reservation.reservation_identity
    {
        return Err(C2GReservationRefusalV1::ReservationMismatch);
    }
    Ok(match reservation.reservation_state {
        C2GReservationStateV1::Reserved => {
            C2GReservationDispositionV1::ReservedBeforeCandidateEffect
        }
        C2GReservationStateV1::Released => C2GReservationDispositionV1::ReleasedOnCandidateSuccess,
        C2GReservationStateV1::ConsumedFailure => {
            C2GReservationDispositionV1::ConsumedByExactlyOneFailure
        }
    })
}

/// Release the by-value hold on candidate success; no G frame is emitted.
pub fn release_g_reservation_on_success_v1(
    mut reservation: C2GReservationV1,
) -> Result<C2GReservationV1, C2GReservationRefusalV1> {
    if reservation.reservation_state != C2GReservationStateV1::Reserved {
        return Err(C2GReservationRefusalV1::ReservationMismatch);
    }
    reservation.reservation_state = C2GReservationStateV1::Released;
    reservation.reservation_identity = reservation_identity(&reservation)?;
    Ok(reservation)
}

/// Post-completion persistence evidence: exact record plus consumed one-use hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2PostCompletionGRefusalV1 {
    record: C2GlobalRefusalV1,
    consumed_reservation: C2GReservationV1,
}

impl C2PostCompletionGRefusalV1 {
    /// Exact refusal that must be appended under G.
    #[must_use]
    pub const fn record(&self) -> &C2GlobalRefusalV1 {
        &self.record
    }
}

/// N-45A: consume one exact reservation for one exact predecessor-bound refusal.
pub fn construct_n_45a_post_completion_candidate_g_refusal(
    mut reservation: C2GReservationV1,
    record: C2GlobalRefusalV1,
) -> Result<C2PostCompletionGRefusalV1, C2GReservationRefusalV1> {
    if reservation.reservation_state != C2GReservationStateV1::Reserved
        || record.predecessor_g_root_identity != reservation.g_root_identity
        || record.predecessor_g_cursor != reservation.g_cursor
        || record.occurrence_id != reservation.occurrence_id
        || record.physical_store_generation_identity
            != reservation.physical_store_generation_identity
        || record.signer_lifecycle_root_identity != reservation.signer_lifecycle_root_identity
        || record.scope_identity != reservation.scope_identity
        || record.active_store_policy_identity != reservation.active_store_policy_identity
        || base64_decode(&record.bounded_canonical_failure_bytes).is_none_or(|bytes| {
            bytes.len() > usize::try_from(reservation.entry_max_bytes).unwrap_or(usize::MAX)
        })
    {
        return Err(C2GReservationRefusalV1::RefusalReservationSplice);
    }
    reservation.reservation_state = C2GReservationStateV1::ConsumedFailure;
    reservation.reservation_identity = reservation_identity(&reservation)?;
    Ok(C2PostCompletionGRefusalV1 {
        record,
        consumed_reservation: reservation,
    })
}

/// N-45A verifier target.
pub fn verify_n_45a_post_completion_candidate_g_refusal(
    evidence: &C2PostCompletionGRefusalV1,
) -> Result<C2GlobalRefusalDispositionV1, C2GReservationRefusalV1> {
    if evidence.consumed_reservation.reservation_state != C2GReservationStateV1::ConsumedFailure
        || evidence.record.predecessor_g_root_identity
            != evidence.consumed_reservation.g_root_identity
        || evidence.record.predecessor_g_cursor != evidence.consumed_reservation.g_cursor
    {
        Err(C2GReservationRefusalV1::RefusalReservationSplice)
    } else {
        Ok(C2GlobalRefusalDispositionV1::PostCompletionCandidateFailurePersistedUnderG)
    }
}

fn base64_encoded_len(input_len: usize) -> usize {
    input_len.saturating_add(2) / 3 * 4
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(base64_encoded_len(input.len()));
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[usize::from(first >> 2)] as char);
        output.push(TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))] as char);
        if chunk.len() > 1 {
            output.push(TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[usize::from(third & 0x3f)] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let a = value(chunk[0])?;
        let b = value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            value(chunk[3])?
        };
        if (!last && (chunk[2] == b'=' || chunk[3] == b'='))
            || (chunk[2] == b'=' && chunk[3] != b'=')
        {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    if base64_encode(&output) == input {
        Some(output)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn input() -> C2GlobalRefusalInputV1 {
        C2GlobalRefusalInputV1 {
            occurrence_id: "store:one".into(),
            physical_store_generation_identity: digest('a'),
            signer_lifecycle_root_identity: digest('b'),
            scope_identity: digest('c'),
            resident_identity: digest('d'),
            resident_generation: 1,
            host_role: "nq_store".into(),
            role_manifest_generation: 1,
            authority_domain: "nq.runtime".into(),
            signer_scope_policy_identity: digest('e'),
            signer_scope_policy_version: 1,
            active_store_policy_identity: digest('f'),
            predecessor_g_root_identity: digest('1'),
            predecessor_g_cursor: 0,
            failure_class: C2GlobalFailureClassV1::StorePressureOrWriteFence,
            bounded_canonical_failure_bytes: br#"{"reason":"pressure"}"#.to_vec(),
            failure_cut: 10,
            signer_key_generation: 2,
        }
    }

    fn signed_record() -> (C2GlobalRefusalV1, VerifiedGlobalRefusalSignerV1) {
        let input = input();
        let key = SigningKey::from_bytes(&[7; 32]);
        let signer = VerifiedGlobalRefusalSignerV1::bind_after_current_signer_verification(
            input.occurrence_id.clone(),
            input.physical_store_generation_identity.clone(),
            input.signer_lifecycle_root_identity.clone(),
            input.scope_identity.clone(),
            input.active_store_policy_identity.clone(),
            input.signer_key_generation,
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        let signature = key.sign(&global_refusal_signature_preimage_v1(&input).unwrap());
        let record = construct_n_43_g_vocabulary_is_exactly_four_closed_classes(
            input,
            4096,
            &signer,
            signature.to_bytes(),
        )
        .unwrap();
        (record, signer)
    }

    fn frontier() -> C2GFrontierV1 {
        let input = input();
        C2GFrontierV1 {
            occurrence_id: input.occurrence_id,
            physical_store_generation_identity: input.physical_store_generation_identity,
            signer_lifecycle_root_identity: input.signer_lifecycle_root_identity,
            scope_identity: input.scope_identity,
            resident_identity: input.resident_identity,
            resident_generation: input.resident_generation,
            host_role: input.host_role,
            role_manifest_generation: input.role_manifest_generation,
            authority_domain: input.authority_domain,
            signer_scope_policy_identity: input.signer_scope_policy_identity,
            signer_scope_policy_version: input.signer_scope_policy_version,
            active_store_policy_identity: input.active_store_policy_identity,
            g_root_identity: input.predecessor_g_root_identity,
            g_cursor: input.predecessor_g_cursor,
            used_slots: 0,
            used_payload_bytes: 0,
            payload_bound: 8192,
            max_entries: 2,
            entry_max_bytes: 4096,
        }
    }

    #[test]
    fn four_class_record_binds_active_key_and_rejects_substitution() {
        let (mut record, signer) = signed_record();
        assert_eq!(
            verify_n_43_g_vocabulary_is_exactly_four_closed_classes(&record, 4096, &signer)
                .unwrap(),
            C2GlobalRefusalDispositionV1::GVocabularyIsExactlyFourClosedClassesOccurrenceGenerationPolicyVerified
        );
        record.predecessor_g_cursor = 1;
        assert!(
            verify_n_43_g_vocabulary_is_exactly_four_closed_classes(&record, 4096, &signer)
                .is_err()
        );
    }

    #[test]
    fn cross_placement_is_closed_in_both_directions() {
        assert!(
            construct_n_44_g_contains_no_bootstrap_key_policy_generation(
                C2JournalCarrierV1::GlobalRefusalG,
                C2JournalRecordFamilyV1::KeyEnrollment,
            )
            .is_err()
        );
        assert!(
            construct_n_44_g_contains_no_bootstrap_key_policy_generation(
                C2JournalCarrierV1::BootstrapB,
                C2JournalRecordFamilyV1::GlobalRefusal,
            )
            .is_err()
        );
    }

    #[test]
    fn pre_g_is_no_write_and_post_completion_consumes_one_reservation() {
        verify_n_45_pre_g_no_fabricated_g(construct_n_45_pre_g_failure_disposition(
            PreGInstallationStageV1::S2GAllocatedUnauthenticated,
        ))
        .unwrap();
        let reservation = reserve_n_87_before_candidate_effect(&frontier(), 9).unwrap();
        let (record, _) = signed_record();
        let evidence =
            construct_n_45a_post_completion_candidate_g_refusal(reservation, record).unwrap();
        assert_eq!(
            verify_n_45a_post_completion_candidate_g_refusal(&evidence).unwrap(),
            C2GlobalRefusalDispositionV1::PostCompletionCandidateFailurePersistedUnderG
        );
    }

    #[test]
    fn reservation_releases_or_consumes_and_exhaustion_fences_before_effect() {
        let frontier = frontier();
        let reserved = reserve_n_87_before_candidate_effect(&frontier, 9).unwrap();
        assert_eq!(
            verify_n_87_reserve_release_consume_and_exhaustion_fence(&reserved, &frontier).unwrap(),
            C2GReservationDispositionV1::ReservedBeforeCandidateEffect
        );
        let released = release_g_reservation_on_success_v1(reserved).unwrap();
        assert_eq!(
            verify_n_87_reserve_release_consume_and_exhaustion_fence(&released, &frontier).unwrap(),
            C2GReservationDispositionV1::ReleasedOnCandidateSuccess
        );

        let mut exhausted = frontier;
        exhausted.used_slots = exhausted.max_entries;
        assert!(matches!(
            reserve_n_87_before_candidate_effect(&exhausted, 10),
            Err(C2GReservationRefusalV1::Exhausted(_))
        ));
    }

    #[test]
    fn base64_is_canonical_and_round_trips() {
        for bytes in [b"a".as_slice(), b"ab", b"abc", b"abcdef"] {
            let encoded = base64_encode(bytes);
            assert_eq!(base64_decode(&encoded).as_deref(), Some(bytes));
        }
        assert!(base64_decode("YQ=").is_none());
    }
}
