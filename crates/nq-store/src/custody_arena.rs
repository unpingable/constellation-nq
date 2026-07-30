//! Preallocated canonical custody for one governed execution.
//!
//! Future product integration may project these files into SQLite, but SQLite
//! must not become the only copy of raw provider bytes or the final governed
//! diagnostic closure. The shipped schema-v6 store has no such projection.

#![allow(dead_code)] // Store-private precursor; product wiring is explicitly unearned.

pub(crate) mod prelaunch_refusal_reserve;

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nq_protocol::{RequestId, Sha256Digest, canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::custody_capacity_model::{
    CUSTODY_CAPACITY_ALIGNMENT_V1, CapacityModelError, checked_arena_geometry_v1,
};

const ARENA_FORMAT: &str = "nq.custody_arena.v1";
const SUPERBLOCK_MAGIC: &[u8; 8] = b"NQCAH001";
const SECTION_MAGIC: &[u8; 8] = b"NQCAS001";
const SUPERBLOCK_SIZE: u64 = CUSTODY_CAPACITY_ALIGNMENT_V1;
const SUPERBLOCK_BYTES: usize = 4096;
const SUPERBLOCK_COUNT: u64 = 2;
const SECTION_HEADER_SIZE: u64 = CUSTODY_CAPACITY_ALIGNMENT_V1;
const SECTION_HEADER_BYTES: usize = 4096;
const SUPERBLOCK_JSON_OFFSET: usize = 128;
// V1 reserved the complete region after the authenticated fixed prefix for
// canonical header JSON. The former 3072 implementation cap left 896 reserved
// bytes unusable and became smaller than the now-required exact derivation
// closure. Using the complete already-reserved region changes no offsets or
// file geometry. Older readers retain their safe fail-closed behavior when a
// newer valid header exceeds their narrower implementation cap.
const MAX_SUPERBLOCK_JSON_BYTES: usize = SUPERBLOCK_BYTES - SUPERBLOCK_JSON_OFFSET;
const FORMAT_VERSION: u8 = 1;
const MAX_HEADER_EVALUATION_ID_BYTES: usize = 256;
const MAX_HEADER_TIMESTAMP_BYTES: usize = 64;
const ACQUISITION_CARRIER_SCHEMA: &str = "nq.acquisition_custody_carrier.v1";
const PROTECTED_TERMINAL_SCHEMA: &str = "nq.governed_protected_terminal.v1";
const PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA: &str =
    "nq.governed_projection_correspondence_refusal.v1";
const MAX_PROJECTION_REFUSAL_DETAIL_BYTES: usize = 1_024;

#[derive(Debug, Error)]
pub(crate) enum ArenaError {
    #[error("custody arena I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("custody arena invariant failed: {0}")]
    Invalid(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArenaState {
    Reserved,
    Claimed,
    RawEvidenceSealed,
    DerivationClaimed,
    /// The exact final-section length and digest are durably committed before
    /// any final-section byte is written.
    ///
    /// This is the one exception to the ordinary "unreferenced frame is
    /// scratch" law: a referenced frame at this frontier must be adjudicated
    /// after restart as exact, unavailable, or corrupt.
    FinalV2SealIntent,
    FinalV2SealedIndexPending,
    FinalV2SealedIndexed,
    /// Exact final bytes remain sealed, but the Store proved that their
    /// projection capsule cannot correspond to the committed prelaunch
    /// frontier. The bounded refusal carrier is retained separately.
    FinalV2ProjectionRefused,
    /// A durable final-seal intent was reopened without its exact committed
    /// frame. This is terminal custody state, not permission to re-evaluate.
    FinalV2SealCommittedUnavailable,
    /// A durable final-seal intent was reopened with a substituted, malformed,
    /// or digest-mismatching frame. This is terminal custody state.
    FinalV2SealCorrupt,
    FailedIndeterminate,
    ExpiredUnlaunched,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CapturedBytesState {
    Captured,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ByteCaptureCommitment {
    state: CapturedBytesState,
    byte_length: u64,
    bytes_digest: Sha256Digest,
}

impl ByteCaptureCommitment {
    fn from_bytes(bytes: Option<&[u8]>) -> Result<Self, ArenaError> {
        let bytes =
            bytes.ok_or_else(|| ArenaError::Invalid("custody bytes were not supplied".into()))?;
        Ok(Self {
            state: CapturedBytesState::Captured,
            byte_length: u64::try_from(bytes.len())
                .map_err(|_| ArenaError::Invalid("capture length overflowed".into()))?,
            bytes_digest: sha256_bytes(bytes),
        })
    }

    fn decode<'a>(
        &self,
        encoded: &'a [u8],
        cursor: &mut usize,
        label: &str,
    ) -> Result<&'a [u8], ArenaError> {
        let length = usize::try_from(self.byte_length)
            .map_err(|_| ArenaError::Invalid(format!("{label} length exceeds address space")))?;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| ArenaError::Invalid(format!("{label} range overflowed")))?;
        let bytes = encoded
            .get(*cursor..end)
            .ok_or_else(|| ArenaError::Invalid(format!("{label} bytes are truncated")))?;
        *cursor = end;
        if sha256_bytes(bytes) != self.bytes_digest {
            return Err(ArenaError::Invalid(format!("{label} digest differs")));
        }
        match self.state {
            CapturedBytesState::Captured => Ok(bytes),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionCarrierHeader {
    schema: String,
    execution_launch_record_id: Sha256Digest,
    provider_intake_record_id: Sha256Digest,
    provider_intake_bytes: ByteCaptureCommitment,
    raw_provider_bytes: ByteCaptureCommitment,
}

/// Exact typed custody object written before any profile or evaluator work.
///
/// The store treats both payloads as opaque exact bytes. Only NQ core may
/// establish that the intake carrier is a valid `ProviderIntakeRecordV1`, that
/// it corresponds to the actual provider attempt, or what the raw bytes mean.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquisitionCarrier {
    pub(crate) execution_launch_record_id: Sha256Digest,
    pub(crate) provider_intake_record_id: Sha256Digest,
    pub(crate) exact_provider_intake_bytes: Vec<u8>,
    pub(crate) exact_raw_provider_bytes: Vec<u8>,
}

impl AcquisitionCarrier {
    fn validate(&self) -> Result<(), ArenaError> {
        if self.exact_provider_intake_bytes.is_empty() {
            return Err(ArenaError::Invalid(
                "acquisition carrier has no provider-intake bytes".into(),
            ));
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ArenaError> {
        self.validate()?;
        let header = AcquisitionCarrierHeader {
            schema: ACQUISITION_CARRIER_SCHEMA.to_owned(),
            execution_launch_record_id: self.execution_launch_record_id.clone(),
            provider_intake_record_id: self.provider_intake_record_id.clone(),
            provider_intake_bytes: ByteCaptureCommitment::from_bytes(Some(
                &self.exact_provider_intake_bytes,
            ))?,
            raw_provider_bytes: ByteCaptureCommitment::from_bytes(Some(
                &self.exact_raw_provider_bytes,
            ))?,
        };
        let header_bytes = canonical_json_bytes(&header)
            .map_err(|error| ArenaError::Invalid(format!("cannot encode carrier: {error}")))?;
        let header_length = u64::try_from(header_bytes.len())
            .map_err(|_| ArenaError::Invalid("carrier-header length overflowed".into()))?;
        let mut encoded = Vec::with_capacity(
            8_usize
                .checked_add(header_bytes.len())
                .and_then(|length| length.checked_add(self.exact_provider_intake_bytes.len()))
                .and_then(|length| length.checked_add(self.exact_raw_provider_bytes.len()))
                .ok_or_else(|| ArenaError::Invalid("carrier length overflowed".into()))?,
        );
        encoded.extend_from_slice(&header_length.to_be_bytes());
        encoded.extend_from_slice(&header_bytes);
        encoded.extend_from_slice(&self.exact_provider_intake_bytes);
        encoded.extend_from_slice(&self.exact_raw_provider_bytes);
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, ArenaError> {
        let header_length_bytes: [u8; 8] = encoded
            .get(..8)
            .ok_or_else(|| ArenaError::Invalid("acquisition carrier is truncated".into()))?
            .try_into()
            .expect("fixed range");
        let header_length =
            usize::try_from(u64::from_be_bytes(header_length_bytes)).map_err(|_| {
                ArenaError::Invalid("carrier-header length exceeds address space".into())
            })?;
        let header_end = 8_usize
            .checked_add(header_length)
            .ok_or_else(|| ArenaError::Invalid("carrier-header range overflowed".into()))?;
        let header_bytes = encoded
            .get(8..header_end)
            .ok_or_else(|| ArenaError::Invalid("acquisition carrier header is truncated".into()))?;
        let header: AcquisitionCarrierHeader = serde_json::from_slice(header_bytes)
            .map_err(|error| ArenaError::Invalid(format!("cannot decode carrier: {error}")))?;
        if header.schema != ACQUISITION_CARRIER_SCHEMA
            || canonical_json_bytes(&header).map_err(|error| {
                ArenaError::Invalid(format!("cannot canonicalize carrier: {error}"))
            })? != header_bytes
        {
            return Err(ArenaError::Invalid(
                "acquisition carrier schema or canonical form differs".into(),
            ));
        }
        let mut cursor = header_end;
        let provider_intake =
            header
                .provider_intake_bytes
                .decode(encoded, &mut cursor, "provider-intake bytes")?;
        let raw_provider =
            header
                .raw_provider_bytes
                .decode(encoded, &mut cursor, "raw provider bytes")?;
        if cursor != encoded.len() {
            return Err(ArenaError::Invalid(
                "acquisition carrier contains uncommitted trailing bytes".into(),
            ));
        }
        let carrier = Self {
            execution_launch_record_id: header.execution_launch_record_id,
            provider_intake_record_id: header.provider_intake_record_id,
            exact_provider_intake_bytes: provider_intake.to_vec(),
            exact_raw_provider_bytes: raw_provider.to_vec(),
        };
        carrier.validate()?;
        Ok(carrier)
    }
}

/// Return the exact encoded payload capacity required for an acquisition
/// carrier with the supplied maximum opaque byte lengths.
///
/// This uses the same header type and canonical encoder as
/// [`AcquisitionCarrier::encode`]. Digest values are fixed-width protocol
/// identities, so the resulting header length is exact for the two supplied
/// byte-length bounds without allocating either payload.
pub(crate) fn acquisition_carrier_capacity_bound(
    max_provider_intake_bytes: u64,
    max_raw_bytes: u64,
) -> Result<u64, ArenaError> {
    if max_provider_intake_bytes == 0 {
        return Err(ArenaError::Invalid(
            "maximum provider-intake bytes must be positive".into(),
        ));
    }
    8_u64
        .checked_add(max_provider_intake_bytes)
        .and_then(|length| length.checked_add(max_raw_bytes))
        .ok_or_else(|| {
            ArenaError::Invalid("acquisition carrier capacity bound overflowed".into())
        })?;
    let placeholder_digest = sha256_bytes(&[]);
    let header = AcquisitionCarrierHeader {
        schema: ACQUISITION_CARRIER_SCHEMA.to_owned(),
        execution_launch_record_id: placeholder_digest.clone(),
        provider_intake_record_id: placeholder_digest.clone(),
        provider_intake_bytes: ByteCaptureCommitment {
            state: CapturedBytesState::Captured,
            byte_length: max_provider_intake_bytes,
            bytes_digest: placeholder_digest.clone(),
        },
        raw_provider_bytes: ByteCaptureCommitment {
            state: CapturedBytesState::Captured,
            byte_length: max_raw_bytes,
            bytes_digest: placeholder_digest,
        },
    };
    let header_bytes = canonical_json_bytes(&header)
        .map_err(|error| ArenaError::Invalid(format!("cannot encode carrier bound: {error}")))?;
    let header_length = u64::try_from(header_bytes.len())
        .map_err(|_| ArenaError::Invalid("carrier-bound header length overflowed".into()))?;
    8_u64
        .checked_add(header_length)
        .and_then(|length| length.checked_add(max_provider_intake_bytes))
        .and_then(|length| length.checked_add(max_raw_bytes))
        .ok_or_else(|| ArenaError::Invalid("acquisition carrier capacity bound overflowed".into()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SectionKind {
    RawEvidence,
    FinalV2Closure,
    ProtectedFailure,
    DependencyClosure,
}

impl SectionKind {
    const fn tag(self) -> u8 {
        match self {
            Self::RawEvidence => 1,
            Self::FinalV2Closure => 2,
            Self::ProtectedFailure => 3,
            Self::DependencyClosure => 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ArenaLayout {
    file_length: u64,
    dependency_header_offset: u64,
    dependency_payload_offset: u64,
    dependency_capacity: u64,
    raw_header_offset: u64,
    raw_payload_offset: u64,
    raw_capacity: u64,
    final_header_offset: u64,
    final_payload_offset: u64,
    final_capacity: u64,
    failure_header_offset: u64,
    failure_payload_offset: u64,
    failure_capacity: u64,
}

impl ArenaLayout {
    pub(crate) fn new(
        dependency_capacity: u64,
        raw_capacity: u64,
        final_capacity: u64,
        failure_capacity: u64,
    ) -> Result<Self, ArenaError> {
        let geometry = checked_arena_geometry_v1(
            dependency_capacity,
            raw_capacity,
            final_capacity,
            failure_capacity,
        )
        .map_err(arena_geometry_error)?;
        Ok(Self {
            file_length: geometry.file_length_bytes,
            dependency_header_offset: geometry.dependency_header_offset,
            dependency_payload_offset: geometry.dependency_payload_offset,
            dependency_capacity,
            raw_header_offset: geometry.raw_header_offset,
            raw_payload_offset: geometry.raw_payload_offset,
            raw_capacity,
            final_header_offset: geometry.final_header_offset,
            final_payload_offset: geometry.final_payload_offset,
            final_capacity,
            failure_header_offset: geometry.failure_header_offset,
            failure_payload_offset: geometry.failure_payload_offset,
            failure_capacity,
        })
    }

    pub(crate) const fn file_length(&self) -> u64 {
        self.file_length
    }

    pub(crate) const fn raw_capacity(&self) -> u64 {
        self.raw_capacity
    }

    pub(crate) const fn dependency_capacity(&self) -> u64 {
        self.dependency_capacity
    }

    pub(crate) const fn final_capacity(&self) -> u64 {
        self.final_capacity
    }

    pub(crate) const fn failure_capacity(&self) -> u64 {
        self.failure_capacity
    }

    fn validate(&self) -> Result<(), ArenaError> {
        let recomputed = Self::new(
            self.dependency_capacity,
            self.raw_capacity,
            self.final_capacity,
            self.failure_capacity,
        )?;
        if &recomputed != self {
            return Err(ArenaError::Invalid(
                "arena layout is not the exact canonical partition layout".into(),
            ));
        }
        Ok(())
    }

    fn section(&self, kind: SectionKind) -> (u64, u64, u64) {
        match kind {
            SectionKind::DependencyClosure => (
                self.dependency_header_offset,
                self.dependency_payload_offset,
                self.dependency_capacity,
            ),
            SectionKind::RawEvidence => (
                self.raw_header_offset,
                self.raw_payload_offset,
                self.raw_capacity,
            ),
            SectionKind::FinalV2Closure => (
                self.final_header_offset,
                self.final_payload_offset,
                self.final_capacity,
            ),
            SectionKind::ProtectedFailure => (
                self.failure_header_offset,
                self.failure_payload_offset,
                self.failure_capacity,
            ),
        }
    }
}

fn arena_geometry_error(error: CapacityModelError) -> ArenaError {
    match error {
        CapacityModelError::ZeroCarrierPayload { .. } => {
            ArenaError::Invalid("all governed arena partitions must be nonzero".into())
        }
        CapacityModelError::UnsafeInteger(_) => {
            ArenaError::Invalid("arena capacity exceeds exact-I-JSON integer domain".into())
        }
        CapacityModelError::ArithmeticOverflow("arena failure end") => {
            ArenaError::Invalid("arena length overflowed".into())
        }
        CapacityModelError::ArithmeticOverflow(operation) if operation.ends_with("alignment") => {
            ArenaError::Invalid("arena alignment overflowed".into())
        }
        CapacityModelError::ArithmeticOverflow(_) => {
            ArenaError::Invalid("arena offset overflowed".into())
        }
        other => ArenaError::Invalid(format!(
            "arena capacity geometry unexpectedly refused: {other}"
        )),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArenaPrelaunchBinding {
    pub(crate) reservation_record_id: Sha256Digest,
    pub(crate) reservation_manifest_digest: Sha256Digest,
    pub(crate) outer_request_record_id: Sha256Digest,
    pub(crate) outer_request_id: String,
    pub(crate) outer_request_digest: Sha256Digest,
    /// Exact authenticated dependency generation used to validate every
    /// prelaunch record and later closure.
    pub(crate) dependency_generation_id: Sha256Digest,
    /// Digest of the complete exact-byte dependency-generation custody
    /// closure, including its independently retained trust anchor.
    pub(crate) dependency_generation_custody_digest: Sha256Digest,
    /// Immutable bootstrap trust anchor independently selected when this
    /// dependency generation was opened.
    pub(crate) trust_anchor_id: Sha256Digest,
    pub(crate) prelaunch_checkpoint_id: Sha256Digest,
    pub(crate) prelaunch_checkpoint_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SealedSection {
    kind: SectionKind,
    payload_length: u64,
    payload_digest: Sha256Digest,
}

impl SealedSection {
    pub(crate) const fn payload_length(&self) -> u64 {
        self.payload_length
    }

    pub(crate) const fn payload_digest(&self) -> &Sha256Digest {
        &self.payload_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArenaHeader {
    schema: String,
    sequence: u64,
    prelaunch: ArenaPrelaunchBinding,
    execution_launch_record_id: Option<Sha256Digest>,
    layout: ArenaLayout,
    state: ArenaState,
    claimed_at: Option<String>,
    derivation_claim: Option<DerivationClaim>,
    dependency_closure: Option<SealedSection>,
    raw_evidence: Option<SealedSection>,
    final_v2_closure: Option<SealedSection>,
    protected_failure: Option<SealedSection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DerivationClaim {
    pub(crate) derivation_id: Sha256Digest,
    pub(crate) dependency_generation_id: Sha256Digest,
    pub(crate) dependency_generation_custody_digest: Sha256Digest,
    pub(crate) trust_anchor_id: Sha256Digest,
    /// Legacy exact text retained only when reopening a header written before
    /// evaluation identity was compacted. New claims store the digest below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) evaluation_id: Option<String>,
    /// Exact digest of the optional evaluation identity.
    ///
    /// The canonical final closure retains the original text. Keeping only its
    /// digest in the fixed physical header makes the maximum header size
    /// independent of JSON escaping without weakening exact correspondence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) evaluation_id_digest: Option<Sha256Digest>,
    pub(crate) profile_semantic_id: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) evaluator_semantic_digest: Option<Sha256Digest>,
    pub(crate) evaluator_artifact_digest: Sha256Digest,
    pub(crate) derived_at: String,
    pub(crate) clock_identity: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) clock_uncertainty_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) clock_qualification_digest: Option<Sha256Digest>,
}

fn validate_header_request_id(value: &str) -> Result<(), ArenaError> {
    RequestId::new(value.to_owned())
        .map(|_| ())
        .map_err(|error| {
            ArenaError::Invalid(format!(
                "arena outer-request identity is not one bounded protocol token: {error}"
            ))
        })
}

fn validate_header_timestamp(value: &str, label: &str) -> Result<(), ArenaError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_TIMESTAMP_BYTES
        || value.chars().any(char::is_control)
        || chrono::DateTime::parse_from_rfc3339(value).is_err()
    {
        return Err(ArenaError::Invalid(format!(
            "arena {label} must be 1..={MAX_HEADER_TIMESTAMP_BYTES} non-control RFC 3339 bytes"
        )));
    }
    Ok(())
}

fn validate_derivation_header_text(claim: &DerivationClaim) -> Result<(), ArenaError> {
    validate_header_timestamp(&claim.derived_at, "derivation time")?;
    if claim.evaluation_id.is_some() && claim.evaluation_id_digest.is_some() {
        return Err(ArenaError::Invalid(
            "arena derivation carries both legacy evaluation text and its compact digest".into(),
        ));
    }
    if claim.evaluation_id.as_ref().is_some_and(|identity| {
        identity.is_empty()
            || identity.len() > MAX_HEADER_EVALUATION_ID_BYTES
            || identity.chars().any(char::is_control)
    }) {
        return Err(ArenaError::Invalid(format!(
            "arena evaluation identity must contain 1..={MAX_HEADER_EVALUATION_ID_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArenaInspection {
    pub(crate) state: ArenaState,
    pub(crate) sequence: u64,
    pub(crate) reservation_id: Sha256Digest,
    pub(crate) prelaunch: ArenaPrelaunchBinding,
    pub(crate) execution_launch_record_id: Option<Sha256Digest>,
    pub(crate) claimed_at: Option<String>,
    pub(crate) derivation_claim: Option<DerivationClaim>,
    pub(crate) layout: ArenaLayout,
    pub(crate) dependency_closure: Option<SealedSection>,
    pub(crate) raw_evidence: Option<SealedSection>,
    pub(crate) final_v2_closure: Option<SealedSection>,
    pub(crate) protected_failure: Option<SealedSection>,
    pub(crate) selected_superblock_digest: Sha256Digest,
    pub(crate) recovered_torn_superblock: bool,
}

#[derive(Debug)]
pub(crate) enum ArenaInventoryEntry {
    Verified {
        relative_path: PathBuf,
        inspection: Box<ArenaInspection>,
    },
    Unreadable {
        relative_path: PathBuf,
        reason: String,
    },
}

/// Narrow read-only durable-state peek used by the global publication fence.
///
/// Unlike [`ArenaInventoryEntry`], this does not take the arena's exclusive
/// lifetime lock and therefore cannot inspect or reopen section bytes. It
/// validates root/file identity and the checksummed double-superblock only.
#[derive(Debug)]
pub(crate) enum ArenaStateInventoryEntry {
    Verified {
        relative_path: PathBuf,
        reservation_id: Sha256Digest,
        state: ArenaState,
    },
    Unreadable {
        relative_path: PathBuf,
        reason: String,
    },
}

/// One-use proof that the typed acquisition carrier was synced, reopened, and
/// verified against the exact launch identity.
///
/// Deliberately non-`Clone`; callers can inspect the reopened carrier but
/// cannot construct this token.
pub(crate) struct RawCustodyToken {
    reservation_id: Sha256Digest,
    section: SealedSection,
    carrier: AcquisitionCarrier,
}

impl RawCustodyToken {
    pub(crate) fn carrier(&self) -> &AcquisitionCarrier {
        &self.carrier
    }
}

/// One-use durable derivation occurrence bound to one reopened raw carrier.
///
/// This store-private precursor does not yet cross a cycle-free product
/// boundary to `nq-core`.
pub(crate) struct DerivationCustodyToken {
    reservation_id: Sha256Digest,
    raw_section: SealedSection,
    reopened_carrier: AcquisitionCarrier,
    claim: DerivationClaim,
}

impl DerivationCustodyToken {
    pub(crate) fn reopened_carrier(&self) -> &AcquisitionCarrier {
        &self.reopened_carrier
    }
}

/// Store-private final-closure candidate paired with the one-use durable
/// evaluation claim that produced it.
///
/// The current constructor performs only precursor checks. It is not the
/// future core-validated correspondence wrapper and has no product caller.
pub(crate) struct DerivedV2ClosureCandidate {
    token: DerivationCustodyToken,
    exact_bytes: Vec<u8>,
}

impl DerivedV2ClosureCandidate {
    pub(crate) fn from_store_internal_precursor(
        token: DerivationCustodyToken,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, ArenaError> {
        validate_governed_closure_document(&exact_bytes)?;
        Ok(Self { token, exact_bytes })
    }
}

/// One-use proof that the final V2 closure was synced and reopened.
pub(crate) struct FinalCustodyToken {
    reservation_id: Sha256Digest,
    section: SealedSection,
}

/// Store-internal failure-carrier candidate.
///
/// Its self-identity and a narrow reservation/launch correspondence are
/// checked here. This is not the fully typed governed failure constructor or
/// validator required by future product integration.
pub(crate) struct ArenaFailureCarrierCandidate {
    exact_bytes: Vec<u8>,
}

impl ArenaFailureCarrierCandidate {
    pub(crate) fn parse_precursor(exact_bytes: Vec<u8>) -> Result<Self, ArenaError> {
        validate_semantic_document(&exact_bytes, "nq.governed_custody_failure.v1", "failure_id")?;
        Ok(Self { exact_bytes })
    }

    pub(crate) fn parse_protected_terminal(exact_bytes: Vec<u8>) -> Result<Self, ArenaError> {
        validate_semantic_document(&exact_bytes, PROTECTED_TERMINAL_SCHEMA, "terminal_id")?;
        Ok(Self { exact_bytes })
    }

    pub(crate) fn parse_projection_correspondence_refusal(
        exact_bytes: Vec<u8>,
    ) -> Result<Self, ArenaError> {
        validate_semantic_document(
            &exact_bytes,
            PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA,
            "refusal_id",
        )?;
        Ok(Self { exact_bytes })
    }
}

pub(crate) struct CustodyArena {
    path: PathBuf,
    file: LifetimeLockedFile,
    header: ArenaHeader,
    active_superblock: usize,
    selected_superblock_digest: Sha256Digest,
    recovered_torn_superblock: bool,
    poisoned: bool,
    #[cfg(test)]
    failpoint: Option<ArenaFailpoint>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArenaFailpoint {
    FinalSealAfterIntent,
    FinalSealAfterIntentSigkill,
    SectionAfterSync,
    SectionAfterSyncSigkill,
    SuperblockAfterSync,
}

#[cfg(test)]
fn kill_current_test_process() -> ! {
    let _ = nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGKILL);
    // If the kernel rejected the signal, fail hard rather than letting an
    // abrupt-crash test pass through an ordinary return.
    std::process::abort()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalSealIntentDisposition {
    Promoted,
    CommittedUnavailable,
    Corrupt,
}

impl CustodyArena {
    pub(crate) fn root_for_database(database_path: &Path) -> Result<PathBuf, ArenaError> {
        let database_path = normalized_database_path(database_path)?;
        let file_name = database_path
            .file_name()
            .ok_or_else(|| ArenaError::Invalid("database path has no final component".into()))?;
        let mut arena_name = file_name.to_os_string();
        arena_name.push(".nq-custody-v1");
        Ok(database_path.with_file_name(arena_name))
    }

    pub(crate) fn relative_path(reservation_id: &Sha256Digest) -> PathBuf {
        let digest = reservation_id
            .as_str()
            .strip_prefix("sha256:")
            .expect("validated digest always has prefix");
        PathBuf::from(format!("{digest}.arena"))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create(
        database_path: &Path,
        prelaunch: ArenaPrelaunchBinding,
        layout: ArenaLayout,
        exact_dependency_closure_bytes: &[u8],
    ) -> Result<Self, ArenaError> {
        layout.validate()?;
        validate_header_request_id(&prelaunch.outer_request_id)?;
        if exact_dependency_closure_bytes.is_empty()
            || sha256_bytes(exact_dependency_closure_bytes)
                != prelaunch.dependency_generation_custody_digest
        {
            return Err(ArenaError::Invalid(
                "dependency-generation custody bytes are absent or differ from prelaunch".into(),
            ));
        }
        let root = Self::root_for_database(database_path)?;
        ensure_arena_root(database_path, &root)?;
        let relative = Self::relative_path(&prelaunch.reservation_record_id);
        let path = root.join(&relative);
        let file = lock_lifetime_exclusive(create_arena_file(database_path, &root, &relative)?)?;
        fallocate_exact(&file, layout.file_length)?;
        let header = ArenaHeader {
            schema: ARENA_FORMAT.to_owned(),
            sequence: 1,
            prelaunch,
            execution_launch_record_id: None,
            layout,
            state: ArenaState::Reserved,
            claimed_at: None,
            derivation_claim: None,
            dependency_closure: None,
            raw_evidence: None,
            final_v2_closure: None,
            protected_failure: None,
        };
        let mut arena = Self {
            path,
            file,
            header,
            active_superblock: 1,
            selected_superblock_digest: sha256_bytes(b"uninitialized-superblock"),
            recovered_torn_superblock: false,
            poisoned: false,
            #[cfg(test)]
            failpoint: None,
        };
        let dependency = arena.write_section(
            SectionKind::DependencyClosure,
            exact_dependency_closure_bytes,
        )?;
        arena.header.dependency_closure = Some(dependency);
        write_superblock(&arena.file, 0, &arena.header)?;
        write_superblock(&arena.file, 1, &arena.header)?;
        arena.file.sync_all()?;
        sync_directory(&root)?;
        arena.selected_superblock_digest = superblock_digest(&arena.file, 1)?;
        arena.verify_file_shape()?;
        arena.verify_sealed_sections()?;
        Ok(arena)
    }

    pub(crate) fn open(
        database_path: &Path,
        expected_prelaunch: &ArenaPrelaunchBinding,
    ) -> Result<Self, ArenaError> {
        let relative_path = Self::relative_path(&expected_prelaunch.reservation_record_id);
        let root = Self::root_for_database(database_path)?;
        let root_identity = verify_arena_root(database_path, &root)?;
        let path = root.join(&relative_path);
        let file = lock_lifetime_exclusive(open_arena_file(
            database_path,
            &root,
            &relative_path,
            &root_identity,
        )?)?;
        verify_arena_file(database_path, &root, &file)?;
        let first = read_superblock(&file, 0);
        let second = read_superblock(&file, 1);
        let (header, active_superblock, selected_superblock_digest, recovered_torn_superblock) =
            select_superblock(first, second)?;
        if &header.prelaunch != expected_prelaunch
            || Self::relative_path(&header.prelaunch.reservation_record_id) != relative_path
        {
            return Err(ArenaError::Invalid(
                "arena prelaunch binding or digest-derived filename differs".into(),
            ));
        }
        let arena = Self {
            path,
            file,
            header,
            active_superblock,
            selected_superblock_digest,
            recovered_torn_superblock,
            poisoned: false,
            #[cfg(test)]
            failpoint: None,
        };
        arena.verify_file_shape()?;
        arena.verify_sealed_sections()?;
        Ok(arena)
    }

    /// Inspect every arena owned by one database occurrence.
    ///
    /// Inventory is deliberately physical and read-only. It classifies durable
    /// frontiers without deciding whether a diagnostic succeeded, whether an
    /// invocation should resume, or whether a protected failure should be
    /// synthesized. An unreadable entry remains visible instead of being
    /// omitted from startup state.
    pub(crate) fn inventory(
        database_path: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<ArenaInventoryEntry>, ArenaError> {
        let root = Self::root_for_database(database_path)?;
        match fs::symlink_metadata(&root) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        }
        let root_identity = verify_arena_root(database_path, &root)?;
        let mut relative_paths = fs::read_dir(&root)?
            .map(|entry| entry.map(|entry| PathBuf::from(entry.file_name())))
            .collect::<Result<Vec<_>, _>>()?;
        relative_paths.sort();
        if relative_paths.len() > maximum_entries {
            return Err(ArenaError::Invalid(format!(
                "custody arena inventory exceeds the bounded limit of {maximum_entries}"
            )));
        }
        relative_paths
            .into_iter()
            .map(|relative_path| {
                match Self::open_discovered(database_path, &root, &root_identity, &relative_path) {
                    Ok(arena) => {
                        let inspection = arena.inspection()?;
                        Ok(ArenaInventoryEntry::Verified {
                            relative_path,
                            inspection: Box::new(inspection),
                        })
                    }
                    Err(error) => Ok(ArenaInventoryEntry::Unreadable {
                        relative_path,
                        reason: error.to_string(),
                    }),
                }
            })
            .collect()
    }

    /// Peek durable arena frontiers without contending with live pre-final
    /// custody handles.
    ///
    /// A caller that observes `FinalV2SealedIndexPending` must subsequently
    /// acquire the ordinary exclusive arena handle before reading any section.
    /// No bytes or semantic result are exposed by this peek.
    pub(crate) fn state_inventory_unlocked(
        database_path: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<ArenaStateInventoryEntry>, ArenaError> {
        let root = Self::root_for_database(database_path)?;
        match fs::symlink_metadata(&root) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        }
        let root_identity = verify_arena_root(database_path, &root)?;
        let mut relative_paths = fs::read_dir(&root)?
            .map(|entry| entry.map(|entry| PathBuf::from(entry.file_name())))
            .collect::<Result<Vec<_>, _>>()?;
        relative_paths.sort();
        if relative_paths.len() > maximum_entries {
            return Err(ArenaError::Invalid(format!(
                "custody arena state inventory exceeds the bounded limit of {maximum_entries}"
            )));
        }
        relative_paths
            .into_iter()
            .map(|relative_path| {
                let inspected = (|| {
                    if relative_path
                        .parent()
                        .is_some_and(|parent| !parent.as_os_str().is_empty())
                        || relative_path.file_name() != Some(relative_path.as_os_str())
                    {
                        return Err(ArenaError::Invalid(
                            "custody state inventory entry is not one root-relative filename"
                                .into(),
                        ));
                    }
                    let file =
                        open_arena_file(database_path, &root, &relative_path, &root_identity)?;
                    verify_arena_file(database_path, &root, &file)?;
                    let first = read_superblock(&file, 0);
                    let second = read_superblock(&file, 1);
                    let (header, _, _, _) = select_superblock(first, second)?;
                    header.layout.validate()?;
                    let metadata = file.metadata()?;
                    if !metadata.is_file()
                        || metadata.permissions().mode() & 0o077 != 0
                        || metadata.len() != header.layout.file_length
                        || header.schema != ARENA_FORMAT
                        || header.sequence == 0
                        || Self::relative_path(&header.prelaunch.reservation_record_id)
                            != relative_path
                    {
                        return Err(ArenaError::Invalid(
                            "custody state inventory file/header identity differs".into(),
                        ));
                    }
                    Ok((header.prelaunch.reservation_record_id, header.state))
                })();
                Ok(match inspected {
                    Ok((reservation_id, state)) => ArenaStateInventoryEntry::Verified {
                        relative_path,
                        reservation_id,
                        state,
                    },
                    Err(error) => ArenaStateInventoryEntry::Unreadable {
                        relative_path,
                        reason: error.to_string(),
                    },
                })
            })
            .collect()
    }

    pub(crate) fn open_by_reservation(
        database_path: &Path,
        reservation_id: &Sha256Digest,
    ) -> Result<Option<Self>, ArenaError> {
        let root = Self::root_for_database(database_path)?;
        match fs::symlink_metadata(&root) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let root_identity = verify_arena_root(database_path, &root)?;
        let relative_path = Self::relative_path(reservation_id);
        match Self::open_discovered(database_path, &root, &root_identity, &relative_path) {
            Ok(arena) => Ok(Some(arena)),
            Err(ArenaError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open_discovered(
        database_path: &Path,
        root: &Path,
        root_identity: &RootIdentity,
        relative_path: &Path,
    ) -> Result<Self, ArenaError> {
        if relative_path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
            || relative_path.file_name() != Some(relative_path.as_os_str())
        {
            return Err(ArenaError::Invalid(
                "custody inventory entry is not one root-relative filename".into(),
            ));
        }
        let path = root.join(relative_path);
        let file = lock_lifetime_exclusive(open_arena_file(
            database_path,
            root,
            relative_path,
            root_identity,
        )?)?;
        verify_arena_file(database_path, root, &file)?;
        let first = read_superblock(&file, 0);
        let second = read_superblock(&file, 1);
        let (header, active_superblock, selected_superblock_digest, recovered_torn_superblock) =
            select_superblock(first, second)?;
        if Self::relative_path(&header.prelaunch.reservation_record_id) != relative_path {
            return Err(ArenaError::Invalid(
                "arena embedded reservation identity differs from its filename".into(),
            ));
        }
        let arena = Self {
            path,
            file,
            header,
            active_superblock,
            selected_superblock_digest,
            recovered_torn_superblock,
            poisoned: false,
            #[cfg(test)]
            failpoint: None,
        };
        arena.verify_file_shape()?;
        arena.verify_sealed_sections()?;
        Ok(arena)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn relative_path_from(&self, database_path: &Path) -> Result<PathBuf, ArenaError> {
        let root = Self::root_for_database(database_path)?;
        self.path
            .strip_prefix(root)
            .map(Path::to_path_buf)
            .map_err(|_| ArenaError::Invalid("arena escaped its database-owned root".into()))
    }

    pub(crate) fn inspection(&self) -> Result<ArenaInspection, ArenaError> {
        self.ensure_usable()?;
        Ok(ArenaInspection {
            state: self.header.state,
            sequence: self.header.sequence,
            reservation_id: self.header.prelaunch.reservation_record_id.clone(),
            prelaunch: self.header.prelaunch.clone(),
            execution_launch_record_id: self.header.execution_launch_record_id.clone(),
            claimed_at: self.header.claimed_at.clone(),
            derivation_claim: self.header.derivation_claim.clone(),
            layout: self.header.layout.clone(),
            dependency_closure: self.header.dependency_closure.clone(),
            raw_evidence: self.header.raw_evidence.clone(),
            final_v2_closure: self.header.final_v2_closure.clone(),
            protected_failure: self.header.protected_failure.clone(),
            selected_superblock_digest: self.selected_superblock_digest.clone(),
            recovered_torn_superblock: self.recovered_torn_superblock,
        })
    }

    /// Reopen the checksummed durable header after an indeterminate write on
    /// this still-lifetime-locked handle.
    ///
    /// The operation supplies no retry authority. It exists only so the
    /// owner of the original one-use launch capability can decide whether a
    /// pre-final failure may still be protected-terminalized or whether a
    /// committed final-seal frontier must be left to Store recovery.
    pub(crate) fn reopen_after_indeterminate_write(&mut self) -> Result<ArenaState, ArenaError> {
        if !self.poisoned {
            return Ok(self.header.state);
        }
        let first = read_superblock(&self.file, 0);
        let second = read_superblock(&self.file, 1);
        let (header, active_superblock, selected_superblock_digest, recovered_torn_superblock) =
            select_superblock(first, second)?;
        if header.schema != self.header.schema
            || header.prelaunch != self.header.prelaunch
            || header.layout != self.header.layout
        {
            return Err(ArenaError::Invalid(
                "reopened poisoned arena changed immutable identity or layout".into(),
            ));
        }
        self.header = header;
        self.active_superblock = active_superblock;
        self.selected_superblock_digest = selected_superblock_digest;
        self.recovered_torn_superblock = recovered_torn_superblock;
        self.poisoned = false;
        if let Err(error) = self
            .verify_file_shape()
            .and_then(|()| self.verify_sealed_sections())
        {
            self.poisoned = true;
            return Err(error);
        }
        Ok(self.header.state)
    }

    pub(crate) fn claim(
        &mut self,
        execution_launch_record_id: Sha256Digest,
        claimed_at: String,
    ) -> Result<(), ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        validate_header_timestamp(&claimed_at, "launch claim")?;
        if self.header.state != ArenaState::Reserved || self.header.claimed_at.is_some() {
            return Err(ArenaError::Invalid(
                "arena reservation has already been claimed or terminalized".into(),
            ));
        }
        self.execute_poisoned(move |arena| {
            arena.transition_inner(|header| {
                header.state = ArenaState::Claimed;
                header.claimed_at = Some(claimed_at);
                header.execution_launch_record_id = Some(execution_launch_record_id);
                Ok(())
            })
        })
    }

    pub(crate) fn seal_acquisition(
        &mut self,
        carrier: AcquisitionCarrier,
    ) -> Result<RawCustodyToken, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::Claimed {
            return Err(ArenaError::Invalid(
                "acquisition custody can be sealed only after the exact launch claim".into(),
            ));
        }
        if self.header.execution_launch_record_id.as_ref()
            != Some(&carrier.execution_launch_record_id)
        {
            return Err(ArenaError::Invalid(
                "acquisition carrier differs from the exact launch claim".into(),
            ));
        }
        let exact_bytes = carrier.encode()?;
        self.execute_poisoned(move |arena| {
            let section = arena.write_section(SectionKind::RawEvidence, &exact_bytes)?;
            arena.transition_inner(|header| {
                header.state = ArenaState::RawEvidenceSealed;
                header.raw_evidence = Some(section.clone());
                Ok(())
            })?;
            let reopened = arena
                .read_committed_section(SectionKind::RawEvidence)?
                .ok_or_else(|| ArenaError::Invalid("sealed acquisition vanished".into()))?;
            let reopened = AcquisitionCarrier::decode(&reopened)?;
            if reopened != carrier {
                return Err(ArenaError::Invalid(
                    "acquisition carrier differed after durable reopen".into(),
                ));
            }
            Ok(RawCustodyToken {
                reservation_id: arena.header.prelaunch.reservation_record_id.clone(),
                section,
                carrier: reopened,
            })
        })
    }

    pub(crate) fn seal_final_v2_closure(
        &mut self,
        derived: DerivedV2ClosureCandidate,
    ) -> Result<FinalCustodyToken, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::DerivationClaimed {
            return Err(ArenaError::Invalid(
                "final V2 closure requires one durable derivation claim".into(),
            ));
        }
        if derived.token.reservation_id != self.header.prelaunch.reservation_record_id
            || self.header.raw_evidence.as_ref() != Some(&derived.token.raw_section)
            || self.header.derivation_claim.as_ref() != Some(&derived.token.claim)
        {
            return Err(ArenaError::Invalid(
                "derived closure token differs from the durable arena frontier".into(),
            ));
        }
        let reopened_raw = self
            .read_committed_section(SectionKind::RawEvidence)?
            .ok_or_else(|| ArenaError::Invalid("raw acquisition is unavailable".into()))?;
        if AcquisitionCarrier::decode(&reopened_raw)? != derived.token.reopened_carrier {
            return Err(ArenaError::Invalid(
                "derived closure lost its store-reopened acquisition carrier".into(),
            ));
        }
        validate_final_v2_correspondence(
            &derived.exact_bytes,
            &self.header.prelaunch,
            &derived.token.claim,
        )?;
        let expected =
            self.section_commitment(SectionKind::FinalV2Closure, &derived.exact_bytes)?;
        self.execute_poisoned(move |arena| {
            // Commit the exact expected frame before touching its physical
            // section. A crash from this point onward cannot make the final
            // result look like ordinary unreferenced scratch.
            arena.transition_inner(|header| {
                header.state = ArenaState::FinalV2SealIntent;
                header.final_v2_closure = Some(expected.clone());
                Ok(())
            })?;
            #[cfg(test)]
            if arena.failpoint == Some(ArenaFailpoint::FinalSealAfterIntent) {
                return Err(ArenaError::Invalid(
                    "injected crash after durable final-seal intent".into(),
                ));
            }
            #[cfg(test)]
            if arena.failpoint == Some(ArenaFailpoint::FinalSealAfterIntentSigkill) {
                kill_current_test_process();
            }
            let section = arena.write_section(SectionKind::FinalV2Closure, &derived.exact_bytes)?;
            if section != expected {
                return Err(ArenaError::Invalid(
                    "written final section differs from its durable seal intent".into(),
                ));
            }
            arena.transition_inner(|header| {
                header.state = ArenaState::FinalV2SealedIndexPending;
                Ok(())
            })?;
            Ok(FinalCustodyToken {
                reservation_id: arena.header.prelaunch.reservation_record_id.clone(),
                section,
            })
        })
    }

    /// Adjudicate one durable final-seal intent without invoking an evaluator
    /// or accepting replacement bytes.
    ///
    /// An exact staged frame is promoted to the ordinary index-pending
    /// frontier. Absence and corruption become distinct terminal custody
    /// states. The operation never retries derivation and never treats an
    /// unreferenced frame from any other state as committed.
    pub(crate) fn adjudicate_final_v2_seal_intent(
        &mut self,
    ) -> Result<FinalSealIntentDisposition, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::FinalV2SealIntent {
            return Err(ArenaError::Invalid(
                "final-seal adjudication requires one durable seal intent".into(),
            ));
        }
        let expected = self
            .header
            .final_v2_closure
            .clone()
            .ok_or_else(|| ArenaError::Invalid("final-seal intent has no commitment".into()))?;
        let observed = self.read_section_frame(SectionKind::FinalV2Closure);
        let disposition = match observed {
            Ok(Some(bytes))
                if expected.kind == SectionKind::FinalV2Closure
                    && expected.payload_length
                        == u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                    && expected.payload_digest == sha256_bytes(&bytes)
                    && self.header.derivation_claim.as_ref().is_some_and(|claim| {
                        validate_final_v2_correspondence(&bytes, &self.header.prelaunch, claim)
                            .is_ok()
                    }) =>
            {
                FinalSealIntentDisposition::Promoted
            }
            Ok(None) => FinalSealIntentDisposition::CommittedUnavailable,
            Ok(Some(_)) | Err(_) => FinalSealIntentDisposition::Corrupt,
        };
        self.execute_poisoned(|arena| {
            arena.transition_inner(|header| {
                header.state = match disposition {
                    FinalSealIntentDisposition::Promoted => ArenaState::FinalV2SealedIndexPending,
                    FinalSealIntentDisposition::CommittedUnavailable => {
                        ArenaState::FinalV2SealCommittedUnavailable
                    }
                    FinalSealIntentDisposition::Corrupt => ArenaState::FinalV2SealCorrupt,
                };
                Ok(())
            })
        })?;
        Ok(disposition)
    }

    pub(crate) fn claim_derivation(
        &mut self,
        raw: RawCustodyToken,
        claim: DerivationClaim,
    ) -> Result<DerivationCustodyToken, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        validate_derivation_header_text(&claim)?;
        if self.header.state != ArenaState::RawEvidenceSealed
            || self.header.derivation_claim.is_some()
        {
            return Err(ArenaError::Invalid(
                "derivation can be claimed exactly once after raw evidence sealing".into(),
            ));
        }
        if raw.reservation_id != self.header.prelaunch.reservation_record_id
            || self.header.raw_evidence.as_ref() != Some(&raw.section)
            || raw.carrier.execution_launch_record_id
                != self
                    .header
                    .execution_launch_record_id
                    .clone()
                    .expect("raw state has launch")
        {
            return Err(ArenaError::Invalid(
                "raw custody token differs from the durable arena frontier".into(),
            ));
        }
        if claim.dependency_generation_id != self.header.prelaunch.dependency_generation_id
            || claim.dependency_generation_custody_digest
                != self.header.prelaunch.dependency_generation_custody_digest
            || claim.trust_anchor_id != self.header.prelaunch.trust_anchor_id
        {
            return Err(ArenaError::Invalid(
                "derivation claim differs from the prelaunch dependency generation or trust anchor"
                    .into(),
            ));
        }
        let reopened = self
            .read_committed_section(SectionKind::RawEvidence)?
            .ok_or_else(|| ArenaError::Invalid("raw acquisition is unavailable".into()))?;
        if AcquisitionCarrier::decode(&reopened)? != raw.carrier {
            return Err(ArenaError::Invalid(
                "derivation token does not carry the store-reopened acquisition".into(),
            ));
        }
        self.execute_poisoned(move |arena| {
            arena.transition_inner(|header| {
                header.state = ArenaState::DerivationClaimed;
                header.derivation_claim = Some(claim.clone());
                Ok(())
            })?;
            Ok(DerivationCustodyToken {
                reservation_id: arena.header.prelaunch.reservation_record_id.clone(),
                raw_section: raw.section,
                reopened_carrier: raw.carrier,
                claim,
            })
        })
    }

    pub(crate) fn seal_failure(
        &mut self,
        failure: ArenaFailureCarrierCandidate,
        terminal_state: ArenaState,
    ) -> Result<SealedSection, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        let legal = matches!(
            (self.header.state, terminal_state),
            (ArenaState::Reserved, ArenaState::ExpiredUnlaunched)
                | (
                    ArenaState::Claimed
                        | ArenaState::RawEvidenceSealed
                        | ArenaState::DerivationClaimed,
                    ArenaState::FailedIndeterminate
                )
        ) && self.header.protected_failure.is_none();
        if !legal {
            return Err(ArenaError::Invalid(
                "protected failure source and terminal state are incompatible".into(),
            ));
        }
        validate_failure_correspondence(
            &failure.exact_bytes,
            &self.header.prelaunch,
            self.header.execution_launch_record_id.as_ref(),
            terminal_state,
            None,
        )?;
        self.execute_poisoned(move |arena| {
            let section =
                arena.write_section(SectionKind::ProtectedFailure, &failure.exact_bytes)?;
            arena.transition_inner(|header| {
                header.state = terminal_state;
                header.protected_failure = Some(section.clone());
                Ok(())
            })?;
            Ok(section)
        })
    }

    /// Terminalize one exact sealed final closure whose Store projection
    /// failed deterministic correspondence validation.
    ///
    /// This preserves the immutable final bytes and commits a separate bounded
    /// reason carrier. It cannot be used for a missing or corrupt final frame,
    /// and it never re-enters derivation or projection.
    pub(crate) fn refuse_final_projection(
        &mut self,
        refusal: ArenaFailureCarrierCandidate,
    ) -> Result<SealedSection, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::FinalV2SealedIndexPending
            || self.header.final_v2_closure.is_none()
            || self.header.protected_failure.is_some()
        {
            return Err(ArenaError::Invalid(
                "projection refusal requires one exact index-pending closure".into(),
            ));
        }
        self.read_committed_section(SectionKind::FinalV2Closure)?
            .ok_or_else(|| ArenaError::Invalid("final projection bytes are unavailable".into()))?;
        validate_failure_correspondence(
            &refusal.exact_bytes,
            &self.header.prelaunch,
            self.header.execution_launch_record_id.as_ref(),
            ArenaState::FinalV2ProjectionRefused,
            self.header.final_v2_closure.as_ref(),
        )?;
        self.execute_poisoned(move |arena| {
            let section =
                arena.write_section(SectionKind::ProtectedFailure, &refusal.exact_bytes)?;
            arena.transition_inner(|header| {
                header.state = ArenaState::FinalV2ProjectionRefused;
                header.protected_failure = Some(section.clone());
                Ok(())
            })?;
            Ok(section)
        })
    }

    #[allow(clippy::needless_pass_by_value)] // Consumption is the one-use index authority.
    pub(crate) fn mark_indexed(
        &mut self,
        final_token: FinalCustodyToken,
    ) -> Result<(), ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::FinalV2SealedIndexPending {
            return Err(ArenaError::Invalid(
                "only a sealed final closure can become indexed".into(),
            ));
        }
        if final_token.reservation_id != self.header.prelaunch.reservation_record_id
            || self.header.final_v2_closure.as_ref() != Some(&final_token.section)
        {
            return Err(ArenaError::Invalid(
                "final custody token differs from the index-pending closure".into(),
            ));
        }
        self.execute_poisoned(|arena| {
            arena.transition_inner(|header| {
                header.state = ArenaState::FinalV2SealedIndexed;
                Ok(())
            })
        })
    }

    pub(crate) fn raw_evidence_bytes(&self) -> Result<Option<Vec<u8>>, ArenaError> {
        self.ensure_usable()?;
        self.read_committed_section(SectionKind::RawEvidence)
    }

    /// Reopen and decode the exact acquisition carrier at any post-acquisition
    /// frontier without reconstructing a one-use derivation capability.
    ///
    /// This read exists for Store-owned arena/SQL projection verification. It
    /// advances no state and assigns no provider or diagnostic semantics.
    pub(crate) fn acquisition_for_projection(&self) -> Result<AcquisitionCarrier, ArenaError> {
        self.ensure_usable()?;
        if !matches!(
            self.header.state,
            ArenaState::RawEvidenceSealed
                | ArenaState::DerivationClaimed
                | ArenaState::FinalV2SealedIndexPending
                | ArenaState::FinalV2SealedIndexed
        ) {
            return Err(ArenaError::Invalid(
                "arena has no acquisition carrier available for projection verification".into(),
            ));
        }
        let bytes = self
            .read_committed_section(SectionKind::RawEvidence)?
            .ok_or_else(|| ArenaError::Invalid("raw acquisition is unavailable".into()))?;
        AcquisitionCarrier::decode(&bytes)
    }

    pub(crate) fn dependency_closure_bytes(&self) -> Result<Vec<u8>, ArenaError> {
        self.ensure_usable()?;
        self.read_committed_section(SectionKind::DependencyClosure)?
            .ok_or_else(|| ArenaError::Invalid("dependency closure is unavailable".into()))
    }

    pub(crate) fn final_v2_closure_bytes(&self) -> Result<Option<Vec<u8>>, ArenaError> {
        self.ensure_usable()?;
        self.read_committed_section(SectionKind::FinalV2Closure)
    }

    /// Reconstruct the one-use raw-custody capability after a verified reopen.
    ///
    /// This does not advance the durable state. It exists so a caller can
    /// continue an interrupted invocation without reacquiring the historical
    /// provider occurrence. The caller remains responsible for validating the
    /// opaque intake bytes before claiming derivation.
    pub(crate) fn reopen_raw_token(&self) -> Result<RawCustodyToken, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::RawEvidenceSealed {
            return Err(ArenaError::Invalid(
                "raw custody can be resumed only from raw_evidence_sealed".into(),
            ));
        }
        let section = self
            .header
            .raw_evidence
            .clone()
            .ok_or_else(|| ArenaError::Invalid("raw custody section is absent".into()))?;
        let bytes = self
            .read_committed_section(SectionKind::RawEvidence)?
            .ok_or_else(|| ArenaError::Invalid("raw custody bytes are absent".into()))?;
        let carrier = AcquisitionCarrier::decode(&bytes)?;
        Ok(RawCustodyToken {
            reservation_id: self.header.prelaunch.reservation_record_id.clone(),
            section,
            carrier,
        })
    }

    /// Reconstruct the one-use derivation-custody capability after reopen.
    ///
    /// The exact raw carrier and durable derivation claim are reopened and
    /// reverified. No evaluator or diagnostic semantics are established here.
    pub(crate) fn reopen_derivation_token(&self) -> Result<DerivationCustodyToken, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::DerivationClaimed {
            return Err(ArenaError::Invalid(
                "derivation custody can be resumed only from derivation_claimed".into(),
            ));
        }
        let raw_section = self
            .header
            .raw_evidence
            .clone()
            .ok_or_else(|| ArenaError::Invalid("raw custody section is absent".into()))?;
        let bytes = self
            .read_committed_section(SectionKind::RawEvidence)?
            .ok_or_else(|| ArenaError::Invalid("raw custody bytes are absent".into()))?;
        let reopened_carrier = AcquisitionCarrier::decode(&bytes)?;
        let claim = self
            .header
            .derivation_claim
            .clone()
            .ok_or_else(|| ArenaError::Invalid("durable derivation claim is absent".into()))?;
        Ok(DerivationCustodyToken {
            reservation_id: self.header.prelaunch.reservation_record_id.clone(),
            raw_section,
            reopened_carrier,
            claim,
        })
    }

    /// Reconstruct the one-use index marker capability after reopen.
    ///
    /// Reopening an index-pending closure never reconstructs or writes the
    /// SQLite projection. The caller must first prove the exact idempotent SQL
    /// write set before consuming this capability.
    pub(crate) fn reopen_final_token(&self) -> Result<FinalCustodyToken, ArenaError> {
        self.ensure_usable()?;
        self.verify_physical_allocation()?;
        if self.header.state != ArenaState::FinalV2SealedIndexPending {
            return Err(ArenaError::Invalid(
                "final custody can be resumed only from final_v2_sealed_index_pending".into(),
            ));
        }
        let section = self
            .header
            .final_v2_closure
            .clone()
            .ok_or_else(|| ArenaError::Invalid("final custody section is absent".into()))?;
        self.read_committed_section(SectionKind::FinalV2Closure)?
            .ok_or_else(|| ArenaError::Invalid("final custody bytes are absent".into()))?;
        Ok(FinalCustodyToken {
            reservation_id: self.header.prelaunch.reservation_record_id.clone(),
            section,
        })
    }

    pub(crate) fn protected_failure_bytes(&self) -> Result<Option<Vec<u8>>, ArenaError> {
        self.ensure_usable()?;
        self.read_committed_section(SectionKind::ProtectedFailure)
    }

    fn ensure_usable(&self) -> Result<(), ArenaError> {
        if self.poisoned {
            return Err(ArenaError::Invalid(
                "custody arena has an indeterminate prior write; drop and reopen it before any state read or transition"
                    .into(),
            ));
        }
        Ok(())
    }

    fn execute_poisoned<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, ArenaError>,
    ) -> Result<T, ArenaError> {
        self.ensure_usable()?;
        self.poisoned = true;
        let result = operation(self);
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    fn transition_inner(
        &mut self,
        mutate: impl FnOnce(&mut ArenaHeader) -> Result<(), ArenaError>,
    ) -> Result<(), ArenaError> {
        self.verify_physical_allocation()?;
        let mut next = self.header.clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| ArenaError::Invalid("arena sequence overflowed".into()))?;
        mutate(&mut next)?;
        validate_successor(&self.header, &next)?;
        let target = (self.active_superblock + 1) % 2;
        write_superblock(&self.file, target, &next)?;
        self.file.sync_data()?;
        #[cfg(test)]
        if self.failpoint == Some(ArenaFailpoint::SuperblockAfterSync) {
            return Err(ArenaError::Invalid(
                "injected indeterminate arena superblock write".into(),
            ));
        }
        let (reopened, reopened_digest) = read_superblock(&self.file, target)?;
        if reopened != next {
            return Err(ArenaError::Invalid(
                "arena superblock differed immediately after sync".into(),
            ));
        }
        self.header = next;
        self.active_superblock = target;
        self.selected_superblock_digest = reopened_digest;
        self.recovered_torn_superblock = false;
        Ok(())
    }

    fn write_section(
        &mut self,
        kind: SectionKind,
        exact_bytes: &[u8],
    ) -> Result<SealedSection, ArenaError> {
        let (header_offset, payload_offset, capacity) = self.header.layout.section(kind);
        let payload_length = u64::try_from(exact_bytes.len())
            .map_err(|_| ArenaError::Invalid("section length overflowed".into()))?;
        if payload_length == 0 || payload_length > capacity {
            return Err(ArenaError::Invalid(format!(
                "{kind:?} section requires {payload_length} bytes but capacity is {capacity}"
            )));
        }
        self.verify_physical_allocation()?;
        self.clear_section_scratch(kind)?;
        write_all_at(&self.file, payload_offset, exact_bytes)?;
        self.file.sync_data()?;
        let payload_digest = sha256_bytes(exact_bytes);
        let frame = encode_section_header(kind, payload_length, &payload_digest)?;
        write_all_at(&self.file, header_offset, &frame)?;
        self.file.sync_data()?;
        #[cfg(test)]
        if self.failpoint == Some(ArenaFailpoint::SectionAfterSync) {
            return Err(ArenaError::Invalid(
                "injected indeterminate arena section write".into(),
            ));
        }
        #[cfg(test)]
        if self.failpoint == Some(ArenaFailpoint::SectionAfterSyncSigkill) {
            kill_current_test_process();
        }
        let reopened = self
            .read_section_frame(kind)?
            .ok_or_else(|| ArenaError::Invalid(format!("{kind:?} section vanished after sync")))?;
        if reopened != exact_bytes {
            return Err(ArenaError::Invalid(format!(
                "{kind:?} section differed immediately after sync"
            )));
        }
        Ok(SealedSection {
            kind,
            payload_length,
            payload_digest,
        })
    }

    fn section_commitment(
        &self,
        kind: SectionKind,
        exact_bytes: &[u8],
    ) -> Result<SealedSection, ArenaError> {
        let (_, _, capacity) = self.header.layout.section(kind);
        let payload_length = u64::try_from(exact_bytes.len())
            .map_err(|_| ArenaError::Invalid("section length overflowed".into()))?;
        if payload_length == 0 || payload_length > capacity {
            return Err(ArenaError::Invalid(format!(
                "{kind:?} section requires {payload_length} bytes but capacity is {capacity}"
            )));
        }
        Ok(SealedSection {
            kind,
            payload_length,
            payload_digest: sha256_bytes(exact_bytes),
        })
    }

    fn clear_section_scratch(&self, kind: SectionKind) -> Result<(), ArenaError> {
        let (header_offset, _, capacity) = self.header.layout.section(kind);
        let length = SECTION_HEADER_SIZE
            .checked_add(capacity)
            .ok_or_else(|| ArenaError::Invalid("section clear length overflowed".into()))?;
        write_zero_range(&self.file, header_offset, length)?;
        self.file.sync_data()?;
        self.verify_physical_allocation()
    }

    fn read_committed_section(&self, kind: SectionKind) -> Result<Option<Vec<u8>>, ArenaError> {
        let expected = match kind {
            SectionKind::DependencyClosure => self.header.dependency_closure.as_ref(),
            SectionKind::RawEvidence => self.header.raw_evidence.as_ref(),
            SectionKind::FinalV2Closure => self.header.final_v2_closure.as_ref(),
            SectionKind::ProtectedFailure => self.header.protected_failure.as_ref(),
        };
        let Some(expected) = expected else {
            // A frame written before its superblock is scratch. It cannot
            // advance or corrupt the state selected from the durable header.
            return Ok(None);
        };
        let bytes = self
            .read_section_frame(kind)?
            .ok_or_else(|| ArenaError::Invalid(format!("{kind:?} committed frame is absent")))?;
        if expected.kind != kind
            || expected.payload_length != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || expected.payload_digest != sha256_bytes(&bytes)
        {
            return Err(ArenaError::Invalid(
                "arena superblock and committed section frame disagree".into(),
            ));
        }
        Ok(Some(bytes))
    }

    fn read_section_frame(&self, kind: SectionKind) -> Result<Option<Vec<u8>>, ArenaError> {
        let (header_offset, payload_offset, capacity) = self.header.layout.section(kind);
        let mut frame = [0_u8; SECTION_HEADER_BYTES];
        read_exact_at(&self.file, header_offset, &mut frame)?;
        if frame.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        let (frame_kind, payload_length, payload_digest) = decode_section_header(&frame)?;
        if frame_kind != kind || payload_length == 0 || payload_length > capacity {
            return Err(ArenaError::Invalid(format!(
                "{kind:?} section frame is substituted or out of bounds"
            )));
        }
        let mut payload = vec![
            0_u8;
            usize::try_from(payload_length).map_err(|_| {
                ArenaError::Invalid("section length exceeds address space".into())
            })?
        ];
        read_exact_at(&self.file, payload_offset, &mut payload)?;
        if sha256_bytes(&payload) != payload_digest {
            return Err(ArenaError::Invalid(format!(
                "{kind:?} section payload digest differs"
            )));
        }
        verify_zero_range(
            &self.file,
            payload_offset
                .checked_add(payload_length)
                .ok_or_else(|| ArenaError::Invalid("section tail offset overflowed".into()))?,
            capacity
                .checked_sub(payload_length)
                .ok_or_else(|| ArenaError::Invalid("section payload exceeds capacity".into()))?,
            "sealed section unused capacity",
        )?;
        Ok(Some(payload))
    }

    #[allow(clippy::too_many_lines)] // One closed state-shape audit keeps every durable frontier explicit.
    fn verify_file_shape(&self) -> Result<(), ArenaError> {
        self.header.layout.validate()?;
        validate_header_request_id(&self.header.prelaunch.outer_request_id)?;
        if let Some(claimed_at) = &self.header.claimed_at {
            validate_header_timestamp(claimed_at, "launch claim")?;
        }
        if let Some(claim) = &self.header.derivation_claim {
            validate_derivation_header_text(claim)?;
        }
        let metadata = self.file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ArenaError::Invalid(
                "arena is not one private regular file".into(),
            ));
        }
        if metadata.len() != self.header.layout.file_length {
            return Err(ArenaError::Invalid(format!(
                "arena length {} differs from header {}",
                metadata.len(),
                self.header.layout.file_length
            )));
        }
        if self.header.schema != ARENA_FORMAT || self.header.sequence == 0 {
            return Err(ArenaError::Invalid(
                "arena header has incompatible identity".into(),
            ));
        }
        let state_shape_valid = match self.header.state {
            ArenaState::Reserved => {
                self.header.execution_launch_record_id.is_none()
                    && self.header.claimed_at.is_none()
                    && self.header.raw_evidence.is_none()
                    && self.header.derivation_claim.is_none()
                    && self.header.final_v2_closure.is_none()
                    && self.header.protected_failure.is_none()
            }
            ArenaState::Claimed => {
                self.header.execution_launch_record_id.is_some()
                    && self.header.claimed_at.is_some()
                    && self.header.raw_evidence.is_none()
                    && self.header.derivation_claim.is_none()
                    && self.header.final_v2_closure.is_none()
                    && self.header.protected_failure.is_none()
            }
            ArenaState::RawEvidenceSealed => {
                self.header.execution_launch_record_id.is_some()
                    && self.header.claimed_at.is_some()
                    && self.header.raw_evidence.is_some()
                    && self.header.derivation_claim.is_none()
                    && self.header.final_v2_closure.is_none()
                    && self.header.protected_failure.is_none()
            }
            ArenaState::DerivationClaimed => {
                self.header.execution_launch_record_id.is_some()
                    && self.header.claimed_at.is_some()
                    && self.header.raw_evidence.is_some()
                    && self.header.derivation_claim.is_some()
                    && self.header.final_v2_closure.is_none()
                    && self.header.protected_failure.is_none()
            }
            ArenaState::FinalV2SealIntent
            | ArenaState::FinalV2SealedIndexPending
            | ArenaState::FinalV2SealedIndexed
            | ArenaState::FinalV2SealCommittedUnavailable
            | ArenaState::FinalV2SealCorrupt => {
                self.header.execution_launch_record_id.is_some()
                    && self.header.claimed_at.is_some()
                    && self.header.raw_evidence.is_some()
                    && self.header.derivation_claim.is_some()
                    && self.header.final_v2_closure.is_some()
                    && self.header.protected_failure.is_none()
            }
            ArenaState::FinalV2ProjectionRefused => {
                self.header.execution_launch_record_id.is_some()
                    && self.header.claimed_at.is_some()
                    && self.header.raw_evidence.is_some()
                    && self.header.derivation_claim.is_some()
                    && self.header.final_v2_closure.is_some()
                    && self.header.protected_failure.is_some()
            }
            ArenaState::FailedIndeterminate => {
                self.header.execution_launch_record_id.is_some()
                    && self.header.claimed_at.is_some()
                    && self.header.final_v2_closure.is_none()
                    && self.header.protected_failure.is_some()
            }
            ArenaState::ExpiredUnlaunched => {
                self.header.execution_launch_record_id.is_none()
                    && self.header.claimed_at.is_none()
                    && self.header.raw_evidence.is_none()
                    && self.header.derivation_claim.is_none()
                    && self.header.final_v2_closure.is_none()
                    && self.header.protected_failure.is_some()
            }
        };
        if !state_shape_valid || self.header.dependency_closure.is_none() {
            return Err(ArenaError::Invalid(
                "arena state and sealed-section frontier disagree".into(),
            ));
        }
        self.verify_physical_allocation()?;
        self.verify_layout_padding()?;
        Ok(())
    }

    fn verify_sealed_sections(&self) -> Result<(), ArenaError> {
        for kind in [
            SectionKind::DependencyClosure,
            SectionKind::RawEvidence,
            SectionKind::FinalV2Closure,
            SectionKind::ProtectedFailure,
        ] {
            if kind == SectionKind::FinalV2Closure
                && matches!(
                    self.header.state,
                    ArenaState::FinalV2SealIntent
                        | ArenaState::FinalV2SealCommittedUnavailable
                        | ArenaState::FinalV2SealCorrupt
                )
            {
                // The intent header, rather than a successfully reopened
                // frame, is authoritative at these frontiers. Engine-owned
                // recovery adjudicates an intent; terminal unavailable/corrupt
                // states remain inspectable without fabricating bytes.
                continue;
            }
            if let Some(bytes) = self.read_committed_section(kind)? {
                match kind {
                    SectionKind::DependencyClosure => {
                        if sha256_bytes(&bytes)
                            != self.header.prelaunch.dependency_generation_custody_digest
                        {
                            return Err(ArenaError::Invalid(
                                "reopened dependency closure differs from prelaunch".into(),
                            ));
                        }
                    }
                    SectionKind::RawEvidence => {
                        let carrier = AcquisitionCarrier::decode(&bytes)?;
                        if self.header.execution_launch_record_id.as_ref()
                            != Some(&carrier.execution_launch_record_id)
                        {
                            return Err(ArenaError::Invalid(
                                "reopened acquisition differs from launch identity".into(),
                            ));
                        }
                    }
                    SectionKind::FinalV2Closure => {
                        let claim = self.header.derivation_claim.as_ref().ok_or_else(|| {
                            ArenaError::Invalid(
                                "reopened final V2 closure has no derivation claim".into(),
                            )
                        })?;
                        validate_final_v2_correspondence(&bytes, &self.header.prelaunch, claim)?;
                    }
                    SectionKind::ProtectedFailure => {
                        validate_failure_correspondence(
                            &bytes,
                            &self.header.prelaunch,
                            self.header.execution_launch_record_id.as_ref(),
                            self.header.state,
                            self.header.final_v2_closure.as_ref(),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_physical_allocation(&self) -> Result<(), ArenaError> {
        let metadata = self.file.metadata()?;
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| ArenaError::Invalid("allocated block count overflowed".into()))?;
        if allocated < self.header.layout.file_length {
            return Err(ArenaError::Invalid(format!(
                "arena has a sparse or deallocated extent: {allocated} allocated for {} bytes",
                self.header.layout.file_length
            )));
        }
        Ok(())
    }

    fn verify_layout_padding(&self) -> Result<(), ArenaError> {
        let layout = &self.header.layout;
        let dependency_end = layout
            .dependency_payload_offset
            .checked_add(layout.dependency_capacity)
            .ok_or_else(|| ArenaError::Invalid("dependency padding offset overflowed".into()))?;
        verify_zero_range(
            &self.file,
            dependency_end,
            layout
                .raw_header_offset
                .checked_sub(dependency_end)
                .ok_or_else(|| ArenaError::Invalid("dependency/raw layout overlaps".into()))?,
            "dependency/raw alignment padding",
        )?;
        let raw_end = layout
            .raw_payload_offset
            .checked_add(layout.raw_capacity)
            .ok_or_else(|| ArenaError::Invalid("raw padding offset overflowed".into()))?;
        verify_zero_range(
            &self.file,
            raw_end,
            layout
                .final_header_offset
                .checked_sub(raw_end)
                .ok_or_else(|| ArenaError::Invalid("raw/final layout overlaps".into()))?,
            "raw/final alignment padding",
        )?;
        let final_end = layout
            .final_payload_offset
            .checked_add(layout.final_capacity)
            .ok_or_else(|| ArenaError::Invalid("final padding offset overflowed".into()))?;
        verify_zero_range(
            &self.file,
            final_end,
            layout
                .failure_header_offset
                .checked_sub(final_end)
                .ok_or_else(|| ArenaError::Invalid("final/failure layout overlaps".into()))?,
            "final/failure alignment padding",
        )?;
        let failure_end = layout
            .failure_payload_offset
            .checked_add(layout.failure_capacity)
            .ok_or_else(|| ArenaError::Invalid("failure padding offset overflowed".into()))?;
        verify_zero_range(
            &self.file,
            failure_end,
            layout
                .file_length
                .checked_sub(failure_end)
                .ok_or_else(|| ArenaError::Invalid("failure/file layout overlaps".into()))?,
            "failure/file alignment padding",
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

type LifetimeLockedFile = nix::fcntl::Flock<File>;

fn lock_lifetime_exclusive(file: File) -> Result<LifetimeLockedFile, ArenaError> {
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).map_err(
        |(_file, error)| {
            ArenaError::Invalid(format!(
                "custody file cannot obtain its exclusive lifetime lock: {error}"
            ))
        },
    )
}

fn ensure_arena_root(database_path: &Path, path: &Path) -> Result<(), ArenaError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_arena_root(database_path, path).map(drop),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path)?;
            sync_directory(
                path.parent()
                    .ok_or_else(|| ArenaError::Invalid("arena root has no parent".into()))?,
            )?;
            verify_arena_root(database_path, path).map(drop)
        }
        Err(error) => Err(error.into()),
    }
}

fn create_arena_file(
    database_path: &Path,
    root: &Path,
    relative: &Path,
) -> Result<File, ArenaError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::{Mode, fstat};
    use nix::unistd::{close, fsync};

    let root_identity = verify_arena_root(database_path, root)?;
    let root_handle = open_root_handle(root, root_identity)?;
    let raw = openat(
        Some(root_handle.as_raw_fd()),
        relative,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let opened = (|| {
        fsync(raw).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        let created = fstat(raw).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        let path = root.join(relative);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let reopened = file.metadata()?;
        if created.st_dev != reopened.dev() || created.st_ino != reopened.ino() {
            return Err(ArenaError::Invalid(
                "dirfd-created arena changed identity before reopen".into(),
            ));
        }
        verify_root_handle_unchanged(root, &root_handle, root_identity)?;
        verify_arena_file(database_path, root, &file)?;
        Ok(file)
    })();
    let close_result = close(raw).map_err(|error| io::Error::from_raw_os_error(error as i32));
    match (opened, close_result) {
        (Ok(file), Ok(())) => Ok(file),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn open_arena_file(
    database_path: &Path,
    root: &Path,
    relative: &Path,
    root_identity: &RootIdentity,
) -> Result<File, ArenaError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::fstat;
    use nix::unistd::close;

    let root_handle = open_root_handle(root, *root_identity)?;
    let raw = openat(
        Some(root_handle.as_raw_fd()),
        relative,
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let opened = (|| {
        let from_dirfd = fstat(raw).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root.join(relative))?;
        let reopened = file.metadata()?;
        if from_dirfd.st_dev != reopened.dev() || from_dirfd.st_ino != reopened.ino() {
            return Err(ArenaError::Invalid(
                "dirfd arena changed identity before path reopen".into(),
            ));
        }
        verify_root_handle_unchanged(root, &root_handle, *root_identity)?;
        verify_arena_file(database_path, root, &file)?;
        Ok(file)
    })();
    let close_result = close(raw).map_err(|error| io::Error::from_raw_os_error(error as i32));
    match (opened, close_result) {
        (Ok(file), Ok(())) => Ok(file),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn verify_arena_root(database_path: &Path, path: &Path) -> Result<RootIdentity, ArenaError> {
    let metadata = fs::symlink_metadata(path)?;
    let database = fs::metadata(normalized_database_path(database_path)?)?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != effective_uid
        || metadata.dev() != database.dev()
        || metadata.nlink() < 2
    {
        return Err(ArenaError::Invalid(
            "custody arena root is not one same-filesystem, owner-private real directory".into(),
        ));
    }
    let identity = RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.permissions().mode() & 0o777,
    };
    let handle = open_root_handle(path, identity)?;
    verify_root_handle_unchanged(path, &handle, identity)?;
    Ok(identity)
}

fn verify_arena_file(database_path: &Path, root: &Path, file: &File) -> Result<(), ArenaError> {
    let database = fs::metadata(normalized_database_path(database_path)?)?;
    let root_metadata = fs::metadata(root)?;
    let metadata = file.metadata()?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if database.dev() != root_metadata.dev()
        || database.dev() != metadata.dev()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ArenaError::Invalid(
            "arena must be one same-filesystem, single-link, owner-private regular file".into(),
        ));
    }
    Ok(())
}

fn open_root_handle(path: &Path, expected: RootIdentity) -> Result<File, ArenaError> {
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    verify_root_handle_unchanged(path, &handle, expected)?;
    Ok(handle)
}

fn verify_root_handle_unchanged(
    path: &Path,
    handle: &File,
    expected: RootIdentity,
) -> Result<(), ArenaError> {
    let handle_metadata = handle.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    let actual = RootIdentity {
        device: handle_metadata.dev(),
        inode: handle_metadata.ino(),
        owner: handle_metadata.uid(),
        mode: handle_metadata.permissions().mode() & 0o777,
    };
    let path_actual = RootIdentity {
        device: path_metadata.dev(),
        inode: path_metadata.ino(),
        owner: path_metadata.uid(),
        mode: path_metadata.permissions().mode() & 0o777,
    };
    if actual != expected || path_actual != expected || !path_metadata.file_type().is_dir() {
        return Err(ArenaError::Invalid(
            "custody arena root changed identity during dirfd operation".into(),
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ArenaError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn normalized_database_path(path: &Path) -> Result<PathBuf, ArenaError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| ArenaError::Invalid("database path has no final component".into()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn align_up(value: u64, alignment: u64) -> Result<u64, ArenaError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(ArenaError::Invalid("arena alignment is invalid".into()));
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or_else(|| ArenaError::Invalid("arena alignment overflowed".into()))
}

fn fallocate_exact(file: &File, length: u64) -> Result<(), ArenaError> {
    let length = libc::off_t::try_from(length)
        .map_err(|_| ArenaError::Invalid("arena length exceeds off_t".into()))?;
    nix::fcntl::fallocate(
        file.as_raw_fd(),
        nix::fcntl::FallocateFlags::empty(),
        0,
        length,
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    file.set_len(u64::try_from(length).expect("validated nonnegative off_t"))?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| ArenaError::Invalid("allocated block count overflowed".into()))?;
    if allocated < metadata.len() {
        return Err(ArenaError::Invalid(format!(
            "fallocate reported success but only {allocated} of {} bytes are allocated",
            metadata.len()
        )));
    }
    Ok(())
}

fn write_all_at(file: &File, mut offset: u64, mut bytes: &[u8]) -> Result<(), ArenaError> {
    while !bytes.is_empty() {
        let written = match file.write_at(bytes, offset) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if written == 0 {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "arena pwrite returned zero").into(),
            );
        }
        offset = offset
            .checked_add(u64::try_from(written).expect("usize fits u64"))
            .ok_or_else(|| ArenaError::Invalid("arena write offset overflowed".into()))?;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn read_exact_at(file: &File, mut offset: u64, mut bytes: &mut [u8]) -> Result<(), ArenaError> {
    while !bytes.is_empty() {
        let read = match file.read_at(bytes, offset) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            return Err(
                io::Error::new(io::ErrorKind::UnexpectedEof, "arena pread reached EOF").into(),
            );
        }
        offset = offset
            .checked_add(u64::try_from(read).expect("usize fits u64"))
            .ok_or_else(|| ArenaError::Invalid("arena read offset overflowed".into()))?;
        let (_, rest) = bytes.split_at_mut(read);
        bytes = rest;
    }
    Ok(())
}

fn verify_zero_range(
    file: &File,
    mut offset: u64,
    mut length: u64,
    label: &str,
) -> Result<(), ArenaError> {
    let mut buffer = [0_u8; 4096];
    while length != 0 {
        let take =
            usize::try_from(length.min(buffer.len() as u64)).expect("bounded by fixed buffer");
        read_exact_at(file, offset, &mut buffer[..take])?;
        if buffer[..take].iter().any(|byte| *byte != 0) {
            return Err(ArenaError::Invalid(format!(
                "{label} contains nonzero bytes"
            )));
        }
        offset = offset
            .checked_add(u64::try_from(take).expect("usize fits u64"))
            .ok_or_else(|| ArenaError::Invalid("zero-range offset overflowed".into()))?;
        length -= u64::try_from(take).expect("usize fits u64");
    }
    Ok(())
}

fn write_zero_range(file: &File, mut offset: u64, mut length: u64) -> Result<(), ArenaError> {
    let zeros = [0_u8; 4096];
    while length != 0 {
        let take =
            usize::try_from(length.min(zeros.len() as u64)).expect("bounded by fixed buffer");
        write_all_at(file, offset, &zeros[..take])?;
        offset = offset
            .checked_add(u64::try_from(take).expect("usize fits u64"))
            .ok_or_else(|| ArenaError::Invalid("zero-write offset overflowed".into()))?;
        length -= u64::try_from(take).expect("usize fits u64");
    }
    Ok(())
}

fn encode_superblock(header: &ArenaHeader) -> Result<[u8; SUPERBLOCK_BYTES], ArenaError> {
    let payload = canonical_json_bytes(header)
        .map_err(|error| ArenaError::Invalid(format!("cannot encode superblock: {error}")))?;
    if payload.len() > MAX_SUPERBLOCK_JSON_BYTES {
        return Err(ArenaError::Invalid(format!(
            "arena superblock payload {} exceeds {} bytes",
            payload.len(),
            MAX_SUPERBLOCK_JSON_BYTES
        )));
    }
    let mut block = [0_u8; SUPERBLOCK_BYTES];
    block[..8].copy_from_slice(SUPERBLOCK_MAGIC);
    block[8] = FORMAT_VERSION;
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| ArenaError::Invalid("superblock length overflowed".into()))?;
    block[12..16].copy_from_slice(&payload_length.to_be_bytes());
    block[16..48].copy_from_slice(raw_digest(&payload).as_slice());
    let prefix_digest = raw_digest(&block[..48]);
    block[48..80].copy_from_slice(&prefix_digest);
    block[SUPERBLOCK_JSON_OFFSET..SUPERBLOCK_JSON_OFFSET + payload.len()].copy_from_slice(&payload);
    Ok(block)
}

fn decode_superblock(block: &[u8; SUPERBLOCK_BYTES]) -> Result<ArenaHeader, ArenaError> {
    if &block[..8] != SUPERBLOCK_MAGIC || block[8] != FORMAT_VERSION {
        return Err(ArenaError::Invalid(
            "arena superblock magic or version differs".into(),
        ));
    }
    if raw_digest(&block[..48]).as_slice() != &block[48..80] {
        return Err(ArenaError::Invalid(
            "arena superblock prefix digest differs".into(),
        ));
    }
    if block[80..SUPERBLOCK_JSON_OFFSET]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ArenaError::Invalid(
            "arena superblock reserved prefix is nonzero".into(),
        ));
    }
    let payload_length =
        u32::from_be_bytes(block[12..16].try_into().expect("fixed range")) as usize;
    if payload_length == 0 || payload_length > MAX_SUPERBLOCK_JSON_BYTES {
        return Err(ArenaError::Invalid(
            "arena superblock payload length is invalid".into(),
        ));
    }
    let payload = &block[SUPERBLOCK_JSON_OFFSET..SUPERBLOCK_JSON_OFFSET + payload_length];
    if raw_digest(payload).as_slice() != &block[16..48] {
        return Err(ArenaError::Invalid(
            "arena superblock payload digest differs".into(),
        ));
    }
    if block[SUPERBLOCK_JSON_OFFSET + payload_length..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ArenaError::Invalid(
            "arena superblock trailing region is nonzero".into(),
        ));
    }
    let header: ArenaHeader = serde_json::from_slice(payload)
        .map_err(|error| ArenaError::Invalid(format!("cannot decode superblock: {error}")))?;
    if canonical_json_bytes(&header)
        .map_err(|error| ArenaError::Invalid(format!("cannot canonicalize superblock: {error}")))?
        != payload
    {
        return Err(ArenaError::Invalid(
            "arena superblock JSON is not canonical".into(),
        ));
    }
    Ok(header)
}

fn write_superblock(file: &File, slot: usize, header: &ArenaHeader) -> Result<(), ArenaError> {
    let offset = u64::try_from(slot)
        .map_err(|_| ArenaError::Invalid("superblock slot overflowed".into()))?
        .checked_mul(SUPERBLOCK_SIZE)
        .ok_or_else(|| ArenaError::Invalid("superblock offset overflowed".into()))?;
    write_all_at(file, offset, &encode_superblock(header)?)
}

fn superblock_digest(file: &File, slot: usize) -> Result<Sha256Digest, ArenaError> {
    let offset = u64::try_from(slot)
        .map_err(|_| ArenaError::Invalid("superblock slot overflowed".into()))?
        .checked_mul(SUPERBLOCK_SIZE)
        .ok_or_else(|| ArenaError::Invalid("superblock offset overflowed".into()))?;
    let mut block = [0_u8; SUPERBLOCK_BYTES];
    read_exact_at(file, offset, &mut block)?;
    Ok(sha256_bytes(&block))
}

fn read_superblock(file: &File, slot: usize) -> Result<(ArenaHeader, Sha256Digest), ArenaError> {
    let offset = u64::try_from(slot)
        .map_err(|_| ArenaError::Invalid("superblock slot overflowed".into()))?
        .checked_mul(SUPERBLOCK_SIZE)
        .ok_or_else(|| ArenaError::Invalid("superblock offset overflowed".into()))?;
    let mut block = [0_u8; SUPERBLOCK_BYTES];
    read_exact_at(file, offset, &mut block)?;
    Ok((decode_superblock(&block)?, sha256_bytes(&block)))
}

fn select_superblock(
    first: Result<(ArenaHeader, Sha256Digest), ArenaError>,
    second: Result<(ArenaHeader, Sha256Digest), ArenaError>,
) -> Result<(ArenaHeader, usize, Sha256Digest, bool), ArenaError> {
    match (first, second) {
        (Ok((first, first_digest)), Ok((second, second_digest))) => {
            if first.schema != second.schema
                || first.prelaunch != second.prelaunch
                || first.layout != second.layout
            {
                return Err(ArenaError::Invalid(
                    "arena superblocks disagree on immutable identity or layout".into(),
                ));
            }
            match first.sequence.cmp(&second.sequence) {
                std::cmp::Ordering::Equal if first == second => {
                    Ok((second, 1, second_digest, false))
                }
                std::cmp::Ordering::Equal => Err(ArenaError::Invalid(
                    "equal-sequence arena superblocks are split-brain".into(),
                )),
                std::cmp::Ordering::Greater => {
                    validate_successor(&second, &first)?;
                    Ok((first, 0, first_digest, false))
                }
                std::cmp::Ordering::Less => {
                    validate_successor(&first, &second)?;
                    Ok((second, 1, second_digest, false))
                }
            }
        }
        (Ok((first, digest)), Err(_)) => Ok((first, 0, digest, true)),
        (Err(_), Ok((second, digest))) => Ok((second, 1, digest, true)),
        (Err(first), Err(second)) => Err(ArenaError::Invalid(format!(
            "both arena superblocks are invalid: {first}; {second}"
        ))),
    }
}

fn validate_successor(previous: &ArenaHeader, next: &ArenaHeader) -> Result<(), ArenaError> {
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or_else(|| ArenaError::Invalid("arena sequence overflowed".into()))?;
    if previous.schema != next.schema
        || previous.prelaunch != next.prelaunch
        || previous.layout != next.layout
        || next.sequence != expected_sequence
    {
        return Err(ArenaError::Invalid(
            "arena superblocks are not one exact legal successor apart".into(),
        ));
    }
    let mut expected = previous.clone();
    expected.sequence = next.sequence;
    match (previous.state, next.state) {
        (ArenaState::Reserved, ArenaState::Claimed) => {
            expected.state = next.state;
            expected
                .execution_launch_record_id
                .clone_from(&next.execution_launch_record_id);
            expected.claimed_at.clone_from(&next.claimed_at);
        }
        (ArenaState::Claimed, ArenaState::RawEvidenceSealed) => {
            expected.state = next.state;
            expected.raw_evidence.clone_from(&next.raw_evidence);
        }
        (ArenaState::RawEvidenceSealed, ArenaState::DerivationClaimed) => {
            expected.state = next.state;
            expected.derivation_claim.clone_from(&next.derivation_claim);
        }
        (ArenaState::DerivationClaimed, ArenaState::FinalV2SealIntent) => {
            expected.state = next.state;
            expected.final_v2_closure.clone_from(&next.final_v2_closure);
        }
        (
            ArenaState::FinalV2SealIntent,
            ArenaState::FinalV2SealedIndexPending
            | ArenaState::FinalV2SealCommittedUnavailable
            | ArenaState::FinalV2SealCorrupt,
        )
        | (ArenaState::FinalV2SealedIndexPending, ArenaState::FinalV2SealedIndexed) => {
            expected.state = next.state;
        }
        (ArenaState::FinalV2SealedIndexPending, ArenaState::FinalV2ProjectionRefused)
        | (
            ArenaState::Claimed | ArenaState::RawEvidenceSealed | ArenaState::DerivationClaimed,
            ArenaState::FailedIndeterminate,
        )
        | (ArenaState::Reserved, ArenaState::ExpiredUnlaunched) => {
            expected.state = next.state;
            expected
                .protected_failure
                .clone_from(&next.protected_failure);
        }
        _ => {
            return Err(ArenaError::Invalid(
                "arena state transition is not permitted".into(),
            ));
        }
    }
    if &expected != next {
        return Err(ArenaError::Invalid(
            "arena successor changed fields outside its one permitted transition".into(),
        ));
    }
    Ok(())
}

fn encode_section_header(
    kind: SectionKind,
    payload_length: u64,
    payload_digest: &Sha256Digest,
) -> Result<[u8; SECTION_HEADER_BYTES], ArenaError> {
    let mut frame = [0_u8; SECTION_HEADER_BYTES];
    frame[..8].copy_from_slice(SECTION_MAGIC);
    frame[8] = FORMAT_VERSION;
    frame[9] = kind.tag();
    frame[16..24].copy_from_slice(&payload_length.to_be_bytes());
    frame[24..56].copy_from_slice(&raw_digest_from_protocol(payload_digest)?);
    let prefix_digest = raw_digest(&frame[..56]);
    frame[56..88].copy_from_slice(&prefix_digest);
    Ok(frame)
}

fn decode_section_header(
    frame: &[u8; SECTION_HEADER_BYTES],
) -> Result<(SectionKind, u64, Sha256Digest), ArenaError> {
    if &frame[..8] != SECTION_MAGIC || frame[8] != FORMAT_VERSION {
        return Err(ArenaError::Invalid(
            "arena section magic or version differs".into(),
        ));
    }
    if raw_digest(&frame[..56]).as_slice() != &frame[56..88] {
        return Err(ArenaError::Invalid(
            "arena section header digest differs".into(),
        ));
    }
    if frame[88..].iter().any(|byte| *byte != 0) {
        return Err(ArenaError::Invalid(
            "arena section reserved header region is nonzero".into(),
        ));
    }
    let kind = match frame[9] {
        1 => SectionKind::RawEvidence,
        2 => SectionKind::FinalV2Closure,
        3 => SectionKind::ProtectedFailure,
        4 => SectionKind::DependencyClosure,
        _ => {
            return Err(ArenaError::Invalid("arena section kind is unknown".into()));
        }
    };
    let payload_length = u64::from_be_bytes(frame[16..24].try_into().expect("fixed range"));
    let digest = protocol_digest_from_raw(&frame[24..56])?;
    Ok((kind, payload_length, digest))
}

fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn raw_digest_from_protocol(digest: &Sha256Digest) -> Result<[u8; 32], ArenaError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| ArenaError::Invalid("digest prefix differs".into()))?;
    let decoded =
        hex::decode(hex).map_err(|_| ArenaError::Invalid("digest hexadecimal differs".into()))?;
    decoded
        .try_into()
        .map_err(|_| ArenaError::Invalid("digest length differs".into()))
}

fn protocol_digest_from_raw(raw: &[u8]) -> Result<Sha256Digest, ArenaError> {
    Sha256Digest::parse(format!("sha256:{}", hex::encode(raw)))
        .map_err(|error| ArenaError::Invalid(error.to_string()))
}

fn validate_semantic_document(
    exact_bytes: &[u8],
    expected_schema: &str,
    identity_field: &str,
) -> Result<Value, ArenaError> {
    if exact_bytes.is_empty() {
        return Err(ArenaError::Invalid(
            "canonical semantic document cannot be empty".into(),
        ));
    }
    let value: Value = serde_json::from_slice(exact_bytes)
        .map_err(|error| ArenaError::Invalid(format!("cannot decode semantic carrier: {error}")))?;
    let Some(object) = value.as_object() else {
        return Err(ArenaError::Invalid(
            "semantic carrier must be one canonical object".into(),
        ));
    };
    if value.get("schema").and_then(Value::as_str) != Some(expected_schema)
        || canonical_json_bytes(&value).map_err(|error| {
            ArenaError::Invalid(format!("cannot canonicalize semantic carrier: {error}"))
        })? != exact_bytes
    {
        return Err(ArenaError::Invalid(
            "semantic carrier schema or canonical bytes differ".into(),
        ));
    }
    let identity = object
        .get(identity_field)
        .and_then(Value::as_str)
        .ok_or_else(|| ArenaError::Invalid("semantic carrier identity is absent".into()))?;
    let mut preimage = object.clone();
    preimage.remove(identity_field);
    let expected = nq_protocol::semantic_digest(&preimage)
        .map_err(|error| ArenaError::Invalid(format!("cannot derive carrier identity: {error}")))?;
    if expected.as_str() != identity {
        return Err(ArenaError::Invalid(
            "semantic carrier identity differs from its exact preimage".into(),
        ));
    }
    Ok(value)
}

fn validate_final_v2_correspondence(
    exact_bytes: &[u8],
    _prelaunch: &ArenaPrelaunchBinding,
    _claim: &DerivationClaim,
) -> Result<(), ArenaError> {
    let _ = validate_governed_closure_document(exact_bytes)?;
    Ok(())
}

fn validate_governed_closure_document(exact_bytes: &[u8]) -> Result<Value, ArenaError> {
    let value: Value = serde_json::from_slice(exact_bytes)
        .map_err(|error| ArenaError::Invalid(format!("cannot decode final closure: {error}")))?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| ArenaError::Invalid("final closure schema is absent".into()))?;
    if !matches!(
        schema,
        "nq.governed_execution_custody_closure.v1"
            | "nq.governed_execution_custody_closure.v2"
            | "nq.governed_execution_custody_closure.v3"
    ) {
        return Err(ArenaError::Invalid(
            "final closure schema is unsupported".into(),
        ));
    }
    validate_semantic_document(exact_bytes, schema, "closure_id")
}

#[allow(clippy::too_many_lines)] // One terminal-carrier validator preserves every state-specific refusal join.
fn validate_failure_correspondence(
    exact_bytes: &[u8],
    prelaunch: &ArenaPrelaunchBinding,
    launch: Option<&Sha256Digest>,
    terminal_state: ArenaState,
    final_closure: Option<&SealedSection>,
) -> Result<(), ArenaError> {
    let value: Value = serde_json::from_slice(exact_bytes)
        .map_err(|error| ArenaError::Invalid(format!("cannot decode failure carrier: {error}")))?;
    if value["schema"] == PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA {
        let value = validate_semantic_document(
            exact_bytes,
            PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA,
            "refusal_id",
        )?;
        let reason = value["reason"]
            .as_object()
            .ok_or_else(|| ArenaError::Invalid("projection refusal has no typed reason".into()))?;
        let detail = reason
            .get("detail")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ArenaError::Invalid("projection refusal reason detail is absent".into())
            })?;
        let source_error_digest = reason
            .get("source_error_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ArenaError::Invalid("projection refusal source-error digest is absent".into())
            })?;
        Sha256Digest::parse(source_error_digest.to_owned()).map_err(|error| {
            ArenaError::Invalid(format!(
                "projection refusal source-error digest is invalid: {error}"
            ))
        })?;
        let Some(final_closure) = final_closure else {
            return Err(ArenaError::Invalid(
                "projection refusal has no sealed final-closure commitment".into(),
            ));
        };
        return match (terminal_state, launch) {
            (ArenaState::FinalV2ProjectionRefused, Some(launch))
                if value["reservation_record_id"]
                    == prelaunch.reservation_record_id.as_str()
                    && value["execution_launch_record_id"] == launch.as_str()
                    && value["final_closure"]["byte_length"]
                        == final_closure.payload_length
                    && value["final_closure"]["bytes_digest"]
                        == final_closure.payload_digest.as_str()
                    && reason.get("code").and_then(Value::as_str)
                        == Some("exact_correspondence_refused")
                    && detail.len() <= MAX_PROJECTION_REFUSAL_DETAIL_BYTES
                    && reason.get("truncated").and_then(Value::as_bool).is_some() =>
            {
                Ok(())
            }
            _ => Err(ArenaError::Invalid(
                "projection refusal differs from reservation, launch, final closure, reason, or terminal state"
                    .into(),
            )),
        };
    }
    if value["schema"] == PROTECTED_TERMINAL_SCHEMA {
        let value =
            validate_semantic_document(exact_bytes, PROTECTED_TERMINAL_SCHEMA, "terminal_id")?;
        let exact_reservation = &value["reservation"];
        let exact_request = &value["outer_request"];
        return match (terminal_state, launch) {
            (ArenaState::FailedIndeterminate, Some(launch))
                if exact_reservation["record_id"]
                    == prelaunch.reservation_record_id.as_str()
                    && exact_reservation["manifest_digest"]
                        == prelaunch.reservation_manifest_digest.as_str()
                    && exact_request["record_id"]
                        == prelaunch.outer_request_record_id.as_str()
                    && exact_request["request_id"] == prelaunch.outer_request_id
                    && exact_request["bytes_digest"]
                        == prelaunch.outer_request_digest.as_str()
                    && value["execution_launch_record_id"] == launch.as_str()
                    && value["terminalization_mode"] == "immediate_owned_launch" =>
            {
                Ok(())
            }
            _ => Err(ArenaError::Invalid(
                "protected terminal differs from reservation, request, launch, mode, or terminal state"
                    .into(),
            )),
        };
    }
    let value =
        validate_semantic_document(exact_bytes, "nq.governed_custody_failure.v1", "failure_id")?;
    if value["reservation_id"] != prelaunch.reservation_record_id.as_str()
        || value["outer_request_id"] != prelaunch.outer_request_id
    {
        return Err(ArenaError::Invalid(
            "custody failure differs from reservation or outer request".into(),
        ));
    }
    match (terminal_state, launch) {
        (ArenaState::ExpiredUnlaunched, None)
            if value["outcome"] == "expired_unlaunched" && value["claim_id"].is_null() =>
        {
            Ok(())
        }
        (ArenaState::FailedIndeterminate, Some(launch))
            if value["outcome"] == "indeterminate_write_refusal"
                && value["claim_id"] == launch.as_str() =>
        {
            Ok(())
        }
        _ => Err(ArenaError::Invalid(
            "custody failure outcome or claim differs from terminal state".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::symlink;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    use serde_json::{Map, json};
    use tempfile::tempdir;

    use super::*;

    const ABRUPT_FINAL_SEAL_DATABASE: &str = "NQ_STORE_ABRUPT_FINAL_SEAL_DATABASE";
    const ABRUPT_FINAL_SEAL_MODE: &str = "NQ_STORE_ABRUPT_FINAL_SEAL_MODE";

    fn digest(label: &[u8]) -> Sha256Digest {
        sha256_bytes(label)
    }

    fn prelaunch(label: &str) -> ArenaPrelaunchBinding {
        ArenaPrelaunchBinding {
            reservation_record_id: digest(format!("reservation:{label}").as_bytes()),
            reservation_manifest_digest: digest(format!("reservation-manifest:{label}").as_bytes()),
            outer_request_record_id: digest(format!("outer-request-record:{label}").as_bytes()),
            outer_request_id: format!("outer-request:{label}"),
            outer_request_digest: digest(format!("outer-request:{label}").as_bytes()),
            dependency_generation_id: digest(b"dependency-generation"),
            dependency_generation_custody_digest: digest(b"dependency-generation-custody"),
            trust_anchor_id: digest(b"trust-anchor"),
            prelaunch_checkpoint_id: digest(format!("checkpoint:{label}").as_bytes()),
            prelaunch_checkpoint_digest: digest(format!("checkpoint-bytes:{label}").as_bytes()),
        }
    }

    #[test]
    fn maximal_bounded_terminal_header_fits_reserved_superblock_region() {
        const MAX_I_JSON_INTEGER: u64 = 9_007_199_254_740_991;
        let maximum_timestamp = format!(
            "2026-07-29T12:00:00.{}Z",
            "1".repeat(MAX_HEADER_TIMESTAMP_BYTES - 21)
        );
        assert_eq!(maximum_timestamp.len(), MAX_HEADER_TIMESTAMP_BYTES);
        validate_header_timestamp(&maximum_timestamp, "maximum fixture")
            .expect("maximum bounded timestamp");

        let section = |kind| SealedSection {
            kind,
            payload_length: MAX_I_JSON_INTEGER,
            payload_digest: digest(format!("max-section:{kind:?}").as_bytes()),
        };
        let header = ArenaHeader {
            schema: ARENA_FORMAT.to_owned(),
            sequence: MAX_I_JSON_INTEGER,
            prelaunch: ArenaPrelaunchBinding {
                reservation_record_id: digest(b"max-reservation"),
                reservation_manifest_digest: digest(b"max-manifest"),
                outer_request_record_id: digest(b"max-outer-record"),
                outer_request_id: "x".repeat(255),
                outer_request_digest: digest(b"max-outer-bytes"),
                dependency_generation_id: digest(b"max-dependency"),
                dependency_generation_custody_digest: digest(b"max-dependency-bytes"),
                trust_anchor_id: digest(b"max-trust-anchor"),
                prelaunch_checkpoint_id: digest(b"max-checkpoint"),
                prelaunch_checkpoint_digest: digest(b"max-checkpoint-bytes"),
            },
            execution_launch_record_id: Some(digest(b"max-launch")),
            layout: ArenaLayout::new(
                MAX_I_JSON_INTEGER / 8,
                MAX_I_JSON_INTEGER / 8,
                MAX_I_JSON_INTEGER / 8,
                MAX_I_JSON_INTEGER / 8,
            )
            .expect("maximum-shape layout"),
            state: ArenaState::FinalV2ProjectionRefused,
            claimed_at: Some(maximum_timestamp.clone()),
            derivation_claim: Some(DerivationClaim {
                derivation_id: digest(b"max-derivation"),
                dependency_generation_id: digest(b"max-dependency"),
                dependency_generation_custody_digest: digest(b"max-dependency-bytes"),
                trust_anchor_id: digest(b"max-trust-anchor"),
                evaluation_id: None,
                evaluation_id_digest: Some(sha256_bytes(
                    "\"".repeat(MAX_HEADER_EVALUATION_ID_BYTES).as_bytes(),
                )),
                profile_semantic_id: digest(b"max-profile"),
                evaluator_semantic_digest: Some(digest(b"max-evaluator-semantic")),
                evaluator_artifact_digest: digest(b"max-evaluator-artifact"),
                derived_at: maximum_timestamp,
                clock_identity: digest(b"max-clock"),
                clock_uncertainty_ms: Some(MAX_I_JSON_INTEGER),
                clock_qualification_digest: Some(digest(b"max-clock-qualification")),
            }),
            dependency_closure: Some(section(SectionKind::DependencyClosure)),
            raw_evidence: Some(section(SectionKind::RawEvidence)),
            final_v2_closure: Some(section(SectionKind::FinalV2Closure)),
            protected_failure: Some(section(SectionKind::ProtectedFailure)),
        };
        validate_header_request_id(&header.prelaunch.outer_request_id)
            .expect("maximum request identity");
        validate_derivation_header_text(
            header
                .derivation_claim
                .as_ref()
                .expect("maximum derivation"),
        )
        .expect("maximum derivation text");
        let payload = canonical_json_bytes(&header).expect("maximum canonical header");
        assert!(
            payload.len() > 3072,
            "fixture must exercise the retired narrow cap"
        );
        assert!(
            payload.len() <= MAX_SUPERBLOCK_JSON_BYTES,
            "maximal bounded header {} exceeds reserved region {}",
            payload.len(),
            MAX_SUPERBLOCK_JSON_BYTES
        );
        let encoded = encode_superblock(&header).expect("maximum header encodes");
        assert_eq!(
            decode_superblock(&encoded).expect("maximum header decodes"),
            header
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum NativeAcquisitionOutcome {
        Response,
        Timeout,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProviderInterpretation {
        Unavailable,
        CandidateReport,
    }

    fn acquisition(
        launch: &Sha256Digest,
        native_outcome: NativeAcquisitionOutcome,
        interpretation: ProviderInterpretation,
        response: Option<&[u8]>,
        native_stdout: Option<&[u8]>,
        native_stderr: Option<&[u8]>,
    ) -> AcquisitionCarrier {
        let provider_intake = canonical_json_bytes(&json!({
            "schema": "nq.test_provider_intake.v1",
            "native_outcome": format!("{native_outcome:?}"),
            "interpretation": format!("{interpretation:?}"),
        }))
        .expect("provider intake");
        let raw = response
            .or(native_stdout)
            .or(native_stderr)
            .unwrap_or_default()
            .to_vec();
        AcquisitionCarrier {
            execution_launch_record_id: launch.clone(),
            provider_intake_record_id: sha256_bytes(&provider_intake),
            exact_provider_intake_bytes: provider_intake,
            exact_raw_provider_bytes: raw,
        }
    }

    fn derivation_claim() -> DerivationClaim {
        let clock_qualification = json!({
            "state": "unqualified",
            "code": "fixture_clock_unqualified",
            "detail": "the fixture establishes no finite UTC-error bound",
        });
        DerivationClaim {
            derivation_id: digest(b"derivation"),
            dependency_generation_id: digest(b"dependency-generation"),
            dependency_generation_custody_digest: digest(b"dependency-generation-custody"),
            trust_anchor_id: digest(b"trust-anchor"),
            evaluation_id: Some("evaluation-001".into()),
            evaluation_id_digest: None,
            profile_semantic_id: digest(b"profile"),
            evaluator_semantic_digest: Some(digest(b"evaluator-semantic")),
            evaluator_artifact_digest: digest(b"evaluator-artifact"),
            derived_at: "2026-07-29T12:00:01Z".into(),
            clock_identity: digest(b"clock"),
            clock_uncertainty_ms: None,
            clock_qualification_digest: Some(
                nq_protocol::semantic_digest(&clock_qualification)
                    .expect("clock qualification identity"),
            ),
        }
    }

    fn semantic_document(
        schema: &str,
        identity_field: &str,
        mut preimage: Map<String, Value>,
    ) -> Vec<u8> {
        preimage.insert("schema".into(), Value::String(schema.into()));
        let identity = nq_protocol::semantic_digest(&preimage).expect("semantic identity");
        preimage.insert(
            identity_field.into(),
            Value::String(identity.as_str().to_owned()),
        );
        canonical_json_bytes(&preimage).expect("canonical semantic document")
    }

    fn final_v2(prelaunch: &ArenaPrelaunchBinding, claim: &DerivationClaim) -> Vec<u8> {
        let mut diagnostic = Map::new();
        diagnostic.insert(
            "completed_at".into(),
            Value::String("2026-07-29T12:00:02Z".into()),
        );
        diagnostic.insert(
            "evaluator".into(),
            json!({
                "digest": claim
                    .evaluator_semantic_digest
                    .as_ref()
                    .expect("new fixture has evaluator semantic identity"),
                "id": "evaluator",
                "version": "1"
            }),
        );
        diagnostic.insert(
            "execution_clock".into(),
            json!({"digest": claim.clock_identity, "id": "clock", "version": "1"}),
        );
        diagnostic.insert(
            "profile_semantic_id".into(),
            Value::String(claim.profile_semantic_id.as_str().to_owned()),
        );
        diagnostic.insert(
            "attempt_interval".into(),
            json!({
                "qualification": {
                    "state": "unqualified",
                    "code": "fixture_clock_unqualified",
                    "detail": "the fixture establishes no finite UTC-error bound",
                },
            }),
        );
        diagnostic.insert(
            "request_id".into(),
            Value::String(prelaunch.outer_request_id.clone()),
        );
        let diagnostic: Value = serde_json::from_slice(&semantic_document(
            "nq.diagnostic_execution.v2",
            "artifact_id",
            diagnostic,
        ))
        .expect("diagnostic");
        let mut closure = Map::new();
        closure.insert("diagnostic".into(), diagnostic);
        closure.insert(
            "execution_binding".into(),
            json!({"record_id": digest(b"binding")}),
        );
        closure.insert("runtime_records".into(), Value::Array(Vec::new()));
        closure.insert(
            "dependency_generation".into(),
            json!({"generation_id": digest(b"dependencies")}),
        );
        semantic_document(
            "nq.governed_execution_custody_closure.v2",
            "closure_id",
            closure,
        )
    }

    fn failure(
        prelaunch: &ArenaPrelaunchBinding,
        launch: Option<&Sha256Digest>,
        outcome: &str,
    ) -> ArenaFailureCarrierCandidate {
        let mut preimage = Map::new();
        preimage.insert(
            "claim_id".into(),
            launch.map_or(Value::Null, |digest| {
                Value::String(digest.as_str().to_owned())
            }),
        );
        preimage.insert(
            "failed_at".into(),
            Value::String("2026-07-29T12:00:03Z".into()),
        );
        preimage.insert("outcome".into(), Value::String(outcome.into()));
        preimage.insert(
            "outer_request_id".into(),
            Value::String(prelaunch.outer_request_id.clone()),
        );
        preimage.insert(
            "reservation_id".into(),
            Value::String(prelaunch.reservation_record_id.as_str().to_owned()),
        );
        ArenaFailureCarrierCandidate::parse_precursor(semantic_document(
            "nq.governed_custody_failure.v1",
            "failure_id",
            preimage,
        ))
        .expect("failure carrier")
    }

    fn create_arena(database: &Path, label: &str) -> (ArenaPrelaunchBinding, CustodyArena) {
        let prelaunch = prelaunch(label);
        let arena = CustodyArena::create(
            database,
            prelaunch.clone(),
            ArenaLayout::new(65_536, 65_536, 65_536, 16_384).expect("layout"),
            b"dependency-generation-custody",
        )
        .expect("create");
        (prelaunch, arena)
    }

    fn derivation_ready_arena(
        database: &Path,
        label: &str,
    ) -> (ArenaPrelaunchBinding, CustodyArena, Vec<u8>) {
        let (prelaunch, mut arena) = create_arena(database, label);
        let launch = digest(format!("{label}:launch").as_bytes());
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        let raw = arena
            .seal_acquisition(acquisition(
                &launch,
                NativeAcquisitionOutcome::Response,
                ProviderInterpretation::CandidateReport,
                Some(b"exact final-seal-intent raw bytes"),
                None,
                None,
            ))
            .expect("raw");
        let claim = derivation_claim();
        let token = arena
            .claim_derivation(raw, claim.clone())
            .expect("derivation");
        // Reopen through the public arena capability so the fixture matches
        // the production final-seal path.
        drop(token);
        let final_bytes = final_v2(&prelaunch, &claim);
        (prelaunch, arena, final_bytes)
    }

    #[test]
    fn arena_seals_raw_then_final_and_reopens_exact_bytes() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "complete");
        let layout = arena.inspection().expect("inspection").layout;
        let reservation_id = prelaunch.reservation_record_id.clone();
        let launch_id = digest(b"arena-launch");
        assert_eq!(
            arena.inspection().expect("inspection").state,
            ArenaState::Reserved
        );
        arena
            .claim(launch_id.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        let carrier = acquisition(
            &launch_id,
            NativeAcquisitionOutcome::Response,
            ProviderInterpretation::CandidateReport,
            Some(b"exact raw provider bytes"),
            None,
            Some(b"bounded stderr"),
        );
        let raw_token = arena.seal_acquisition(carrier.clone()).expect("raw seal");
        assert_eq!(raw_token.carrier(), &carrier);
        let claim = derivation_claim();
        let derivation_token = arena
            .claim_derivation(raw_token, claim.clone())
            .expect("derivation claim");
        assert_eq!(derivation_token.reopened_carrier(), &carrier);
        let final_bytes = final_v2(&prelaunch, &claim);
        let final_token = arena
            .seal_final_v2_closure(
                DerivedV2ClosureCandidate::from_store_internal_precursor(
                    derivation_token,
                    final_bytes.clone(),
                )
                .expect("derived closure"),
            )
            .expect("final seal");
        assert_eq!(final_token.reservation_id, reservation_id);
        assert_eq!(
            final_token.section.payload_digest(),
            &sha256_bytes(&final_bytes)
        );
        arena.mark_indexed(final_token).expect("index mark");
        assert_eq!(
            arena.inspection().expect("inspection").state,
            ArenaState::FinalV2SealedIndexed
        );
        assert_eq!(
            arena.relative_path_from(&database).expect("relative path"),
            CustodyArena::relative_path(&reservation_id)
        );
        drop(arena);

        let reopened = CustodyArena::open(&database, &prelaunch).expect("reopen");
        assert_eq!(
            reopened.inspection().expect("inspection").reservation_id,
            reservation_id
        );
        assert_eq!(
            reopened
                .inspection()
                .expect("inspection")
                .execution_launch_record_id,
            Some(launch_id)
        );
        assert_eq!(reopened.inspection().expect("inspection").layout, layout);
        let raw = reopened
            .raw_evidence_bytes()
            .expect("raw read")
            .expect("raw bytes");
        assert_eq!(AcquisitionCarrier::decode(&raw).expect("carrier"), carrier);
        assert_eq!(
            reopened.final_v2_closure_bytes().expect("final read"),
            Some(final_bytes)
        );
    }

    #[test]
    fn durable_final_seal_intent_promotes_only_exact_staged_bytes() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("intent-exact.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena, final_bytes) = derivation_ready_arena(&database, "intent-exact");
        let derivation = arena.reopen_derivation_token().expect("reopen derivation");
        arena.failpoint = Some(ArenaFailpoint::SectionAfterSync);
        assert!(matches!(
            arena.seal_final_v2_closure(
                DerivedV2ClosureCandidate::from_store_internal_precursor(
                    derivation,
                    final_bytes.clone(),
                )
                .expect("candidate"),
            ),
            Err(ArenaError::Invalid(message)) if message.contains("injected indeterminate")
        ));
        drop(arena);

        let mut reopened =
            CustodyArena::open(&database, &prelaunch).expect("intent is inspectable");
        assert_eq!(
            reopened.inspection().expect("inspection").state,
            ArenaState::FinalV2SealIntent
        );
        assert_eq!(
            reopened
                .adjudicate_final_v2_seal_intent()
                .expect("exact intent adjudication"),
            FinalSealIntentDisposition::Promoted
        );
        assert_eq!(
            reopened.inspection().expect("inspection").state,
            ArenaState::FinalV2SealedIndexPending
        );
        assert_eq!(
            reopened.final_v2_closure_bytes().expect("final bytes"),
            Some(final_bytes)
        );
    }

    #[test]
    fn durable_final_seal_intent_terminalizes_absence_and_substitution() {
        let directory = tempdir().expect("directory");

        let absent_database = directory.path().join("intent-absent.db");
        File::create(&absent_database).expect("database placeholder");
        let (absent_prelaunch, mut absent, absent_final) =
            derivation_ready_arena(&absent_database, "intent-absent");
        let absent_derivation = absent.reopen_derivation_token().expect("reopen derivation");
        absent.failpoint = Some(ArenaFailpoint::FinalSealAfterIntent);
        assert!(
            absent
                .seal_final_v2_closure(
                    DerivedV2ClosureCandidate::from_store_internal_precursor(
                        absent_derivation,
                        absent_final,
                    )
                    .expect("candidate"),
                )
                .is_err()
        );
        drop(absent);
        let mut absent =
            CustodyArena::open(&absent_database, &absent_prelaunch).expect("inspect absence");
        assert_eq!(
            absent
                .adjudicate_final_v2_seal_intent()
                .expect("adjudicate absence"),
            FinalSealIntentDisposition::CommittedUnavailable
        );
        assert_eq!(
            absent.inspection().expect("inspection").state,
            ArenaState::FinalV2SealCommittedUnavailable
        );

        let corrupt_database = directory.path().join("intent-corrupt.db");
        File::create(&corrupt_database).expect("database placeholder");
        let (corrupt_prelaunch, mut corrupt, corrupt_final) =
            derivation_ready_arena(&corrupt_database, "intent-corrupt");
        let corrupt_derivation = corrupt
            .reopen_derivation_token()
            .expect("reopen derivation");
        corrupt.failpoint = Some(ArenaFailpoint::FinalSealAfterIntent);
        assert!(
            corrupt
                .seal_final_v2_closure(
                    DerivedV2ClosureCandidate::from_store_internal_precursor(
                        corrupt_derivation,
                        corrupt_final,
                    )
                    .expect("candidate"),
                )
                .is_err()
        );
        let (header_offset, payload_offset, _) =
            corrupt.header.layout.section(SectionKind::FinalV2Closure);
        let path = corrupt.path().to_owned();
        drop(corrupt);
        let substitute = b"coherent but different final bytes";
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("corruptor");
        write_all_at(&file, payload_offset, substitute).expect("substitute payload");
        let frame = encode_section_header(
            SectionKind::FinalV2Closure,
            u64::try_from(substitute.len()).expect("length"),
            &sha256_bytes(substitute),
        )
        .expect("substitute frame");
        write_all_at(&file, header_offset, &frame).expect("substitute frame write");
        file.sync_all().expect("sync substitution");
        drop(file);

        let mut corrupt =
            CustodyArena::open(&corrupt_database, &corrupt_prelaunch).expect("inspect corruption");
        assert_eq!(
            corrupt
                .adjudicate_final_v2_seal_intent()
                .expect("adjudicate corruption"),
            FinalSealIntentDisposition::Corrupt
        );
        assert_eq!(
            corrupt.inspection().expect("inspection").state,
            ArenaState::FinalV2SealCorrupt
        );
    }

    // Ordinary no-op test unless selected by the parent crash harness below.
    // The parent requires SIGKILL termination; a normal return cannot satisfy
    // the hostile.
    #[test]
    fn abrupt_final_seal_child() {
        let Ok(database) = std::env::var(ABRUPT_FINAL_SEAL_DATABASE) else {
            return;
        };
        let mode = std::env::var(ABRUPT_FINAL_SEAL_MODE).expect("crash mode");
        let database = PathBuf::from(database);
        File::create(&database).expect("database placeholder");
        let (_prelaunch, mut arena, final_bytes) = derivation_ready_arena(&database, mode.as_str());
        let derivation = arena.reopen_derivation_token().expect("reopen derivation");
        arena.failpoint = Some(match mode.as_str() {
            "intent-only" => ArenaFailpoint::FinalSealAfterIntentSigkill,
            "exact-frame" => ArenaFailpoint::SectionAfterSyncSigkill,
            other => panic!("unknown abrupt final-seal mode {other}"),
        });
        let _ = arena.seal_final_v2_closure(
            DerivedV2ClosureCandidate::from_store_internal_precursor(derivation, final_bytes)
                .expect("candidate"),
        );
        panic!("abrupt final-seal child returned without SIGKILL");
    }

    #[test]
    fn sigkill_final_seal_windows_recover_without_treating_intent_as_scratch() {
        let directory = tempdir().expect("directory");
        for (mode, expected) in [
            (
                "intent-only",
                FinalSealIntentDisposition::CommittedUnavailable,
            ),
            ("exact-frame", FinalSealIntentDisposition::Promoted),
        ] {
            let database = directory.path().join(format!("{mode}.db"));
            let status = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("custody_arena::tests::abrupt_final_seal_child")
                .arg("--nocapture")
                .env(ABRUPT_FINAL_SEAL_DATABASE, &database)
                .env(ABRUPT_FINAL_SEAL_MODE, mode)
                .status()
                .expect("spawn abrupt final-seal child");
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "{mode} child must terminate by SIGKILL, not skip or return"
            );

            let expected_prelaunch = prelaunch(mode);
            let mut reopened =
                CustodyArena::open(&database, &expected_prelaunch).expect("intent inspectable");
            assert_eq!(
                reopened.inspection().expect("inspection").state,
                ArenaState::FinalV2SealIntent
            );
            assert_eq!(
                reopened
                    .adjudicate_final_v2_seal_intent()
                    .expect("adjudicate killed seal"),
                expected
            );
            assert_eq!(
                reopened.inspection().expect("inspection").state,
                match expected {
                    FinalSealIntentDisposition::Promoted => {
                        ArenaState::FinalV2SealedIndexPending
                    }
                    FinalSealIntentDisposition::CommittedUnavailable => {
                        ArenaState::FinalV2SealCommittedUnavailable
                    }
                    FinalSealIntentDisposition::Corrupt => unreachable!("not requested"),
                }
            );
        }
    }

    #[test]
    fn one_torn_superblock_recovers_and_two_are_refused() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, arena) = create_arena(&database, "torn");
        let reservation_id = prelaunch.reservation_record_id.clone();
        let path = arena.path().to_owned();
        drop(arena);

        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("corruptor");
        file.seek(SeekFrom::Start(0)).expect("seek");
        file.write_all(b"TORN").expect("corrupt first");
        file.sync_all().expect("sync first corruption");
        drop(file);
        let reopened = CustodyArena::open(&database, &prelaunch).expect("one-copy recovery");
        assert!(
            reopened
                .inspection()
                .expect("inspection")
                .recovered_torn_superblock
        );
        assert_eq!(
            reopened.inspection().expect("inspection").reservation_id,
            reservation_id
        );
        drop(reopened);

        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("second corruptor");
        file.seek(SeekFrom::Start(SUPERBLOCK_SIZE))
            .expect("seek second");
        file.write_all(b"TORN").expect("corrupt second");
        file.sync_all().expect("sync second corruption");
        drop(file);
        assert!(matches!(
            CustodyArena::open(&database, &prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("both arena superblocks")
        ));
    }

    #[test]
    fn section_frame_detects_torn_or_substituted_payload() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "section");
        let launch = digest(b"section-launch");
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        arena
            .seal_acquisition(acquisition(
                &launch,
                NativeAcquisitionOutcome::Response,
                ProviderInterpretation::CandidateReport,
                Some(b"exact raw evidence"),
                None,
                None,
            ))
            .expect("raw");
        let payload_offset = arena.header.layout.raw_payload_offset;
        let path = arena.path().to_owned();
        drop(arena);

        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("corruptor");
        file.write_at(b"X", payload_offset)
            .expect("substitute byte");
        file.sync_all().expect("sync substitution");
        drop(file);
        assert!(matches!(
            CustodyArena::open(&database, &prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("payload digest")
        ));
    }

    #[test]
    fn unreferenced_frame_after_crash_is_scratch_not_state_advancement() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "scratch");
        let launch = digest(b"scratch-launch");
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        arena
            .seal_acquisition(acquisition(
                &launch,
                NativeAcquisitionOutcome::Timeout,
                ProviderInterpretation::Unavailable,
                None,
                Some(b"partial stdout"),
                Some(b"timeout"),
            ))
            .expect("raw");
        let (header_offset, payload_offset, _) =
            arena.header.layout.section(SectionKind::FinalV2Closure);
        let path = arena.path().to_owned();
        let scratch = b"torn final scratch";
        write_all_at(&arena.file, payload_offset, scratch).expect("scratch payload");
        let frame = encode_section_header(
            SectionKind::FinalV2Closure,
            scratch.len() as u64,
            &sha256_bytes(scratch),
        )
        .expect("scratch frame");
        write_all_at(&arena.file, header_offset, &frame).expect("scratch frame write");
        arena.file.sync_all().expect("scratch sync");
        drop(arena);

        let reopened = CustodyArena::open(&database, &prelaunch).expect("reopen prior state");
        assert_eq!(
            reopened.inspection().expect("inspection").state,
            ArenaState::RawEvidenceSealed
        );
        assert_eq!(reopened.final_v2_closure_bytes().expect("final read"), None);
        assert_eq!(reopened.path(), path);
    }

    #[test]
    fn shorter_retry_clears_a_longer_uncommitted_section_tail() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "retry-tail");
        let launch = digest(b"retry-tail-launch");
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");

        let (header_offset, payload_offset, capacity) =
            arena.header.layout.section(SectionKind::RawEvidence);
        let scratch = vec![0xA5; 32_768];
        assert!(u64::try_from(scratch.len()).expect("scratch length") < capacity);
        write_all_at(&arena.file, payload_offset, &scratch).expect("scratch payload");
        let frame = encode_section_header(
            SectionKind::RawEvidence,
            scratch.len() as u64,
            &sha256_bytes(&scratch),
        )
        .expect("scratch frame");
        write_all_at(&arena.file, header_offset, &frame).expect("scratch frame write");
        arena.file.sync_all().expect("scratch sync");

        let carrier = acquisition(
            &launch,
            NativeAcquisitionOutcome::Timeout,
            ProviderInterpretation::Unavailable,
            None,
            None,
            Some(b"short retry"),
        );
        let committed_length = carrier.encode().expect("carrier bytes").len();
        assert!(committed_length < scratch.len());
        arena
            .seal_acquisition(carrier)
            .expect("shorter legal retry");

        let tail_length = scratch.len() - committed_length;
        let mut tail = vec![0xFF; tail_length];
        read_exact_at(
            &arena.file,
            payload_offset + u64::try_from(committed_length).expect("committed length"),
            &mut tail,
        )
        .expect("read cleared tail");
        assert!(
            tail.iter().all(|byte| *byte == 0),
            "uncommitted bytes from the longer attempt survived the retry"
        );

        drop(arena);
        let reopened = CustodyArena::open(&database, &prelaunch).expect("reopen");
        assert_eq!(
            reopened.inspection().expect("inspection").state,
            ArenaState::RawEvidenceSealed
        );
    }

    #[test]
    fn indeterminate_superblock_write_poison_requires_reopen() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "superblock-poison");
        let launch = digest(b"superblock-poison-launch");
        arena.failpoint = Some(ArenaFailpoint::SuperblockAfterSync);

        assert!(matches!(
            arena.claim(launch.clone(), "2026-07-29T12:00:00Z".into()),
            Err(ArenaError::Invalid(message)) if message.contains("injected indeterminate")
        ));
        assert!(matches!(
            arena.inspection(),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        assert!(matches!(
            arena.claim(launch.clone(), "2026-07-29T12:00:00Z".into()),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        assert!(matches!(
            arena.raw_evidence_bytes(),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        drop(arena);

        // The successor header was durable before the injected uncertainty.
        // Reopen, not same-handle retry, adjudicates it as the one claim.
        let reopened = CustodyArena::open(&database, &prelaunch).expect("reopen adjudication");
        let inspection = reopened.inspection().expect("inspection");
        assert_eq!(inspection.state, ArenaState::Claimed);
        assert_eq!(inspection.execution_launch_record_id, Some(launch));
    }

    #[test]
    fn indeterminate_section_write_poison_requires_reopen() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "section-poison");
        let launch = digest(b"section-poison-launch");
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        arena.failpoint = Some(ArenaFailpoint::SectionAfterSync);

        assert!(matches!(
            arena.seal_acquisition(acquisition(
                &launch,
                NativeAcquisitionOutcome::Timeout,
                ProviderInterpretation::Unavailable,
                None,
                None,
                Some(b"first attempt"),
            )),
            Err(ArenaError::Invalid(message)) if message.contains("injected indeterminate")
        ));
        assert!(matches!(
            arena.inspection(),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        assert!(matches!(
            arena.seal_acquisition(acquisition(
                &launch,
                NativeAcquisitionOutcome::Timeout,
                ProviderInterpretation::Unavailable,
                None,
                None,
                Some(b"same-handle retry"),
            )),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        drop(arena);

        // No successor header was written, so the frame is scratch. A fresh
        // handle may clear it and perform the one legal seal.
        let mut reopened = CustodyArena::open(&database, &prelaunch).expect("reopen adjudication");
        assert_eq!(
            reopened.inspection().expect("inspection").state,
            ArenaState::Claimed
        );
        reopened
            .seal_acquisition(acquisition(
                &launch,
                NativeAcquisitionOutcome::Timeout,
                ProviderInterpretation::Unavailable,
                None,
                None,
                Some(b"after reopen"),
            ))
            .expect("seal after adjudication");
    }

    #[test]
    fn superblock_split_brain_and_sequence_gap_are_refused() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");

        let (split_prelaunch, split) = create_arena(&database, "split");
        let mut split_header = split.header.clone();
        split_header.claimed_at = Some("2026-07-29T12:00:00Z".into());
        write_superblock(&split.file, 0, &split_header).expect("split header");
        split.file.sync_all().expect("split sync");
        drop(split);
        assert!(matches!(
            CustodyArena::open(&database, &split_prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("split-brain")
        ));

        let second_database = directory.path().join("nq-two.db");
        File::create(&second_database).expect("second database placeholder");
        let (gap_prelaunch, gap) = create_arena(&second_database, "gap");
        let mut gap_header = gap.header.clone();
        gap_header.sequence += 2;
        write_superblock(&gap.file, 0, &gap_header).expect("gap header");
        gap.file.sync_all().expect("gap sync");
        drop(gap);
        assert!(matches!(
            CustodyArena::open(&second_database, &gap_prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("legal successor")
        ));
    }

    #[test]
    fn layout_is_block_separated_and_noncanonical_overlap_is_refused() {
        let layout = ArenaLayout::new(3073, 4097, 8193, 2049).expect("layout");
        for offset in [
            layout.dependency_header_offset,
            layout.dependency_payload_offset,
            layout.raw_header_offset,
            layout.raw_payload_offset,
            layout.final_header_offset,
            layout.final_payload_offset,
            layout.failure_header_offset,
            layout.failure_payload_offset,
            layout.file_length,
        ] {
            assert_eq!(offset % SUPERBLOCK_SIZE, 0);
        }
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, arena) = create_arena(&database, "overlap");
        let mut bad = arena.header.clone();
        bad.layout.final_header_offset = bad.layout.raw_payload_offset;
        write_superblock(&arena.file, 0, &bad).expect("bad first");
        write_superblock(&arena.file, 1, &bad).expect("bad second");
        arena.file.sync_all().expect("bad sync");
        drop(arena);
        assert!(matches!(
            CustodyArena::open(&database, &prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("canonical partition layout")
        ));
    }

    #[test]
    fn capacity_model_preserves_frozen_arena_geometry_for_every_alignment_residue() {
        fn frozen_align(value: u64) -> u64 {
            (value + SUPERBLOCK_SIZE - 1) & !(SUPERBLOCK_SIZE - 1)
        }

        fn frozen_offsets(capacities: [u64; 4]) -> [u64; 9] {
            let dependency_header = 2 * SUPERBLOCK_SIZE;
            let dependency_payload = dependency_header + SECTION_HEADER_SIZE;
            let raw_header = frozen_align(dependency_payload + capacities[0]);
            let raw_payload = raw_header + SECTION_HEADER_SIZE;
            let final_header = frozen_align(raw_payload + capacities[1]);
            let final_payload = final_header + SECTION_HEADER_SIZE;
            let failure_header = frozen_align(final_payload + capacities[2]);
            let failure_payload = failure_header + SECTION_HEADER_SIZE;
            let file_length = frozen_align(failure_payload + capacities[3]);
            [
                dependency_header,
                dependency_payload,
                raw_header,
                raw_payload,
                final_header,
                final_payload,
                failure_header,
                failure_payload,
                file_length,
            ]
        }

        for varied_partition in 0..4 {
            for residue in 0..SUPERBLOCK_SIZE {
                let mut capacities = [SUPERBLOCK_SIZE; 4];
                capacities[varied_partition] = if residue == 0 {
                    SUPERBLOCK_SIZE
                } else {
                    residue
                };
                let expected = frozen_offsets(capacities);
                let actual =
                    ArenaLayout::new(capacities[0], capacities[1], capacities[2], capacities[3])
                        .expect("all nonzero alignment residues fit");
                assert_eq!(
                    [
                        actual.dependency_header_offset,
                        actual.dependency_payload_offset,
                        actual.raw_header_offset,
                        actual.raw_payload_offset,
                        actual.final_header_offset,
                        actual.final_payload_offset,
                        actual.failure_header_offset,
                        actual.failure_payload_offset,
                        actual.file_length,
                    ],
                    expected,
                    "partition {varied_partition}, residue {residue}"
                );
            }
        }
    }

    #[test]
    fn capacity_model_preserves_zero_and_closes_unsafe_integer_boundaries() {
        assert!(matches!(
            ArenaLayout::new(0, 1, 1, 1),
            Err(ArenaError::Invalid(message))
                if message == "all governed arena partitions must be nonzero"
        ));
        for capacities in [
            [u64::MAX, 1, 1, 1],
            [1, u64::MAX, 1, 1],
            [1, 1, u64::MAX, 1],
            [1, 1, 1, u64::MAX],
            [u64::MAX - 12_288, 1, 1, 1],
        ] {
            assert!(matches!(
                ArenaLayout::new(
                    capacities[0],
                    capacities[1],
                    capacities[2],
                    capacities[3]
                ),
                Err(ArenaError::Invalid(message))
                    if message == "arena capacity exceeds exact-I-JSON integer domain"
            ));
        }
    }

    #[test]
    fn opaque_no_response_intake_and_empty_raw_capture_are_durable() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "no-response");
        let launch = digest(b"no-response-launch");
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        let carrier = acquisition(
            &launch,
            NativeAcquisitionOutcome::Timeout,
            ProviderInterpretation::Unavailable,
            None,
            None,
            Some(b"deadline exceeded"),
        );
        arena
            .seal_acquisition(carrier.clone())
            .expect("no-response carrier");
        drop(arena);
        let reopened = CustodyArena::open(&database, &prelaunch).expect("reopen");
        let bytes = reopened
            .raw_evidence_bytes()
            .expect("raw read")
            .expect("opaque no-response bytes");
        assert_eq!(AcquisitionCarrier::decode(&bytes).expect("decode"), carrier);
    }

    #[test]
    fn acquisition_custody_requires_intake_bytes_but_assigns_no_semantics() {
        let launch = digest(b"substitution-launch");
        let valid = acquisition(
            &launch,
            NativeAcquisitionOutcome::Response,
            ProviderInterpretation::CandidateReport,
            Some(b"response"),
            None,
            None,
        );
        assert!(valid.validate().is_ok());

        let mut empty_intake = valid;
        empty_intake.exact_provider_intake_bytes.clear();
        assert!(matches!(
            empty_intake.encode(),
            Err(ArenaError::Invalid(message)) if message.contains("no provider-intake bytes")
        ));
    }

    #[test]
    fn acquisition_capacity_bound_matches_exact_encoder_at_decimal_boundaries() {
        let launch = digest(b"capacity-launch");
        let intake = digest(b"capacity-intake");
        for (provider_bytes, raw_bytes) in [
            (1_usize, 0_usize),
            (9, 10),
            (10, 99),
            (99, 100),
            (100, 1_000),
        ] {
            let carrier = AcquisitionCarrier {
                execution_launch_record_id: launch.clone(),
                provider_intake_record_id: intake.clone(),
                exact_provider_intake_bytes: vec![b'i'; provider_bytes],
                exact_raw_provider_bytes: vec![b'r'; raw_bytes],
            };
            let encoded = carrier.encode().expect("exact acquisition carrier");
            let bound = acquisition_carrier_capacity_bound(
                u64::try_from(provider_bytes).expect("provider bound"),
                u64::try_from(raw_bytes).expect("raw bound"),
            )
            .expect("capacity bound");
            assert_eq!(
                u64::try_from(encoded.len()).expect("encoded length"),
                bound,
                "bound must use the encoder's exact canonical header at ({provider_bytes}, {raw_bytes})"
            );
        }
    }

    #[test]
    fn acquisition_capacity_bound_is_the_exact_arena_acceptance_boundary() {
        let directory = tempdir().expect("directory");
        let launch = digest(b"capacity-boundary-launch");
        let intake = digest(b"capacity-boundary-intake");
        let carrier = AcquisitionCarrier {
            execution_launch_record_id: launch.clone(),
            provider_intake_record_id: intake,
            exact_provider_intake_bytes: vec![b'i'; 17],
            exact_raw_provider_bytes: vec![b'r'; 31],
        };
        let bound = acquisition_carrier_capacity_bound(17, 31).expect("capacity bound");

        let exact_database = directory.path().join("exact.db");
        File::create(&exact_database).expect("database placeholder");
        let mut exact_prelaunch = prelaunch("capacity-exact");
        exact_prelaunch.dependency_generation_custody_digest = sha256_bytes(b"dependency");
        let exact_layout =
            ArenaLayout::new(4_096, bound, 4_096, 4_096).expect("exact-bound layout");
        let mut exact = CustodyArena::create(
            &exact_database,
            exact_prelaunch,
            exact_layout,
            b"dependency",
        )
        .expect("exact-bound arena");
        exact
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        exact
            .seal_acquisition(carrier.clone())
            .expect("exact bound accepts exact carrier");

        let short_database = directory.path().join("short.db");
        File::create(&short_database).expect("database placeholder");
        let mut short_prelaunch = prelaunch("capacity-short");
        short_prelaunch.dependency_generation_custody_digest = sha256_bytes(b"dependency");
        let short_layout = ArenaLayout::new(4_096, bound - 1, 4_096, 4_096).expect("short layout");
        let mut short = CustodyArena::create(
            &short_database,
            short_prelaunch,
            short_layout,
            b"dependency",
        )
        .expect("short arena");
        short
            .claim(launch, "2026-07-29T12:00:00Z".into())
            .expect("claim");
        let Err(error) = short.seal_acquisition(carrier) else {
            panic!("one byte below the exact bound must refuse");
        };
        assert!(
            matches!(&error, ArenaError::Invalid(message)
                if message.contains("requires") && message.contains("capacity")),
            "unexpected short-capacity refusal: {error:?}"
        );
    }

    #[test]
    fn acquisition_capacity_bound_rejects_empty_intake_and_arithmetic_overflow() {
        assert!(matches!(
            acquisition_carrier_capacity_bound(0, 1),
            Err(ArenaError::Invalid(message)) if message.contains("must be positive")
        ));
        assert!(matches!(
            acquisition_carrier_capacity_bound(u64::MAX, 0),
            Err(ArenaError::Invalid(message)) if message.contains("overflowed")
        ));
        assert!(matches!(
            acquisition_carrier_capacity_bound(1, u64::MAX),
            Err(ArenaError::Invalid(message)) if message.contains("overflowed")
        ));
    }

    #[test]
    fn evaluation_and_terminal_transitions_are_one_use_and_source_typed() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, mut arena) = create_arena(&database, "terminal");
        let launch = digest(b"terminal-launch");
        arena
            .claim(launch.clone(), "2026-07-29T12:00:00Z".into())
            .expect("claim");
        assert!(matches!(
            arena.seal_failure(
                failure(&prelaunch, None, "expired_unlaunched"),
                ArenaState::ExpiredUnlaunched
            ),
            Err(ArenaError::Invalid(message)) if message.contains("incompatible")
        ));
        arena
            .seal_failure(
                failure(&prelaunch, Some(&launch), "indeterminate_write_refusal"),
                ArenaState::FailedIndeterminate,
            )
            .expect("claimed failure");
        assert!(matches!(
            arena.seal_failure(
                failure(&prelaunch, Some(&launch), "indeterminate_write_refusal"),
                ArenaState::FailedIndeterminate
            ),
            Err(ArenaError::Invalid(message)) if message.contains("incompatible")
        ));

        let second_database = directory.path().join("nq-two.db");
        File::create(&second_database).expect("second database placeholder");
        let (expired_prelaunch, mut expired) = create_arena(&second_database, "expired");
        expired
            .seal_failure(
                failure(&expired_prelaunch, None, "expired_unlaunched"),
                ArenaState::ExpiredUnlaunched,
            )
            .expect("unlaunched expiry");
        assert_eq!(
            expired.inspection().expect("inspection").state,
            ArenaState::ExpiredUnlaunched
        );
    }

    #[test]
    fn hole_punch_and_root_symlink_swap_are_refused() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, arena) = create_arena(&database, "hole");
        nix::fcntl::fallocate(
            arena.file.as_raw_fd(),
            nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE
                | nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE,
            i64::try_from(arena.header.layout.raw_payload_offset).expect("offset"),
            i64::try_from(SUPERBLOCK_SIZE).expect("length"),
        )
        .expect("local filesystem supports hole punching");
        arena.file.sync_all().expect("hole sync");
        drop(arena);
        assert!(matches!(
            CustodyArena::open(&database, &prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("sparse or deallocated")
        ));

        let second_database = directory.path().join("nq-two.db");
        File::create(&second_database).expect("second database placeholder");
        let (swap_prelaunch, swap) = create_arena(&second_database, "swap");
        let root = CustodyArena::root_for_database(&second_database).expect("root");
        let moved = directory.path().join("moved-root");
        drop(swap);
        fs::rename(&root, &moved).expect("move root");
        symlink(&moved, &root).expect("replace with symlink");
        assert!(matches!(
            CustodyArena::open(&second_database, &swap_prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("real directory")
        ));
    }

    #[test]
    fn exclusive_lifetime_lock_refuses_a_second_arena_handle() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database placeholder");
        let (prelaunch, first) = create_arena(&database, "exclusive-handle");

        assert!(matches!(
            CustodyArena::open(&database, &prelaunch),
            Err(ArenaError::Invalid(message)) if message.contains("exclusive lifetime lock")
        ));

        drop(first);
        let reopened =
            CustodyArena::open(&database, &prelaunch).expect("lock releases only on handle drop");
        assert_eq!(
            reopened.inspection().expect("inspection").state,
            ArenaState::Reserved
        );
    }
}
