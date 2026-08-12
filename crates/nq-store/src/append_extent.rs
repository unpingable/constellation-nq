//! Fixed C2 bootstrap (`B`) and global-refusal (`G`) append extents.
//!
//! The types in this module are evidence about fixed physical carriers.  They
//! do not grant writer standing, signer standing, capacity, or a Store writer
//! session.  In particular, a header is accepted only as one member of an
//! exact, non-recursively identified B/G pair.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

use nq_protocol::{
    CanonicalizationError, Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fixed C2 allocation/alignment page.
pub const C2_APPEND_ALIGNMENT_BYTES_V1: u64 = 4096;
/// Two superblocks and one header precede every payload.
pub const C2_APPEND_PAYLOAD_OFFSET_V1: u64 = 3 * C2_APPEND_ALIGNMENT_BYTES_V1;
/// Exact append-layout identifier.
pub const C2_APPEND_EXTENT_LAYOUT_ID_V1: &str = "nq.append_extent_layout.v1";
/// Cycle-free B/G pair identity domain.
pub const C2_CARRIER_PAIR_IDENTITY_DOMAIN_V1: &str = "nq.c2.carrier_pair.identity.v1";
/// Role-distinct header identity domain.
pub const C2_CARRIER_HEADER_IDENTITY_DOMAIN_V1: &str = "nq.c2.carrier_header.identity.v1";
/// Predecessor-bound append-frame identity domain.
pub const C2_APPEND_FRAME_IDENTITY_DOMAIN_V1: &str = "nq.c2.append_frame.identity.v1";
/// Largest exactly representable unsigned I-JSON integer.
const IJSON_SAFE_U64: u64 = 9_007_199_254_740_991;

/// Closed physical carrier roles.  A role cannot be supplied as free text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2AppendExtentRoleV1 {
    /// Reusable Store bootstrap and verification material.
    BootstrapB,
    /// Per-candidate, post-completion global refusals only.
    GlobalRefusalG,
}

/// Exact immutable geometry for the B/G pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2AppendExtentLayoutV1 {
    schema: &'static str,
    alignment_bytes: u64,
    superblock_zero_offset: u64,
    superblock_one_offset: u64,
    header_offset: u64,
    payload_offset: u64,
    b_payload_bound: u64,
    g_payload_bound: u64,
    b_append_extent_length: u64,
    b_aggregate_length_with_lock: u64,
    g_append_extent_length: u64,
    global_refusal_max_entries: u32,
    global_refusal_entry_max_bytes: u32,
}

impl C2AppendExtentLayoutV1 {
    /// Exact B append-file length, excluding the separate lock allocation.
    #[must_use]
    pub const fn b_append_extent_length(&self) -> u64 {
        self.b_append_extent_length
    }

    /// Historical aggregate `B = A + extent_length(b_payload_bound)`.
    #[must_use]
    pub const fn b_aggregate_length_with_lock(&self) -> u64 {
        self.b_aggregate_length_with_lock
    }

    /// Exact G append-file length.
    #[must_use]
    pub const fn g_append_extent_length(&self) -> u64 {
        self.g_append_extent_length
    }

    /// Exact payload bound for one role.
    #[must_use]
    pub const fn payload_bound(&self, role: C2AppendExtentRoleV1) -> u64 {
        match role {
            C2AppendExtentRoleV1::BootstrapB => self.b_payload_bound,
            C2AppendExtentRoleV1::GlobalRefusalG => self.g_payload_bound,
        }
    }

    /// Installed maximum number of G entries.
    #[must_use]
    pub const fn global_refusal_max_entries(&self) -> u32 {
        self.global_refusal_max_entries
    }

    /// Installed maximum canonical bytes for one G entry.
    #[must_use]
    pub const fn global_refusal_entry_max_bytes(&self) -> u32 {
        self.global_refusal_entry_max_bytes
    }
}

/// Immutable file facts admitted to the cycle-free pair preimage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2CarrierFileFactsV1 {
    /// Semantic identity of the exact file descriptor target.
    pub file_identity: Sha256Digest,
    /// Observed device number.
    pub device: u64,
    /// Observed inode number.
    pub inode: u64,
    /// Observed owner UID.
    pub owner_uid: u32,
    /// Observed owner GID.
    pub owner_gid: u32,
    /// Exact permission bits; C2 accepts `0600` only.
    pub mode: u32,
    /// Exact physical file length.
    pub physical_length: u64,
    /// Exact link count; C2 accepts one only.
    pub link_count: u64,
}

/// Inputs used to construct one nonrecursive carrier-pair identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2CarrierPairInputV1 {
    /// Exact Store occurrence.
    pub occurrence_id: String,
    /// Immutable physical Store generation.
    pub physical_store_generation_identity: Sha256Digest,
    /// Candidate-tree-pinned qualified backend profile.
    pub qualified_backend_profile_identity: Sha256Digest,
    /// B descriptor facts.
    pub b_file: C2CarrierFileFactsV1,
    /// G descriptor facts.
    pub g_file: C2CarrierFileFactsV1,
}

/// One role-distinct authenticated extent header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2CarrierHeaderV1 {
    schema: &'static str,
    schema_version: u8,
    header_identity: Sha256Digest,
    carrier_pair_identity: Sha256Digest,
    qualified_backend_profile_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    role: C2AppendExtentRoleV1,
    append_extent_layout: &'static str,
    payload_bound: u64,
    physical_length: u64,
    file: C2CarrierFileFactsV1,
}

impl C2CarrierHeaderV1 {
    #[must_use]
    pub(crate) const fn identity(&self) -> &Sha256Digest {
        &self.header_identity
    }
}

/// Exact correspondence between the common pair and both headers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2CarrierPairHeaderCorrespondenceV1 {
    carrier_pair_identity: Sha256Digest,
    pair: C2CarrierPairInputV1,
    b_header: C2CarrierHeaderV1,
    g_header: C2CarrierHeaderV1,
}

impl C2CarrierPairHeaderCorrespondenceV1 {
    /// Exact authenticated pair identity.
    #[must_use]
    pub const fn pair_identity(&self) -> &Sha256Digest {
        &self.carrier_pair_identity
    }

    /// Role-distinct B header.
    #[must_use]
    pub const fn b_header(&self) -> &C2CarrierHeaderV1 {
        &self.b_header
    }

    /// Role-distinct G header.
    #[must_use]
    pub const fn g_header(&self) -> &C2CarrierHeaderV1 {
        &self.g_header
    }
}

/// Closed frame families prevent B/G vocabulary cross-placement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2AppendFrameKindV1 {
    StoreGenerationBootstrap,
    KeyEnrollment,
    ActiveStorePolicy,
    InstallationIntent,
    InstallationReceipt,
    SignerTransition,
    GlobalRefusal,
}

impl C2AppendFrameKindV1 {
    pub(crate) const fn role(self) -> C2AppendExtentRoleV1 {
        match self {
            Self::GlobalRefusal => C2AppendExtentRoleV1::GlobalRefusalG,
            Self::StoreGenerationBootstrap
            | Self::KeyEnrollment
            | Self::ActiveStorePolicy
            | Self::InstallationIntent
            | Self::InstallationReceipt
            | Self::SignerTransition => C2AppendExtentRoleV1::BootstrapB,
        }
    }
}

/// Verified append cursor.  It has no operation for decrement or reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2AppendCursorV1 {
    role: C2AppendExtentRoleV1,
    next_payload_offset: u64,
    next_slot: u32,
    content_root: Sha256Digest,
}

impl C2AppendCursorV1 {
    /// Construct the empty, header-authenticated cursor.
    pub fn from_verified_header(
        header: &C2CarrierHeaderV1,
    ) -> Result<Self, C2AppendExtentRefusalV1> {
        verify_header_identity(header)?;
        Ok(Self {
            role: header.role,
            next_payload_offset: 0,
            next_slot: 0,
            content_root: semantic_digest(&EmptyRootPreimage {
                domain: "nq.c2.append_extent.empty_root.v1",
                header_identity: &header.header_identity,
            })?,
        })
    }

    /// Next relative payload byte, never a file-global offset.
    #[must_use]
    pub const fn next_payload_offset(&self) -> u64 {
        self.next_payload_offset
    }

    /// Next frame slot.
    #[must_use]
    pub const fn next_slot(&self) -> u32 {
        self.next_slot
    }

    /// Current predecessor root.
    #[must_use]
    pub const fn content_root(&self) -> &Sha256Digest {
        &self.content_root
    }
}

/// Length-delimited, predecessor-bound, checksummed append frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2AppendFrameV1 {
    schema: &'static str,
    schema_version: u8,
    frame_identity: Sha256Digest,
    role: C2AppendExtentRoleV1,
    kind: C2AppendFrameKindV1,
    slot: u32,
    relative_payload_offset: u64,
    canonical_payload_length: u32,
    predecessor_root: Sha256Digest,
    payload_checksum: Sha256Digest,
    resulting_root: Sha256Digest,
}

/// Exact lock-to-B-genesis backlink.  It cannot point to G or a later frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2LockBacklinkV1 {
    schema: &'static str,
    physical_store_generation_identity: Sha256Digest,
    b_genesis_frame_identity: Sha256Digest,
    backlink_identity: Sha256Digest,
}

/// Typed refusal for fixed geometry, pair, header, and frame verification.
#[derive(Debug, Error)]
pub enum C2AppendExtentRefusalV1 {
    #[error("append-extent arithmetic overflow or unsafe I-JSON length")]
    ArithmeticOverflow,
    #[error("B/G payload bounds or installed G maxima are zero or inconsistent")]
    InvalidBounds,
    #[error("carrier file facts are unsafe or do not match fixed geometry")]
    InvalidFileFacts,
    #[error("the B and G carriers are not distinct regular-file identities on one device")]
    CarrierPairAliasOrDeviceMismatch,
    #[error(
        "carrier pair, profile, occurrence, generation, role, layout, bounds, or file facts mismatch"
    )]
    HeaderCorrespondenceMismatch,
    #[error("a frame family was placed in the wrong carrier role")]
    CrossVocabularyPlacement,
    #[error("an append frame is not the exact next predecessor-bound frame")]
    FrameChainMismatch,
    #[error("an append frame exceeds the preallocated payload or slot bound")]
    ExtentExhausted,
    #[error("the lock backlink is not the exact B genesis frame for this physical generation")]
    BacklinkMismatch,
    #[error("canonical identity computation failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
    #[error("durable append carrier I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the durable header, superblock, or append-record codec is malformed")]
    DurableCodecMalformed,
    #[error("the durable append carrier contains a torn or uncommitted tail")]
    TornAppend,
    #[error("one durable operation identity was reused with changed content")]
    ChangedContentCollision,
}

#[derive(Serialize)]
struct PairPreimage<'a> {
    domain: &'static str,
    append_extent_layout: &'static str,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    qualified_backend_profile_identity: &'a Sha256Digest,
    b_file: &'a C2CarrierFileFactsV1,
    g_file: &'a C2CarrierFileFactsV1,
}

#[derive(Serialize)]
struct HeaderPreimage<'a> {
    domain: &'static str,
    schema: &'static str,
    schema_version: u8,
    carrier_pair_identity: &'a Sha256Digest,
    qualified_backend_profile_identity: &'a Sha256Digest,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    role: C2AppendExtentRoleV1,
    append_extent_layout: &'static str,
    payload_bound: u64,
    physical_length: u64,
    file: &'a C2CarrierFileFactsV1,
}

#[derive(Serialize)]
struct EmptyRootPreimage<'a> {
    domain: &'static str,
    header_identity: &'a Sha256Digest,
}

#[derive(Serialize)]
struct FramePreimage<'a> {
    domain: &'static str,
    schema: &'static str,
    schema_version: u8,
    role: C2AppendExtentRoleV1,
    kind: C2AppendFrameKindV1,
    slot: u32,
    relative_payload_offset: u64,
    canonical_payload_length: u32,
    predecessor_root: &'a Sha256Digest,
    payload_checksum: &'a Sha256Digest,
}

#[derive(Serialize)]
struct RootProgression<'a> {
    domain: &'static str,
    predecessor_root: &'a Sha256Digest,
    frame_identity: &'a Sha256Digest,
}

#[derive(Serialize)]
struct BacklinkPreimage<'a> {
    domain: &'static str,
    schema: &'static str,
    physical_store_generation_identity: &'a Sha256Digest,
    b_genesis_frame_identity: &'a Sha256Digest,
}

fn checked_extent_length(payload_bound: u64) -> Result<u64, C2AppendExtentRefusalV1> {
    let unaligned = C2_APPEND_PAYLOAD_OFFSET_V1
        .checked_add(payload_bound)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let rounded = unaligned
        .checked_add(C2_APPEND_ALIGNMENT_BYTES_V1 - 1)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?
        / C2_APPEND_ALIGNMENT_BYTES_V1
        * C2_APPEND_ALIGNMENT_BYTES_V1;
    if rounded > IJSON_SAFE_U64 {
        Err(C2AppendExtentRefusalV1::ArithmeticOverflow)
    } else {
        Ok(rounded)
    }
}

/// WU-03: construct the sole fixed B/G geometry and installed G maxima.
pub fn construct_wu_03_immutable_wu_append_extents_b_g_carrier(
    b_payload_bound: u64,
    g_payload_bound: u64,
    global_refusal_max_entries: u32,
    global_refusal_entry_max_bytes: u32,
) -> Result<C2AppendExtentLayoutV1, C2AppendExtentRefusalV1> {
    if b_payload_bound == 0
        || g_payload_bound == 0
        || global_refusal_max_entries == 0
        || global_refusal_entry_max_bytes == 0
        || u64::from(global_refusal_max_entries)
            .checked_mul(u64::from(global_refusal_entry_max_bytes))
            .is_none_or(|maximum| maximum > g_payload_bound)
    {
        return Err(C2AppendExtentRefusalV1::InvalidBounds);
    }
    let b_append_extent_length = checked_extent_length(b_payload_bound)?;
    let g_append_extent_length = checked_extent_length(g_payload_bound)?;
    let b_aggregate_length_with_lock = C2_APPEND_ALIGNMENT_BYTES_V1
        .checked_add(b_append_extent_length)
        .filter(|length| *length <= IJSON_SAFE_U64)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let layout = C2AppendExtentLayoutV1 {
        schema: C2_APPEND_EXTENT_LAYOUT_ID_V1,
        alignment_bytes: C2_APPEND_ALIGNMENT_BYTES_V1,
        superblock_zero_offset: 0,
        superblock_one_offset: C2_APPEND_ALIGNMENT_BYTES_V1,
        header_offset: 2 * C2_APPEND_ALIGNMENT_BYTES_V1,
        payload_offset: C2_APPEND_PAYLOAD_OFFSET_V1,
        b_payload_bound,
        g_payload_bound,
        b_append_extent_length,
        b_aggregate_length_with_lock,
        g_append_extent_length,
        global_refusal_max_entries,
        global_refusal_entry_max_bytes,
    };
    verify_wu_03_immutable_wu_append_extents_b_g_carrier(&layout)?;
    Ok(layout)
}

/// WU-03: verify exact offsets and refuse double-count, omission, or overrun.
pub fn verify_wu_03_immutable_wu_append_extents_b_g_carrier(
    layout: &C2AppendExtentLayoutV1,
) -> Result<(), C2AppendExtentRefusalV1> {
    let expected = construct_layout_without_recursive_verification(
        layout.b_payload_bound,
        layout.g_payload_bound,
        layout.global_refusal_max_entries,
        layout.global_refusal_entry_max_bytes,
    )?;
    if &expected == layout {
        Ok(())
    } else {
        Err(C2AppendExtentRefusalV1::InvalidBounds)
    }
}

fn construct_layout_without_recursive_verification(
    b_payload_bound: u64,
    g_payload_bound: u64,
    global_refusal_max_entries: u32,
    global_refusal_entry_max_bytes: u32,
) -> Result<C2AppendExtentLayoutV1, C2AppendExtentRefusalV1> {
    if b_payload_bound == 0
        || g_payload_bound == 0
        || global_refusal_max_entries == 0
        || global_refusal_entry_max_bytes == 0
    {
        return Err(C2AppendExtentRefusalV1::InvalidBounds);
    }
    let required = u64::from(global_refusal_max_entries)
        .checked_mul(u64::from(global_refusal_entry_max_bytes))
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    if required > g_payload_bound {
        return Err(C2AppendExtentRefusalV1::InvalidBounds);
    }
    let b_append_extent_length = checked_extent_length(b_payload_bound)?;
    let g_append_extent_length = checked_extent_length(g_payload_bound)?;
    Ok(C2AppendExtentLayoutV1 {
        schema: C2_APPEND_EXTENT_LAYOUT_ID_V1,
        alignment_bytes: C2_APPEND_ALIGNMENT_BYTES_V1,
        superblock_zero_offset: 0,
        superblock_one_offset: C2_APPEND_ALIGNMENT_BYTES_V1,
        header_offset: 2 * C2_APPEND_ALIGNMENT_BYTES_V1,
        payload_offset: C2_APPEND_PAYLOAD_OFFSET_V1,
        b_payload_bound,
        g_payload_bound,
        b_append_extent_length,
        b_aggregate_length_with_lock: C2_APPEND_ALIGNMENT_BYTES_V1
            .checked_add(b_append_extent_length)
            .filter(|length| *length <= IJSON_SAFE_U64)
            .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?,
        g_append_extent_length,
        global_refusal_max_entries,
        global_refusal_entry_max_bytes,
    })
}

/// N-85 constructor target for the exact formula/physical-layout law.
pub fn construct_n_85_extent_b_g_formulas_physical_layout_no(
    b_payload_bound: u64,
    g_payload_bound: u64,
    global_refusal_max_entries: u32,
    global_refusal_entry_max_bytes: u32,
) -> Result<C2AppendExtentLayoutV1, C2AppendExtentRefusalV1> {
    construct_wu_03_immutable_wu_append_extents_b_g_carrier(
        b_payload_bound,
        g_payload_bound,
        global_refusal_max_entries,
        global_refusal_entry_max_bytes,
    )
}

/// N-85 verifier target.
pub fn verify_n_85_extent_b_g_formulas_physical_layout_no(
    layout: &C2AppendExtentLayoutV1,
) -> Result<(), C2AppendExtentRefusalV1> {
    verify_wu_03_immutable_wu_append_extents_b_g_carrier(layout)
}

fn validate_file_facts(
    facts: &C2CarrierFileFactsV1,
    expected_length: u64,
) -> Result<(), C2AppendExtentRefusalV1> {
    if facts.device > IJSON_SAFE_U64
        || facts.inode == 0
        || facts.inode > IJSON_SAFE_U64
        || facts.mode != 0o600
        || facts.physical_length != expected_length
        || facts.link_count != 1
    {
        Err(C2AppendExtentRefusalV1::InvalidFileFacts)
    } else {
        Ok(())
    }
}

fn pair_identity(pair: &C2CarrierPairInputV1) -> Result<Sha256Digest, CanonicalizationError> {
    semantic_digest(&PairPreimage {
        domain: C2_CARRIER_PAIR_IDENTITY_DOMAIN_V1,
        append_extent_layout: C2_APPEND_EXTENT_LAYOUT_ID_V1,
        occurrence_id: &pair.occurrence_id,
        physical_store_generation_identity: &pair.physical_store_generation_identity,
        qualified_backend_profile_identity: &pair.qualified_backend_profile_identity,
        b_file: &pair.b_file,
        g_file: &pair.g_file,
    })
}

fn construct_header(
    layout: &C2AppendExtentLayoutV1,
    pair: &C2CarrierPairInputV1,
    carrier_pair_identity: &Sha256Digest,
    role: C2AppendExtentRoleV1,
) -> Result<C2CarrierHeaderV1, C2AppendExtentRefusalV1> {
    let (payload_bound, physical_length, file) = match role {
        C2AppendExtentRoleV1::BootstrapB => (
            layout.b_payload_bound,
            layout.b_append_extent_length,
            pair.b_file.clone(),
        ),
        C2AppendExtentRoleV1::GlobalRefusalG => (
            layout.g_payload_bound,
            layout.g_append_extent_length,
            pair.g_file.clone(),
        ),
    };
    let preimage = HeaderPreimage {
        domain: C2_CARRIER_HEADER_IDENTITY_DOMAIN_V1,
        schema: "nq.c2_carrier_header.v1",
        schema_version: 1,
        carrier_pair_identity,
        qualified_backend_profile_identity: &pair.qualified_backend_profile_identity,
        occurrence_id: &pair.occurrence_id,
        physical_store_generation_identity: &pair.physical_store_generation_identity,
        role,
        append_extent_layout: C2_APPEND_EXTENT_LAYOUT_ID_V1,
        payload_bound,
        physical_length,
        file: &file,
    };
    Ok(C2CarrierHeaderV1 {
        schema: "nq.c2_carrier_header.v1",
        schema_version: 1,
        header_identity: semantic_digest(&preimage)?,
        carrier_pair_identity: carrier_pair_identity.clone(),
        qualified_backend_profile_identity: pair.qualified_backend_profile_identity.clone(),
        occurrence_id: pair.occurrence_id.clone(),
        physical_store_generation_identity: pair.physical_store_generation_identity.clone(),
        role,
        append_extent_layout: C2_APPEND_EXTENT_LAYOUT_ID_V1,
        payload_bound,
        physical_length,
        file,
    })
}

/// N-86: construct both headers from one common, nonrecursive pair preimage.
pub fn construct_n_86_headers_bind_common_pair_profile_occurrence_generation(
    layout: &C2AppendExtentLayoutV1,
    pair: C2CarrierPairInputV1,
) -> Result<C2CarrierPairHeaderCorrespondenceV1, C2AppendExtentRefusalV1> {
    verify_n_85_extent_b_g_formulas_physical_layout_no(layout)?;
    if pair.occurrence_id.is_empty() || pair.occurrence_id.len() > 256 {
        return Err(C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch);
    }
    validate_file_facts(&pair.b_file, layout.b_append_extent_length)?;
    validate_file_facts(&pair.g_file, layout.g_append_extent_length)?;
    if pair.b_file.device != pair.g_file.device
        || pair.b_file.file_identity == pair.g_file.file_identity
        || pair.b_file.inode == pair.g_file.inode
    {
        return Err(C2AppendExtentRefusalV1::CarrierPairAliasOrDeviceMismatch);
    }
    let carrier_pair_identity = pair_identity(&pair)?;
    let b_header = construct_header(
        layout,
        &pair,
        &carrier_pair_identity,
        C2AppendExtentRoleV1::BootstrapB,
    )?;
    let g_header = construct_header(
        layout,
        &pair,
        &carrier_pair_identity,
        C2AppendExtentRoleV1::GlobalRefusalG,
    )?;
    let correspondence = C2CarrierPairHeaderCorrespondenceV1 {
        carrier_pair_identity,
        pair,
        b_header,
        g_header,
    };
    verify_n_86_headers_bind_common_pair_profile_occurrence_generation(layout, &correspondence)?;
    Ok(correspondence)
}

fn verify_header_identity(header: &C2CarrierHeaderV1) -> Result<(), C2AppendExtentRefusalV1> {
    let expected = semantic_digest(&HeaderPreimage {
        domain: C2_CARRIER_HEADER_IDENTITY_DOMAIN_V1,
        schema: header.schema,
        schema_version: header.schema_version,
        carrier_pair_identity: &header.carrier_pair_identity,
        qualified_backend_profile_identity: &header.qualified_backend_profile_identity,
        occurrence_id: &header.occurrence_id,
        physical_store_generation_identity: &header.physical_store_generation_identity,
        role: header.role,
        append_extent_layout: header.append_extent_layout,
        payload_bound: header.payload_bound,
        physical_length: header.physical_length,
        file: &header.file,
    })?;
    if expected == header.header_identity {
        Ok(())
    } else {
        Err(C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch)
    }
}

/// N-86: verify pair/header equality without allowing a header-selected profile.
pub fn verify_n_86_headers_bind_common_pair_profile_occurrence_generation(
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
) -> Result<(), C2AppendExtentRefusalV1> {
    let expected_pair_identity = pair_identity(&correspondence.pair)?;
    let expected_b = construct_header(
        layout,
        &correspondence.pair,
        &expected_pair_identity,
        C2AppendExtentRoleV1::BootstrapB,
    )?;
    let expected_g = construct_header(
        layout,
        &correspondence.pair,
        &expected_pair_identity,
        C2AppendExtentRoleV1::GlobalRefusalG,
    )?;
    if correspondence.carrier_pair_identity == expected_pair_identity
        && correspondence.b_header == expected_b
        && correspondence.g_header == expected_g
    {
        Ok(())
    } else {
        Err(C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch)
    }
}

/// REC-30 constructs the exact common-pair/both-header correspondence.
pub fn construct_rec_30_pair_header_correspondence(
    layout: &C2AppendExtentLayoutV1,
    pair: C2CarrierPairInputV1,
) -> Result<C2CarrierPairHeaderCorrespondenceV1, C2AppendExtentRefusalV1> {
    construct_n_86_headers_bind_common_pair_profile_occurrence_generation(layout, pair)
}

/// REC-30 verifies both role-distinct headers against the one common pair.
pub fn verify_rec_30_pair_header_correspondence(
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
) -> Result<(), C2AppendExtentRefusalV1> {
    verify_n_86_headers_bind_common_pair_profile_occurrence_generation(layout, correspondence)
}

/// Construct exactly one next append frame and advance the retain-only cursor.
pub fn append_exact_frame_v1(
    layout: &C2AppendExtentLayoutV1,
    cursor: C2AppendCursorV1,
    kind: C2AppendFrameKindV1,
    canonical_payload: &[u8],
) -> Result<(C2AppendFrameV1, C2AppendCursorV1), C2AppendExtentRefusalV1> {
    if kind.role() != cursor.role {
        return Err(C2AppendExtentRefusalV1::CrossVocabularyPlacement);
    }
    let payload_length = u32::try_from(canonical_payload.len())
        .map_err(|_| C2AppendExtentRefusalV1::ExtentExhausted)?;
    let next_offset = cursor
        .next_payload_offset
        .checked_add(u64::from(payload_length))
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    if canonical_payload.is_empty()
        || next_offset > layout.payload_bound(cursor.role)
        || (cursor.role == C2AppendExtentRoleV1::GlobalRefusalG
            && (payload_length > layout.global_refusal_entry_max_bytes
                || cursor.next_slot >= layout.global_refusal_max_entries))
    {
        return Err(C2AppendExtentRefusalV1::ExtentExhausted);
    }
    let payload_checksum = sha256_bytes(canonical_payload);
    let frame_identity = semantic_digest(&FramePreimage {
        domain: C2_APPEND_FRAME_IDENTITY_DOMAIN_V1,
        schema: "nq.c2_append_frame.v1",
        schema_version: 1,
        role: cursor.role,
        kind,
        slot: cursor.next_slot,
        relative_payload_offset: cursor.next_payload_offset,
        canonical_payload_length: payload_length,
        predecessor_root: &cursor.content_root,
        payload_checksum: &payload_checksum,
    })?;
    let resulting_root = semantic_digest(&RootProgression {
        domain: "nq.c2.append_extent.root_progression.v1",
        predecessor_root: &cursor.content_root,
        frame_identity: &frame_identity,
    })?;
    let frame = C2AppendFrameV1 {
        schema: "nq.c2_append_frame.v1",
        schema_version: 1,
        frame_identity,
        role: cursor.role,
        kind,
        slot: cursor.next_slot,
        relative_payload_offset: cursor.next_payload_offset,
        canonical_payload_length: payload_length,
        predecessor_root: cursor.content_root,
        payload_checksum,
        resulting_root: resulting_root.clone(),
    };
    let advanced = C2AppendCursorV1 {
        role: cursor.role,
        next_payload_offset: next_offset,
        next_slot: cursor
            .next_slot
            .checked_add(1)
            .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?,
        content_root: resulting_root,
    };
    Ok((frame, advanced))
}

/// Verify an observed frame against the exact predecessor cursor and bytes.
pub fn verify_exact_frame_v1(
    layout: &C2AppendExtentLayoutV1,
    cursor: C2AppendCursorV1,
    observed: &C2AppendFrameV1,
    canonical_payload: &[u8],
) -> Result<C2AppendCursorV1, C2AppendExtentRefusalV1> {
    let (expected, advanced) =
        append_exact_frame_v1(layout, cursor, observed.kind, canonical_payload)?;
    if &expected == observed {
        Ok(advanced)
    } else {
        Err(C2AppendExtentRefusalV1::FrameChainMismatch)
    }
}

const C2_DURABLE_HEADER_PAGE_MAGIC_V1: &[u8; 8] = b"NQHDRV1\0";
const C2_DURABLE_SUPERBLOCK_MAGIC_V1: &[u8; 8] = b"NQSUPV1\0";
const C2_DURABLE_RECORD_MAGIC_V1: &[u8; 8] = b"NQRECV1\0";
const C2_DURABLE_PAGE_PREFIX_BYTES_V1: usize = 8 + 4 + 32;
const C2_DURABLE_RECORD_PREFIX_BYTES_V1: usize = 8 + 1 + 4 + 4 + 32;
const C2_DURABLE_RECORD_CHECKSUM_BYTES_V1: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct C2DurableAppendSuperblockV1 {
    schema: String,
    schema_version: u8,
    header_identity: Sha256Digest,
    role: C2AppendExtentRoleV1,
    epoch: u64,
    physical_next_offset: u64,
    semantic_next_payload_offset: u64,
    next_slot: u32,
    content_root: Sha256Digest,
    last_operation_identity: Option<Sha256Digest>,
    last_frame_identity: Option<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2DurableAppendDispositionV1 {
    Appended,
    ExactReplay,
}

/// Physical B/G append outcome. It is evidence only, never signer standing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2DurableAppendOutcomeV1 {
    pub(crate) disposition: C2DurableAppendDispositionV1,
    pub(crate) role: C2AppendExtentRoleV1,
    pub(crate) kind: C2AppendFrameKindV1,
    pub(crate) operation_identity: Sha256Digest,
    pub(crate) frame_identity: Sha256Digest,
    pub(crate) resulting_root: Sha256Digest,
    pub(crate) slot: u32,
}

/// Read-only exact carrier frontier used by Store installation/reopen
/// verification. It is evidence, not append or signer authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2DurableAppendPairSnapshotV1 {
    pub(crate) b_content_root: Sha256Digest,
    pub(crate) b_next_payload_offset: u64,
    pub(crate) b_next_slot: u32,
    pub(crate) g_content_root: Sha256Digest,
    pub(crate) g_next_payload_offset: u64,
    pub(crate) g_next_slot: u32,
}

#[derive(Clone, Debug)]
struct C2DurableRecordSummaryV1 {
    kind: C2AppendFrameKindV1,
    operation_identity: Sha256Digest,
    canonical_payload: Vec<u8>,
    frame_identity: Sha256Digest,
    resulting_root: Sha256Digest,
    slot: u32,
}

/// Read-only view of one authenticated physical B/G record.  The append
/// codec has already checked its checksum, frame chain, slot, and carrier
/// role.  Semantic signer-envelope verification is deliberately performed by
/// the signer owner, which consumes this view without gaining a mutation
/// handle to the carrier.
pub(crate) struct C2DurableRecordViewV1<'record> {
    pub(crate) role: C2AppendExtentRoleV1,
    pub(crate) kind: C2AppendFrameKindV1,
    pub(crate) slot: u32,
    pub(crate) operation_identity: &'record Sha256Digest,
    pub(crate) canonical_payload: &'record [u8],
    pub(crate) frame_identity: &'record Sha256Digest,
    pub(crate) resulting_root: &'record Sha256Digest,
}

struct C2OpenedDurableExtentV1 {
    file: File,
    header: C2CarrierHeaderV1,
    cursor: C2AppendCursorV1,
    superblock_epoch: u64,
    physical_next_offset: u64,
    records: Vec<C2DurableRecordSummaryV1>,
}

/// Descriptor-owning authenticated B/G pair. It is process-local,
/// nonserializable, noncloneable, and has no raw-coordinate constructor.
pub(crate) struct C2DurableAppendPairV1 {
    layout: C2AppendExtentLayoutV1,
    correspondence: C2CarrierPairHeaderCorrespondenceV1,
    b: C2OpenedDurableExtentV1,
    g: C2OpenedDurableExtentV1,
}

/// Physical extent initialization boundary used only by the fresh C2
/// installer.  The callback observes a fully written and `sync_data`-ed
/// extent, so BootstrapB is reachable before GlobalRefusalG begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2InstallationExtentInitializedV1 {
    BootstrapB,
    GlobalRefusalG,
}

/// Exact split between append-codec refusal and an installation crash
/// observer stopping after one real physical extent effect.
pub(crate) enum C2ObservedAppendExtentRefusalV1<E> {
    Append(C2AppendExtentRefusalV1),
    Observer(E),
}

fn digest_raw_bytes(digest: &Sha256Digest) -> Result<[u8; 32], C2AppendExtentRefusalV1> {
    let text = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(C2AppendExtentRefusalV1::DurableCodecMalformed)?;
    hex::decode(text)
        .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)?
        .try_into()
        .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)
}

fn digest_from_raw(bytes: &[u8]) -> Result<Sha256Digest, C2AppendExtentRefusalV1> {
    if bytes.len() != 32 {
        return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
    }
    Sha256Digest::parse(format!("sha256:{}", hex::encode(bytes)))
        .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)
}

fn write_all_at(file: &File, mut offset: u64, mut bytes: &[u8]) -> Result<(), std::io::Error> {
    while !bytes.is_empty() {
        let written = file.write_at(bytes, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "C2 durable append pwrite returned zero",
            ));
        }
        offset = offset
            .checked_add(written as u64)
            .ok_or_else(|| std::io::Error::other("C2 durable append offset overflow"))?;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn read_exact_at(file: &File, mut offset: u64, mut bytes: &mut [u8]) -> Result<(), std::io::Error> {
    while !bytes.is_empty() {
        let read = file.read_at(bytes, offset)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "C2 durable append pread reached EOF",
            ));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("C2 durable append offset overflow"))?;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

fn encode_durable_page<T: Serialize>(
    magic: &[u8; 8],
    value: &T,
) -> Result<Vec<u8>, C2AppendExtentRefusalV1> {
    let canonical = canonical_json_bytes(value)?;
    if canonical.len() > C2_APPEND_ALIGNMENT_BYTES_V1 as usize - C2_DURABLE_PAGE_PREFIX_BYTES_V1 {
        return Err(C2AppendExtentRefusalV1::ExtentExhausted);
    }
    let mut page = vec![0; C2_APPEND_ALIGNMENT_BYTES_V1 as usize];
    page[..8].copy_from_slice(magic);
    page[8..12].copy_from_slice(&(canonical.len() as u32).to_be_bytes());
    let mut checksum_preimage = Vec::with_capacity(magic.len() + canonical.len());
    checksum_preimage.extend_from_slice(magic);
    checksum_preimage.extend_from_slice(&canonical);
    page[12..44].copy_from_slice(&digest_raw_bytes(&sha256_bytes(&checksum_preimage))?);
    page[44..44 + canonical.len()].copy_from_slice(&canonical);
    Ok(page)
}

fn decode_durable_page(
    file: &File,
    offset: u64,
    magic: &[u8; 8],
) -> Result<Vec<u8>, C2AppendExtentRefusalV1> {
    let mut page = vec![0; C2_APPEND_ALIGNMENT_BYTES_V1 as usize];
    read_exact_at(file, offset, &mut page)?;
    if &page[..8] != magic {
        return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
    }
    let length = u32::from_be_bytes(
        page[8..12]
            .try_into()
            .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)?,
    ) as usize;
    let end = C2_DURABLE_PAGE_PREFIX_BYTES_V1
        .checked_add(length)
        .filter(|end| *end <= page.len())
        .ok_or(C2AppendExtentRefusalV1::DurableCodecMalformed)?;
    if page[end..].iter().any(|byte| *byte != 0) {
        return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
    }
    let canonical = &page[C2_DURABLE_PAGE_PREFIX_BYTES_V1..end];
    let mut checksum_preimage = Vec::with_capacity(magic.len() + canonical.len());
    checksum_preimage.extend_from_slice(magic);
    checksum_preimage.extend_from_slice(canonical);
    if page[12..44] != digest_raw_bytes(&sha256_bytes(&checksum_preimage))? {
        return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
    }
    Ok(canonical.to_vec())
}

fn kind_byte(kind: C2AppendFrameKindV1) -> u8 {
    match kind {
        C2AppendFrameKindV1::StoreGenerationBootstrap => 1,
        C2AppendFrameKindV1::KeyEnrollment => 2,
        C2AppendFrameKindV1::ActiveStorePolicy => 3,
        C2AppendFrameKindV1::InstallationIntent => 4,
        C2AppendFrameKindV1::InstallationReceipt => 5,
        C2AppendFrameKindV1::SignerTransition => 6,
        C2AppendFrameKindV1::GlobalRefusal => 7,
    }
}

fn decode_kind(byte: u8) -> Result<C2AppendFrameKindV1, C2AppendExtentRefusalV1> {
    match byte {
        1 => Ok(C2AppendFrameKindV1::StoreGenerationBootstrap),
        2 => Ok(C2AppendFrameKindV1::KeyEnrollment),
        3 => Ok(C2AppendFrameKindV1::ActiveStorePolicy),
        4 => Ok(C2AppendFrameKindV1::InstallationIntent),
        5 => Ok(C2AppendFrameKindV1::InstallationReceipt),
        6 => Ok(C2AppendFrameKindV1::SignerTransition),
        7 => Ok(C2AppendFrameKindV1::GlobalRefusal),
        _ => Err(C2AppendExtentRefusalV1::DurableCodecMalformed),
    }
}

fn encode_durable_record(
    frame: &C2AppendFrameV1,
    kind: C2AppendFrameKindV1,
    operation_identity: &Sha256Digest,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, C2AppendExtentRefusalV1> {
    let frame_bytes = canonical_json_bytes(frame)?;
    let frame_length =
        u32::try_from(frame_bytes.len()).map_err(|_| C2AppendExtentRefusalV1::ExtentExhausted)?;
    let payload_length = u32::try_from(canonical_payload.len())
        .map_err(|_| C2AppendExtentRefusalV1::ExtentExhausted)?;
    let capacity = C2_DURABLE_RECORD_PREFIX_BYTES_V1
        .checked_add(frame_bytes.len())
        .and_then(|length| length.checked_add(canonical_payload.len()))
        .and_then(|length| length.checked_add(C2_DURABLE_RECORD_CHECKSUM_BYTES_V1))
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let mut record = Vec::with_capacity(capacity);
    record.extend_from_slice(C2_DURABLE_RECORD_MAGIC_V1);
    record.push(kind_byte(kind));
    record.extend_from_slice(&frame_length.to_be_bytes());
    record.extend_from_slice(&payload_length.to_be_bytes());
    record.extend_from_slice(&digest_raw_bytes(operation_identity)?);
    record.extend_from_slice(&frame_bytes);
    record.extend_from_slice(canonical_payload);
    record.extend_from_slice(&digest_raw_bytes(&sha256_bytes(&record))?);
    Ok(record)
}

fn initial_superblock(
    header: &C2CarrierHeaderV1,
) -> Result<C2DurableAppendSuperblockV1, C2AppendExtentRefusalV1> {
    let cursor = C2AppendCursorV1::from_verified_header(header)?;
    Ok(C2DurableAppendSuperblockV1 {
        schema: "nq.c2_durable_append_superblock.v1".to_owned(),
        schema_version: 1,
        header_identity: header.header_identity.clone(),
        role: header.role,
        epoch: 0,
        physical_next_offset: 0,
        semantic_next_payload_offset: cursor.next_payload_offset,
        next_slot: cursor.next_slot,
        content_root: cursor.content_root,
        last_operation_identity: None,
        last_frame_identity: None,
    })
}

fn verify_file_matches_header(
    file: &File,
    header: &C2CarrierHeaderV1,
) -> Result<(), C2AppendExtentRefusalV1> {
    verify_header_identity(header)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.dev() != header.file.device
        || metadata.ino() != header.file.inode
        || metadata.uid() != header.file.owner_uid
        || metadata.gid() != header.file.owner_gid
        || metadata.permissions().mode() & 0o7777 != header.file.mode
        || metadata.len() != header.file.physical_length
        || metadata.nlink() != header.file.link_count
    {
        return Err(C2AppendExtentRefusalV1::InvalidFileFacts);
    }
    Ok(())
}

fn initialize_durable_extent_v1(
    file: &File,
    header: &C2CarrierHeaderV1,
) -> Result<C2OpenedDurableExtentV1, C2AppendExtentRefusalV1> {
    verify_file_matches_header(file, header)?;
    let mut observed = vec![0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < header.physical_length {
        let remaining = header.physical_length - offset;
        let length = usize::try_from(remaining.min(observed.len() as u64))
            .map_err(|_| C2AppendExtentRefusalV1::ArithmeticOverflow)?;
        read_exact_at(file, offset, &mut observed[..length])?;
        if observed[..length].iter().any(|byte| *byte != 0) {
            return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
        }
        offset = offset
            .checked_add(length as u64)
            .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    }

    let header_page = encode_durable_page(C2_DURABLE_HEADER_PAGE_MAGIC_V1, header)?;
    let superblock = initial_superblock(header)?;
    let superblock_page = encode_durable_page(C2_DURABLE_SUPERBLOCK_MAGIC_V1, &superblock)?;
    write_all_at(file, 2 * C2_APPEND_ALIGNMENT_BYTES_V1, &header_page)?;
    write_all_at(file, 0, &superblock_page)?;
    write_all_at(file, C2_APPEND_ALIGNMENT_BYTES_V1, &superblock_page)?;
    file.sync_data()?;
    Ok(C2OpenedDurableExtentV1 {
        file: file.try_clone()?,
        header: header.clone(),
        cursor: C2AppendCursorV1::from_verified_header(header)?,
        superblock_epoch: 0,
        physical_next_offset: 0,
        records: Vec::new(),
    })
}

fn decode_superblock_page_v1(
    file: &File,
    offset: u64,
) -> Result<C2DurableAppendSuperblockV1, C2AppendExtentRefusalV1> {
    let canonical = decode_durable_page(file, offset, C2_DURABLE_SUPERBLOCK_MAGIC_V1)?;
    let decoded: C2DurableAppendSuperblockV1 = serde_json::from_slice(&canonical)
        .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)?;
    if canonical_json_bytes(&decoded)? != canonical
        || decoded.schema != "nq.c2_durable_append_superblock.v1"
        || decoded.schema_version != 1
    {
        return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
    }
    Ok(decoded)
}

fn select_durable_superblock_v1(
    file: &File,
) -> Result<C2DurableAppendSuperblockV1, C2AppendExtentRefusalV1> {
    let zero = decode_superblock_page_v1(file, 0).ok();
    let one = decode_superblock_page_v1(file, C2_APPEND_ALIGNMENT_BYTES_V1).ok();
    match (zero, one) {
        (Some(zero), Some(one)) => Ok(if zero.epoch >= one.epoch { zero } else { one }),
        (Some(value), None) | (None, Some(value)) => Ok(value),
        (None, None) => Err(C2AppendExtentRefusalV1::DurableCodecMalformed),
    }
}

fn decode_durable_record_at_v1(
    layout: &C2AppendExtentLayoutV1,
    extent: &C2OpenedDurableExtentV1,
    cursor: C2AppendCursorV1,
    relative_physical_offset: u64,
    committed_physical_end: u64,
) -> Result<(C2DurableRecordSummaryV1, C2AppendCursorV1, u64), C2AppendExtentRefusalV1> {
    let absolute = C2_APPEND_PAYLOAD_OFFSET_V1
        .checked_add(relative_physical_offset)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let mut prefix = [0_u8; C2_DURABLE_RECORD_PREFIX_BYTES_V1];
    read_exact_at(&extent.file, absolute, &mut prefix)?;
    if &prefix[..8] != C2_DURABLE_RECORD_MAGIC_V1 {
        return Err(C2AppendExtentRefusalV1::DurableCodecMalformed);
    }
    let kind = decode_kind(prefix[8])?;
    let frame_length = u32::from_be_bytes(
        prefix[9..13]
            .try_into()
            .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)?,
    ) as usize;
    let payload_length = u32::from_be_bytes(
        prefix[13..17]
            .try_into()
            .map_err(|_| C2AppendExtentRefusalV1::DurableCodecMalformed)?,
    ) as usize;
    let operation_identity = digest_from_raw(&prefix[17..49])?;
    let record_length = C2_DURABLE_RECORD_PREFIX_BYTES_V1
        .checked_add(frame_length)
        .and_then(|length| length.checked_add(payload_length))
        .and_then(|length| length.checked_add(C2_DURABLE_RECORD_CHECKSUM_BYTES_V1))
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let relative_end = relative_physical_offset
        .checked_add(record_length as u64)
        .filter(|end| *end <= committed_physical_end)
        .ok_or(C2AppendExtentRefusalV1::TornAppend)?;
    let mut record = vec![0_u8; record_length];
    read_exact_at(&extent.file, absolute, &mut record)?;
    let checksum_start = record_length - C2_DURABLE_RECORD_CHECKSUM_BYTES_V1;
    let expected_checksum = digest_raw_bytes(&sha256_bytes(&record[..checksum_start]))?;
    if record[checksum_start..] != expected_checksum {
        return Err(C2AppendExtentRefusalV1::TornAppend);
    }
    let frame_start = C2_DURABLE_RECORD_PREFIX_BYTES_V1;
    let frame_end = frame_start + frame_length;
    let payload_end = frame_end + payload_length;
    let canonical_payload = record[frame_end..payload_end].to_vec();
    let (expected_frame, advanced) =
        append_exact_frame_v1(layout, cursor, kind, &canonical_payload)?;
    if canonical_json_bytes(&expected_frame)? != record[frame_start..frame_end] {
        return Err(C2AppendExtentRefusalV1::FrameChainMismatch);
    }
    Ok((
        C2DurableRecordSummaryV1 {
            kind,
            operation_identity,
            canonical_payload,
            frame_identity: expected_frame.frame_identity.clone(),
            resulting_root: expected_frame.resulting_root.clone(),
            slot: expected_frame.slot,
        },
        advanced,
        relative_end,
    ))
}

fn suffix_is_zero_v1(file: &File, start: u64, end: u64) -> Result<bool, C2AppendExtentRefusalV1> {
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut offset = start;
    while offset < end {
        let length = usize::try_from((end - offset).min(buffer.len() as u64))
            .map_err(|_| C2AppendExtentRefusalV1::ArithmeticOverflow)?;
        read_exact_at(file, offset, &mut buffer[..length])?;
        if buffer[..length].iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        offset = offset
            .checked_add(length as u64)
            .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    }
    Ok(true)
}

fn open_durable_extent_v1(
    layout: &C2AppendExtentLayoutV1,
    file: &File,
    header: &C2CarrierHeaderV1,
) -> Result<C2OpenedDurableExtentV1, C2AppendExtentRefusalV1> {
    verify_file_matches_header(file, header)?;
    let observed_header = decode_durable_page(
        file,
        2 * C2_APPEND_ALIGNMENT_BYTES_V1,
        C2_DURABLE_HEADER_PAGE_MAGIC_V1,
    )?;
    if observed_header != canonical_json_bytes(header)? {
        return Err(C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch);
    }
    let superblock = select_durable_superblock_v1(file)?;
    if superblock.header_identity != header.header_identity || superblock.role != header.role {
        return Err(C2AppendExtentRefusalV1::HeaderCorrespondenceMismatch);
    }
    if superblock.physical_next_offset > header.payload_bound {
        return Err(C2AppendExtentRefusalV1::ExtentExhausted);
    }
    let mut extent = C2OpenedDurableExtentV1 {
        file: file.try_clone()?,
        header: header.clone(),
        cursor: C2AppendCursorV1::from_verified_header(header)?,
        superblock_epoch: superblock.epoch,
        physical_next_offset: superblock.physical_next_offset,
        records: Vec::new(),
    };
    let mut cursor = extent.cursor.clone();
    let mut relative_offset = 0_u64;
    while relative_offset < superblock.physical_next_offset {
        let (record, advanced, next_offset) = decode_durable_record_at_v1(
            layout,
            &extent,
            cursor,
            relative_offset,
            superblock.physical_next_offset,
        )?;
        if extent
            .records
            .iter()
            .any(|seen| seen.operation_identity == record.operation_identity)
        {
            return Err(C2AppendExtentRefusalV1::ChangedContentCollision);
        }
        extent.records.push(record);
        cursor = advanced;
        relative_offset = next_offset;
    }
    if relative_offset != superblock.physical_next_offset
        || cursor.next_payload_offset != superblock.semantic_next_payload_offset
        || cursor.next_slot != superblock.next_slot
        || cursor.content_root != superblock.content_root
        || extent
            .records
            .last()
            .map(|record| &record.operation_identity)
            != superblock.last_operation_identity.as_ref()
        || extent.records.last().map(|record| &record.frame_identity)
            != superblock.last_frame_identity.as_ref()
    {
        return Err(C2AppendExtentRefusalV1::FrameChainMismatch);
    }
    let physical_payload_end = C2_APPEND_PAYLOAD_OFFSET_V1
        .checked_add(header.payload_bound)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let committed_end = C2_APPEND_PAYLOAD_OFFSET_V1
        .checked_add(superblock.physical_next_offset)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    if !suffix_is_zero_v1(file, committed_end, physical_payload_end)? {
        return Err(C2AppendExtentRefusalV1::TornAppend);
    }
    extent.cursor = cursor;
    Ok(extent)
}

/// Initialize the authenticated append pages in one freshly preallocated pair.
pub(crate) fn initialize_durable_append_pair_v1(
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
    b: &File,
    g: &File,
) -> Result<C2DurableAppendPairV1, C2AppendExtentRefusalV1> {
    verify_rec_30_pair_header_correspondence(layout, correspondence)?;
    Ok(C2DurableAppendPairV1 {
        layout: layout.clone(),
        correspondence: correspondence.clone(),
        b: initialize_durable_extent_v1(b, correspondence.b_header())?,
        g: initialize_durable_extent_v1(g, correspondence.g_header())?,
    })
}

/// Installation-only observed variant.  Normal production append users keep
/// using `initialize_durable_append_pair_v1`; this seam exists solely so the
/// fresh Store driver can stop between the two independently durable extent
/// initializations without moving the callback into signing APIs.
pub(crate) fn initialize_durable_append_pair_with_observer_v1<E>(
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
    b: &File,
    g: &File,
    observer: &mut impl FnMut(C2InstallationExtentInitializedV1) -> Result<(), E>,
) -> Result<C2DurableAppendPairV1, C2ObservedAppendExtentRefusalV1<E>> {
    verify_rec_30_pair_header_correspondence(layout, correspondence)
        .map_err(C2ObservedAppendExtentRefusalV1::Append)?;
    let b = initialize_durable_extent_v1(b, correspondence.b_header())
        .map_err(C2ObservedAppendExtentRefusalV1::Append)?;
    observer(C2InstallationExtentInitializedV1::BootstrapB)
        .map_err(C2ObservedAppendExtentRefusalV1::Observer)?;
    let g = initialize_durable_extent_v1(g, correspondence.g_header())
        .map_err(C2ObservedAppendExtentRefusalV1::Append)?;
    observer(C2InstallationExtentInitializedV1::GlobalRefusalG)
        .map_err(C2ObservedAppendExtentRefusalV1::Observer)?;
    Ok(C2DurableAppendPairV1 {
        layout: layout.clone(),
        correspondence: correspondence.clone(),
        b,
        g,
    })
}

/// Reopen and scan one exact authenticated B/G pair after process restart.
pub(crate) fn open_durable_append_pair_v1(
    layout: &C2AppendExtentLayoutV1,
    correspondence: &C2CarrierPairHeaderCorrespondenceV1,
    b: &File,
    g: &File,
) -> Result<C2DurableAppendPairV1, C2AppendExtentRefusalV1> {
    verify_rec_30_pair_header_correspondence(layout, correspondence)?;
    Ok(C2DurableAppendPairV1 {
        layout: layout.clone(),
        correspondence: correspondence.clone(),
        b: open_durable_extent_v1(layout, b, correspondence.b_header())?,
        g: open_durable_extent_v1(layout, g, correspondence.g_header())?,
    })
}

fn append_durable_record_v1(
    layout: &C2AppendExtentLayoutV1,
    extent: &mut C2OpenedDurableExtentV1,
    operation_identity: Sha256Digest,
    kind: C2AppendFrameKindV1,
    canonical_payload: &[u8],
) -> Result<C2DurableAppendOutcomeV1, C2AppendExtentRefusalV1> {
    if kind.role() != extent.header.role {
        return Err(C2AppendExtentRefusalV1::CrossVocabularyPlacement);
    }
    if let Some(existing) = extent
        .records
        .iter()
        .find(|record| record.operation_identity == operation_identity)
    {
        if existing.kind != kind || existing.canonical_payload != canonical_payload {
            return Err(C2AppendExtentRefusalV1::ChangedContentCollision);
        }
        return Ok(C2DurableAppendOutcomeV1 {
            disposition: C2DurableAppendDispositionV1::ExactReplay,
            role: extent.header.role,
            kind,
            operation_identity,
            frame_identity: existing.frame_identity.clone(),
            resulting_root: existing.resulting_root.clone(),
            slot: existing.slot,
        });
    }

    let (frame, advanced) =
        append_exact_frame_v1(layout, extent.cursor.clone(), kind, canonical_payload)?;
    let record = encode_durable_record(&frame, kind, &operation_identity, canonical_payload)?;
    let physical_next_offset = extent
        .physical_next_offset
        .checked_add(record.len() as u64)
        .filter(|end| *end <= extent.header.payload_bound)
        .ok_or(C2AppendExtentRefusalV1::ExtentExhausted)?;
    let absolute = C2_APPEND_PAYLOAD_OFFSET_V1
        .checked_add(extent.physical_next_offset)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    write_all_at(&extent.file, absolute, &record)?;
    extent.file.sync_data()?;

    let next_epoch = extent
        .superblock_epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= IJSON_SAFE_U64)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    let superblock = C2DurableAppendSuperblockV1 {
        schema: "nq.c2_durable_append_superblock.v1".to_owned(),
        schema_version: 1,
        header_identity: extent.header.header_identity.clone(),
        role: extent.header.role,
        epoch: next_epoch,
        physical_next_offset,
        semantic_next_payload_offset: advanced.next_payload_offset,
        next_slot: advanced.next_slot,
        content_root: advanced.content_root.clone(),
        last_operation_identity: Some(operation_identity.clone()),
        last_frame_identity: Some(frame.frame_identity.clone()),
    };
    let page = encode_durable_page(C2_DURABLE_SUPERBLOCK_MAGIC_V1, &superblock)?;
    let superblock_offset = (next_epoch % 2)
        .checked_mul(C2_APPEND_ALIGNMENT_BYTES_V1)
        .ok_or(C2AppendExtentRefusalV1::ArithmeticOverflow)?;
    write_all_at(&extent.file, superblock_offset, &page)?;
    extent.file.sync_data()?;

    extent.cursor = advanced;
    extent.superblock_epoch = next_epoch;
    extent.physical_next_offset = physical_next_offset;
    extent.records.push(C2DurableRecordSummaryV1 {
        kind,
        operation_identity: operation_identity.clone(),
        canonical_payload: canonical_payload.to_vec(),
        frame_identity: frame.frame_identity.clone(),
        resulting_root: frame.resulting_root.clone(),
        slot: frame.slot,
    });
    Ok(C2DurableAppendOutcomeV1 {
        disposition: C2DurableAppendDispositionV1::Appended,
        role: extent.header.role,
        kind,
        operation_identity,
        frame_identity: frame.frame_identity,
        resulting_root: frame.resulting_root,
        slot: frame.slot,
    })
}

impl C2DurableAppendPairV1 {
    /// Append through the role selected by the closed frame vocabulary.
    pub(crate) fn append_or_replay_exact(
        &mut self,
        operation_identity: Sha256Digest,
        kind: C2AppendFrameKindV1,
        canonical_payload: &[u8],
    ) -> Result<C2DurableAppendOutcomeV1, C2AppendExtentRefusalV1> {
        verify_rec_30_pair_header_correspondence(&self.layout, &self.correspondence)?;
        match kind.role() {
            C2AppendExtentRoleV1::BootstrapB => append_durable_record_v1(
                &self.layout,
                &mut self.b,
                operation_identity,
                kind,
                canonical_payload,
            ),
            C2AppendExtentRoleV1::GlobalRefusalG => append_durable_record_v1(
                &self.layout,
                &mut self.g,
                operation_identity,
                kind,
                canonical_payload,
            ),
        }
    }

    pub(crate) fn pair_identity(&self) -> &Sha256Digest {
        self.correspondence.pair_identity()
    }

    /// Exact Store occurrence authenticated by both retained carrier headers.
    pub(crate) fn occurrence_id(&self) -> &str {
        &self.correspondence.pair.occurrence_id
    }

    /// Exact physical Store generation authenticated by both retained
    /// carrier headers.  It is inert evidence, not signer standing.
    pub(crate) fn physical_store_generation_identity(&self) -> &Sha256Digest {
        &self.correspondence.pair.physical_store_generation_identity
    }

    /// Exact qualified backend profile authenticated by both retained extent
    /// headers.  This is evidence for same-snapshot restore/quarantine
    /// correspondence; it grants no append or signer authority.
    pub(crate) fn qualified_backend_profile_identity(&self) -> &Sha256Digest {
        &self.correspondence.pair.qualified_backend_profile_identity
    }

    pub(crate) fn current_snapshot(&self) -> C2DurableAppendPairSnapshotV1 {
        C2DurableAppendPairSnapshotV1 {
            b_content_root: self.b.cursor.content_root.clone(),
            b_next_payload_offset: self.b.cursor.next_payload_offset,
            b_next_slot: self.b.cursor.next_slot,
            g_content_root: self.g.cursor.content_root.clone(),
            g_next_payload_offset: self.g.cursor.next_payload_offset,
            g_next_slot: self.g.cursor.next_slot,
        }
    }

    /// Enumerate only already-authenticated records for the closed semantic
    /// verifier.  Returned values borrow this process-local pair and cannot be
    /// used to append, replay, or reconstruct signer standing.
    pub(crate) fn authenticated_records(&self) -> impl Iterator<Item = C2DurableRecordViewV1<'_>> {
        self.b
            .records
            .iter()
            .map(|record| C2DurableRecordViewV1 {
                role: C2AppendExtentRoleV1::BootstrapB,
                kind: record.kind,
                slot: record.slot,
                operation_identity: &record.operation_identity,
                canonical_payload: &record.canonical_payload,
                frame_identity: &record.frame_identity,
                resulting_root: &record.resulting_root,
            })
            .chain(self.g.records.iter().map(|record| C2DurableRecordViewV1 {
                role: C2AppendExtentRoleV1::GlobalRefusalG,
                kind: record.kind,
                slot: record.slot,
                operation_identity: &record.operation_identity,
                canonical_payload: &record.canonical_payload,
                frame_identity: &record.frame_identity,
                resulting_root: &record.resulting_root,
            }))
    }
}

/// Construct the one-way lock backlink from the exact physical MSG-03 B
/// genesis outcome. A semantic message identity or later B frame cannot
/// satisfy this boundary.
pub(crate) fn construct_lock_backlink_from_durable_bootstrap_v1(
    physical_store_generation_identity: Sha256Digest,
    outcome: &C2DurableAppendOutcomeV1,
) -> Result<C2LockBacklinkV1, C2AppendExtentRefusalV1> {
    if outcome.disposition != C2DurableAppendDispositionV1::Appended
        && outcome.disposition != C2DurableAppendDispositionV1::ExactReplay
    {
        return Err(C2AppendExtentRefusalV1::BacklinkMismatch);
    }
    if outcome.role != C2AppendExtentRoleV1::BootstrapB
        || outcome.kind != C2AppendFrameKindV1::StoreGenerationBootstrap
        || outcome.slot != 0
    {
        return Err(C2AppendExtentRefusalV1::BacklinkMismatch);
    }
    let backlink_identity = semantic_digest(&BacklinkPreimage {
        domain: "nq.c2.lock_b_genesis_backlink.identity.v1",
        schema: "nq.c2_lock_b_genesis_backlink.v1",
        physical_store_generation_identity: &physical_store_generation_identity,
        b_genesis_frame_identity: &outcome.frame_identity,
    })?;
    Ok(C2LockBacklinkV1 {
        schema: "nq.c2_lock_b_genesis_backlink.v1",
        physical_store_generation_identity,
        b_genesis_frame_identity: outcome.frame_identity.clone(),
        backlink_identity,
    })
}

/// Construct the one-way lock backlink after the B genesis identity exists.
pub fn construct_lock_backlink_v1(
    physical_store_generation_identity: Sha256Digest,
    b_genesis_frame: &C2AppendFrameV1,
) -> Result<C2LockBacklinkV1, C2AppendExtentRefusalV1> {
    if b_genesis_frame.role != C2AppendExtentRoleV1::BootstrapB
        || b_genesis_frame.kind != C2AppendFrameKindV1::StoreGenerationBootstrap
        || b_genesis_frame.slot != 0
    {
        return Err(C2AppendExtentRefusalV1::BacklinkMismatch);
    }
    let backlink_identity = semantic_digest(&BacklinkPreimage {
        domain: "nq.c2.lock_b_genesis_backlink.identity.v1",
        schema: "nq.c2_lock_b_genesis_backlink.v1",
        physical_store_generation_identity: &physical_store_generation_identity,
        b_genesis_frame_identity: &b_genesis_frame.frame_identity,
    })?;
    Ok(C2LockBacklinkV1 {
        schema: "nq.c2_lock_b_genesis_backlink.v1",
        physical_store_generation_identity,
        b_genesis_frame_identity: b_genesis_frame.frame_identity.clone(),
        backlink_identity,
    })
}

/// Verify the backlink without allowing a reciprocal/self-authenticating pair.
pub fn verify_lock_backlink_v1(
    backlink: &C2LockBacklinkV1,
    physical_store_generation_identity: &Sha256Digest,
    b_genesis_frame: &C2AppendFrameV1,
) -> Result<(), C2AppendExtentRefusalV1> {
    let expected =
        construct_lock_backlink_v1(physical_store_generation_identity.clone(), b_genesis_frame)?;
    if &expected == backlink {
        Ok(())
    } else {
        Err(C2AppendExtentRefusalV1::BacklinkMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::path::Path;
    use std::process::Command;
    use tempfile::NamedTempFile;

    const CRASH_CHILD_MODE: &str = "NQ_C2_APPEND_CRASH_CHILD_MODE";
    const CRASH_CHILD_B_PATH: &str = "NQ_C2_APPEND_CRASH_CHILD_B_PATH";
    const CRASH_CHILD_G_PATH: &str = "NQ_C2_APPEND_CRASH_CHILD_G_PATH";

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn layout() -> C2AppendExtentLayoutV1 {
        construct_wu_03_immutable_wu_append_extents_b_g_carrier(32_768, 16_384, 16, 1024).unwrap()
    }

    fn facts(identity: char, inode: u64, length: u64) -> C2CarrierFileFactsV1 {
        C2CarrierFileFactsV1 {
            file_identity: digest(identity),
            device: 7,
            inode,
            owner_uid: 1000,
            owner_gid: 1000,
            mode: 0o600,
            physical_length: length,
            link_count: 1,
        }
    }

    fn correspondence() -> (C2AppendExtentLayoutV1, C2CarrierPairHeaderCorrespondenceV1) {
        let layout = layout();
        let pair = C2CarrierPairInputV1 {
            occurrence_id: "store:one".into(),
            physical_store_generation_identity: digest('a'),
            qualified_backend_profile_identity: digest('b'),
            b_file: facts('c', 11, layout.b_append_extent_length()),
            g_file: facts('d', 12, layout.g_append_extent_length()),
        };
        let headers = construct_rec_30_pair_header_correspondence(&layout, pair).unwrap();
        (layout, headers)
    }

    fn physical_facts(identity: char, file: &File) -> C2CarrierFileFactsV1 {
        let metadata = file.metadata().unwrap();
        C2CarrierFileFactsV1 {
            file_identity: digest(identity),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mode: metadata.permissions().mode() & 0o7777,
            physical_length: metadata.len(),
            link_count: metadata.nlink(),
        }
    }

    fn physical_correspondence() -> (
        C2AppendExtentLayoutV1,
        C2CarrierPairHeaderCorrespondenceV1,
        NamedTempFile,
        NamedTempFile,
    ) {
        let layout = layout();
        let b = NamedTempFile::new().unwrap();
        let g = NamedTempFile::new().unwrap();
        b.as_file()
            .set_len(layout.b_append_extent_length())
            .unwrap();
        g.as_file()
            .set_len(layout.g_append_extent_length())
            .unwrap();
        std::fs::set_permissions(b.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(g.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let pair = C2CarrierPairInputV1 {
            occurrence_id: "store:durable".into(),
            physical_store_generation_identity: digest('a'),
            qualified_backend_profile_identity: digest('b'),
            b_file: physical_facts('c', b.as_file()),
            g_file: physical_facts('d', g.as_file()),
        };
        let headers = construct_rec_30_pair_header_correspondence(&layout, pair).unwrap();
        (layout, headers, b, g)
    }

    fn correspondence_for_open_files(
        b: &File,
        g: &File,
    ) -> (C2AppendExtentLayoutV1, C2CarrierPairHeaderCorrespondenceV1) {
        let layout = layout();
        let pair = C2CarrierPairInputV1 {
            occurrence_id: "store:durable".into(),
            physical_store_generation_identity: digest('a'),
            qualified_backend_profile_identity: digest('b'),
            b_file: physical_facts('c', b),
            g_file: physical_facts('d', g),
        };
        let headers = construct_rec_30_pair_header_correspondence(&layout, pair).unwrap();
        (layout, headers)
    }

    fn run_crash_child(mode: &str, b: &Path, g: &Path) {
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("append_extent::tests::c2_durable_append_crash_child_role")
            .arg("--nocapture")
            .env(CRASH_CHILD_MODE, mode)
            .env(CRASH_CHILD_B_PATH, b)
            .env(CRASH_CHILD_G_PATH, g)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "crash child {mode} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn c2_durable_append_crash_child_role() {
        let Ok(mode) = std::env::var(CRASH_CHILD_MODE) else {
            return;
        };
        let b_path = std::env::var_os(CRASH_CHILD_B_PATH).unwrap();
        let g_path = std::env::var_os(CRASH_CHILD_G_PATH).unwrap();
        let b = OpenOptions::new()
            .read(true)
            .write(true)
            .open(b_path)
            .unwrap();
        let g = OpenOptions::new()
            .read(true)
            .write(true)
            .open(g_path)
            .unwrap();
        let (layout, headers) = correspondence_for_open_files(&b, &g);

        match mode.as_str() {
            "append-then-exit" => {
                let mut pair = open_durable_append_pair_v1(&layout, &headers, &b, &g).unwrap();
                let outcome = pair
                    .append_or_replay_exact(
                        digest('e'),
                        C2AppendFrameKindV1::StoreGenerationBootstrap,
                        br#"{"exact":"process-boundary"}"#,
                    )
                    .unwrap();
                assert_eq!(outcome.disposition, C2DurableAppendDispositionV1::Appended);
            }
            "changed-content-then-exit" => {
                let mut pair = open_durable_append_pair_v1(&layout, &headers, &b, &g).unwrap();
                assert!(matches!(
                    pair.append_or_replay_exact(
                        digest('e'),
                        C2AppendFrameKindV1::StoreGenerationBootstrap,
                        br#"{"exact":"substituted"}"#,
                    ),
                    Err(C2AppendExtentRefusalV1::ChangedContentCollision)
                ));
            }
            "durable-uncommitted-tail-then-exit" => {
                write_all_at(&b, C2_APPEND_PAYLOAD_OFFSET_V1, b"torn").unwrap();
                b.sync_data().unwrap();
            }
            other => panic!("unknown crash child mode: {other}"),
        }

        // Deliberately bypass the test harness and all Rust destructors.  The
        // parent process is the only observer of restart behavior.
        std::process::exit(0);
    }

    #[test]
    fn durable_append_real_process_exit_reopens_or_refuses_exactly() {
        let (layout, headers, b, g) = physical_correspondence();
        initialize_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file()).unwrap();

        run_crash_child("append-then-exit", b.path(), g.path());
        let mut reopened =
            open_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file()).unwrap();
        let replay = reopened
            .append_or_replay_exact(
                digest('e'),
                C2AppendFrameKindV1::StoreGenerationBootstrap,
                br#"{"exact":"process-boundary"}"#,
            )
            .unwrap();
        assert_eq!(
            replay.disposition,
            C2DurableAppendDispositionV1::ExactReplay
        );
        drop(reopened);

        run_crash_child("changed-content-then-exit", b.path(), g.path());
        let mut after_collision =
            open_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file()).unwrap();
        assert_eq!(
            after_collision
                .append_or_replay_exact(
                    digest('e'),
                    C2AppendFrameKindV1::StoreGenerationBootstrap,
                    br#"{"exact":"process-boundary"}"#,
                )
                .unwrap()
                .disposition,
            C2DurableAppendDispositionV1::ExactReplay
        );

        let (torn_layout, torn_headers, torn_b, torn_g) = physical_correspondence();
        initialize_durable_append_pair_v1(
            &torn_layout,
            &torn_headers,
            torn_b.as_file(),
            torn_g.as_file(),
        )
        .unwrap();
        run_crash_child(
            "durable-uncommitted-tail-then-exit",
            torn_b.path(),
            torn_g.path(),
        );
        assert!(matches!(
            open_durable_append_pair_v1(
                &torn_layout,
                &torn_headers,
                torn_b.as_file(),
                torn_g.as_file(),
            ),
            Err(C2AppendExtentRefusalV1::TornAppend)
        ));
    }

    #[test]
    fn exact_geometry_counts_lock_once_and_rejects_one_over() {
        let layout = layout();
        assert_eq!(layout.b_append_extent_length(), 45_056);
        assert_eq!(layout.b_aggregate_length_with_lock(), 49_152);
        assert_eq!(layout.g_append_extent_length(), 28_672);
        assert!(construct_n_85_extent_b_g_formulas_physical_layout_no(u64::MAX, 1, 1, 1).is_err());
        assert!(construct_n_85_extent_b_g_formulas_physical_layout_no(1, 1023, 1, 1024).is_err());
    }

    #[test]
    fn headers_are_role_distinct_but_share_exact_pair_coordinates() {
        let (layout, headers) = correspondence();
        verify_rec_30_pair_header_correspondence(&layout, &headers).unwrap();
        assert_ne!(
            headers.b_header().header_identity,
            headers.g_header().header_identity
        );
        assert_eq!(
            headers.b_header().carrier_pair_identity,
            headers.g_header().carrier_pair_identity
        );
    }

    #[test]
    fn durable_pair_append_replay_and_reopen_preserve_exact_bytes() {
        let (layout, headers, b, g) = physical_correspondence();
        let operation = digest('e');
        let payload = br#"{"exact":"bootstrap"}"#;
        let first = initialize_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file())
            .unwrap()
            .append_or_replay_exact(
                operation.clone(),
                C2AppendFrameKindV1::StoreGenerationBootstrap,
                payload,
            )
            .unwrap();
        assert_eq!(first.disposition, C2DurableAppendDispositionV1::Appended);

        let mut reopened =
            open_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file()).unwrap();
        let replay = reopened
            .append_or_replay_exact(
                operation.clone(),
                C2AppendFrameKindV1::StoreGenerationBootstrap,
                payload,
            )
            .unwrap();
        assert_eq!(
            replay.disposition,
            C2DurableAppendDispositionV1::ExactReplay
        );
        assert_eq!(replay.frame_identity, first.frame_identity);
        assert!(matches!(
            reopened.append_or_replay_exact(
                operation.clone(),
                C2AppendFrameKindV1::StoreGenerationBootstrap,
                br#"{"exact":"changed"}"#,
            ),
            Err(C2AppendExtentRefusalV1::ChangedContentCollision)
        ));
        // The hostile changed-content attempt is exact no-write: the original
        // outer occurrence remains the sole replayable physical record.
        let after_collision = reopened
            .append_or_replay_exact(
                operation,
                C2AppendFrameKindV1::StoreGenerationBootstrap,
                payload,
            )
            .unwrap();
        assert_eq!(
            after_collision.disposition,
            C2DurableAppendDispositionV1::ExactReplay
        );
        assert_eq!(after_collision.frame_identity, first.frame_identity);
    }

    #[test]
    fn installation_observer_can_stop_after_durable_b_before_g_initialization() {
        let (layout, headers, b, g) = physical_correspondence();
        let mut observed = Vec::new();
        let result = initialize_durable_append_pair_with_observer_v1(
            &layout,
            &headers,
            b.as_file(),
            g.as_file(),
            &mut |effect| {
                observed.push(effect);
                if effect == C2InstallationExtentInitializedV1::BootstrapB {
                    Err("stop after B")
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(
            result,
            Err(C2ObservedAppendExtentRefusalV1::Observer("stop after B"))
        ));
        assert_eq!(
            observed,
            vec![C2InstallationExtentInitializedV1::BootstrapB]
        );
        assert!(open_durable_extent_v1(&layout, b.as_file(), headers.b_header()).is_ok());
        assert!(matches!(
            open_durable_extent_v1(&layout, g.as_file(), headers.g_header()),
            Err(C2AppendExtentRefusalV1::DurableCodecMalformed)
        ));
    }

    #[test]
    fn durable_pair_keeps_global_refusal_in_g_and_detects_uncommitted_tail() {
        let (layout, headers, b, g) = physical_correspondence();
        let mut pair =
            initialize_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file()).unwrap();
        let refusal = pair
            .append_or_replay_exact(
                digest('f'),
                C2AppendFrameKindV1::GlobalRefusal,
                br#"{"refusal":"closed"}"#,
            )
            .unwrap();
        assert_eq!(refusal.role, C2AppendExtentRoleV1::GlobalRefusalG);
        drop(pair);

        write_all_at(b.as_file(), C2_APPEND_PAYLOAD_OFFSET_V1, b"torn").unwrap();
        b.as_file().sync_data().unwrap();
        assert!(matches!(
            open_durable_append_pair_v1(&layout, &headers, b.as_file(), g.as_file()),
            Err(C2AppendExtentRefusalV1::TornAppend)
        ));
    }

    #[test]
    fn aliases_and_cross_vocabularies_refuse() {
        let layout = layout();
        let shared = facts('c', 11, layout.b_append_extent_length());
        let pair = C2CarrierPairInputV1 {
            occurrence_id: "store:one".into(),
            physical_store_generation_identity: digest('a'),
            qualified_backend_profile_identity: digest('b'),
            b_file: shared.clone(),
            g_file: C2CarrierFileFactsV1 {
                physical_length: layout.g_append_extent_length(),
                ..shared
            },
        };
        assert!(matches!(
            construct_n_86_headers_bind_common_pair_profile_occurrence_generation(&layout, pair),
            Err(C2AppendExtentRefusalV1::CarrierPairAliasOrDeviceMismatch)
        ));

        let (_, headers) = correspondence();
        let cursor = C2AppendCursorV1::from_verified_header(headers.g_header()).unwrap();
        assert!(matches!(
            append_exact_frame_v1(&layout, cursor, C2AppendFrameKindV1::KeyEnrollment, b"{}",),
            Err(C2AppendExtentRefusalV1::CrossVocabularyPlacement)
        ));
    }

    #[test]
    fn frame_chain_is_adjacent_retain_only_and_backlink_is_genesis_only() {
        let (layout, headers) = correspondence();
        let cursor = C2AppendCursorV1::from_verified_header(headers.b_header()).unwrap();
        let (genesis, cursor) = append_exact_frame_v1(
            &layout,
            cursor,
            C2AppendFrameKindV1::StoreGenerationBootstrap,
            br#"{"schema":"bootstrap"}"#,
        )
        .unwrap();
        let backlink = construct_lock_backlink_v1(digest('a'), &genesis).unwrap();
        verify_lock_backlink_v1(&backlink, &digest('a'), &genesis).unwrap();
        let (second, _) = append_exact_frame_v1(
            &layout,
            cursor,
            C2AppendFrameKindV1::ActiveStorePolicy,
            br#"{"schema":"policy"}"#,
        )
        .unwrap();
        assert!(construct_lock_backlink_v1(digest('a'), &second).is_err());
    }
}
