//! Fixed C2 bootstrap (`B`) and global-refusal (`G`) append extents.
//!
//! The types in this module are evidence about fixed physical carriers.  They
//! do not grant writer standing, signer standing, capacity, or a Store writer
//! session.  In particular, a header is accepted only as one member of an
//! exact, non-recursively identified B/G pair.

use nq_protocol::{CanonicalizationError, Sha256Digest, semantic_digest, sha256_bytes};
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
    const fn role(self) -> C2AppendExtentRoleV1 {
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
