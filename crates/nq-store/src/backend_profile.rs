//! Candidate-bound C2 backend profile and cycle-free implementation manifest.
//!
//! Decoding and identity computation are implementation hooks only. The
//! candidate-tree-pinned JSON assets and production qualification result do
//! not exist under implementation authorization.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PROFILE_SCHEMA_V1: &str = "nq.c2_qualified_backend_profile.v1";
const PROFILE_DOMAIN_V1: &str = "nq.c2.qualified_backend_profile.identity.v1";
const MANIFEST_SCHEMA_V1: &str = "nq.c2_backend_implementation_manifest.v1";
const MANIFEST_DOMAIN_V1: &str = "nq.c2.backend_implementation_manifest.identity.v1";
const SOLE_BACKEND_V1: &str = "linux_posix_fallocate_regular_file_v1";

/// Closed cycle-free manifest bytes. The manifest contains no own identity,
/// profile identity, certificate identity, commit, or generated output whose
/// preimage would make its digest cyclic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2BackendImplementationManifestV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    contract_schema_version: String,
    source_blobs: BTreeMap<String, Sha256Digest>,
    build_inputs: BTreeMap<String, Sha256Digest>,
    #[serde(skip)]
    canonical_bytes: Vec<u8>,
    #[serde(skip)]
    identity: Option<Sha256Digest>,
}

impl C2BackendImplementationManifestV1 {
    /// Computed semantic identity.
    #[must_use]
    pub fn identity(&self) -> &Sha256Digest {
        self.identity
            .as_ref()
            .expect("decoder establishes identity")
    }

    /// Canonical candidate bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Exact closed qualified-backend profile bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct C2QualifiedBackendProfileV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    backend: String,
    implementation_manifest_identity: Sha256Digest,
    contract_schema_version: String,
    toolchains: BTreeSet<String>,
    targets: BTreeSet<String>,
    abis: BTreeSet<String>,
    syscalls: BTreeSet<String>,
    kernel_predicate: String,
    filesystem_predicate: String,
    mount_option_predicate: String,
    device_topology_predicate: String,
    allocation_predicate: String,
    sync_predicate: String,
    directory_sync_predicate: String,
    descriptor_reopen_predicate: String,
    correspondence_predicate: String,
    permitted_variability: BTreeSet<String>,
    #[serde(skip)]
    canonical_bytes: Vec<u8>,
    #[serde(skip)]
    identity: Option<Sha256Digest>,
}

impl C2QualifiedBackendProfileV1 {
    /// Candidate-bound profile identity. Computing this is not qualification.
    #[must_use]
    pub fn identity(&self) -> &Sha256Digest {
        self.identity
            .as_ref()
            .expect("decoder establishes identity")
    }

    /// Exact manifest named by this profile.
    #[must_use]
    pub const fn implementation_manifest_identity(&self) -> &Sha256Digest {
        &self.implementation_manifest_identity
    }

    /// Sole closed backend name.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }
}

/// Exact decode or correspondence refusal.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BackendProfileRefusalV1 {
    /// JSON was noncanonical, malformed, or had unknown fields.
    #[error("backend profile/manifest bytes are malformed or noncanonical")]
    MalformedOrNoncanonical,
    /// A closed schema/domain/backend value was substituted.
    #[error("backend profile/manifest closed constant was substituted")]
    SubstitutedClosedConstant,
    /// Manifest is empty, cyclic, or names a generated/self-containing input.
    #[error("backend implementation manifest is incomplete or cyclic")]
    IncompleteOrCyclicManifest,
    /// Profile omits a required closed predicate/input class.
    #[error("backend profile is incomplete")]
    IncompleteProfile,
    /// Profile names another implementation manifest.
    #[error("backend profile/manifest identity correspondence mismatch")]
    ManifestCrossPair,
}

fn domain_identity(domain: &str, canonical: &[u8]) -> Sha256Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 1 + canonical.len());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(canonical);
    sha256_bytes(&preimage)
}

fn exact_canonical<T>(bytes: &[u8]) -> Result<T, BackendProfileRefusalV1>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| BackendProfileRefusalV1::MalformedOrNoncanonical)?;
    if canonical_json_bytes(&value).map_err(|_| BackendProfileRefusalV1::MalformedOrNoncanonical)?
        != bytes
    {
        return Err(BackendProfileRefusalV1::MalformedOrNoncanonical);
    }
    Ok(value)
}

fn prohibited_manifest_member(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    [
        "qualified_backend_profile",
        "implementation_manifest.v1.json",
        "certificate",
        "registry",
        "target/",
        "generated",
    ]
    .iter()
    .any(|token| normalized.contains(token))
}

/// N-28 decoder for exact cycle-free manifest bytes.
pub fn decode_n_28_implementation_manifest(
    bytes: &[u8],
) -> Result<C2BackendImplementationManifestV1, BackendProfileRefusalV1> {
    let mut manifest: C2BackendImplementationManifestV1 = exact_canonical(bytes)?;
    if manifest.schema != MANIFEST_SCHEMA_V1
        || manifest.schema_version != 1
        || manifest.identity_domain != MANIFEST_DOMAIN_V1
    {
        return Err(BackendProfileRefusalV1::SubstitutedClosedConstant);
    }
    verify_n_28_acyclic_manifest(&manifest)?;
    manifest.canonical_bytes = bytes.to_vec();
    manifest.identity = Some(domain_identity(MANIFEST_DOMAIN_V1, bytes));
    Ok(manifest)
}

/// N-28 rejects missing source/build classes and self-containing members.
pub fn verify_n_28_acyclic_manifest(
    manifest: &C2BackendImplementationManifestV1,
) -> Result<(), BackendProfileRefusalV1> {
    if manifest.contract_schema_version.is_empty()
        || manifest.source_blobs.is_empty()
        || manifest.build_inputs.is_empty()
        || manifest
            .source_blobs
            .keys()
            .chain(manifest.build_inputs.keys())
            .any(|path| path.is_empty() || prohibited_manifest_member(path))
    {
        return Err(BackendProfileRefusalV1::IncompleteOrCyclicManifest);
    }
    Ok(())
}

/// N-26 decoder for exact canonical profile bytes.
pub fn decode_n_26_qualified_profile(
    bytes: &[u8],
) -> Result<C2QualifiedBackendProfileV1, BackendProfileRefusalV1> {
    let mut profile: C2QualifiedBackendProfileV1 = exact_canonical(bytes)?;
    if profile.schema != PROFILE_SCHEMA_V1
        || profile.schema_version != 1
        || profile.identity_domain != PROFILE_DOMAIN_V1
        || profile.backend != SOLE_BACKEND_V1
    {
        return Err(BackendProfileRefusalV1::SubstitutedClosedConstant);
    }
    verify_profile_complete(&profile)?;
    profile.canonical_bytes = bytes.to_vec();
    profile.identity = Some(domain_identity(PROFILE_DOMAIN_V1, bytes));
    Ok(profile)
}

fn verify_profile_complete(
    profile: &C2QualifiedBackendProfileV1,
) -> Result<(), BackendProfileRefusalV1> {
    let scalar_predicates = [
        &profile.contract_schema_version,
        &profile.kernel_predicate,
        &profile.filesystem_predicate,
        &profile.mount_option_predicate,
        &profile.device_topology_predicate,
        &profile.allocation_predicate,
        &profile.sync_predicate,
        &profile.directory_sync_predicate,
        &profile.descriptor_reopen_predicate,
        &profile.correspondence_predicate,
    ];
    if scalar_predicates.iter().any(|value| value.is_empty())
        || profile.toolchains.is_empty()
        || profile.targets.is_empty()
        || profile.abis.is_empty()
        || profile.syscalls.is_empty()
        || profile.permitted_variability.is_empty()
    {
        return Err(BackendProfileRefusalV1::IncompleteProfile);
    }
    Ok(())
}

/// N-26 verifies the recomputed profile identity.
pub fn verify_n_26_exact_profile_identity(
    profile: &C2QualifiedBackendProfileV1,
) -> Result<(), BackendProfileRefusalV1> {
    verify_profile_complete(profile)?;
    let expected = domain_identity(PROFILE_DOMAIN_V1, &profile.canonical_bytes);
    if profile.identity.as_ref() != Some(&expected) {
        return Err(BackendProfileRefusalV1::MalformedOrNoncanonical);
    }
    Ok(())
}

/// WU-05 binds one exact manifest into one exact profile.
pub fn construct_wu_05_immutable_wu_backend_profile_manifest_backend_identity(
    profile_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<C2QualifiedBackendProfileV1, BackendProfileRefusalV1> {
    let manifest = decode_n_28_implementation_manifest(manifest_bytes)?;
    let profile = decode_n_26_qualified_profile(profile_bytes)?;
    if profile.implementation_manifest_identity() != manifest.identity() {
        return Err(BackendProfileRefusalV1::ManifestCrossPair);
    }
    Ok(profile)
}

/// WU-05 verifier recomputes both candidate-bound identities.
pub fn verify_wu_05_immutable_wu_backend_profile_manifest_backend_identity(
    profile: &C2QualifiedBackendProfileV1,
    manifest: &C2BackendImplementationManifestV1,
) -> Result<(), BackendProfileRefusalV1> {
    verify_n_26_exact_profile_identity(profile)?;
    verify_n_28_acyclic_manifest(manifest)?;
    if profile.implementation_manifest_identity() != manifest.identity() {
        return Err(BackendProfileRefusalV1::ManifestCrossPair);
    }
    Ok(())
}

/// REC-13 decoder alias.
pub fn decode_rec_13_profile(
    bytes: &[u8],
) -> Result<C2QualifiedBackendProfileV1, BackendProfileRefusalV1> {
    decode_n_26_qualified_profile(bytes)
}

/// REC-13 verifier alias.
pub fn verify_rec_13_profile(
    profile: &C2QualifiedBackendProfileV1,
) -> Result<(), BackendProfileRefusalV1> {
    verify_n_26_exact_profile_identity(profile)
}

/// REC-14 decoder alias.
pub fn decode_rec_14_manifest(
    bytes: &[u8],
) -> Result<C2BackendImplementationManifestV1, BackendProfileRefusalV1> {
    decode_n_28_implementation_manifest(bytes)
}

/// REC-14 verifier alias.
pub fn verify_rec_14_manifest(
    manifest: &C2BackendImplementationManifestV1,
) -> Result<(), BackendProfileRefusalV1> {
    verify_n_28_acyclic_manifest(manifest)
}

/// AM-02 constructor alias.
pub fn construct_am_02_crosswalk_am_charter_bind_qualified_backend_profile(
    profile_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<C2QualifiedBackendProfileV1, BackendProfileRefusalV1> {
    construct_wu_05_immutable_wu_backend_profile_manifest_backend_identity(
        profile_bytes,
        manifest_bytes,
    )
}

/// AM-02 verifier alias.
pub fn verify_am_02_crosswalk_am_charter_bind_qualified_backend_profile(
    profile: &C2QualifiedBackendProfileV1,
    manifest: &C2BackendImplementationManifestV1,
) -> Result<(), BackendProfileRefusalV1> {
    verify_wu_05_immutable_wu_backend_profile_manifest_backend_identity(profile, manifest)
}

/// SEAM-09 construct only a cycle-free manifest.
pub fn construct_seam_09_immutable_seam_profile_cycle_profile_implementation_manifest(
    bytes: &[u8],
) -> Result<C2BackendImplementationManifestV1, BackendProfileRefusalV1> {
    decode_n_28_implementation_manifest(bytes)
}

/// SEAM-09 verifier alias.
pub fn verify_seam_09_immutable_seam_profile_cycle_profile_implementation_manifest(
    manifest: &C2BackendImplementationManifestV1,
) -> Result<(), BackendProfileRefusalV1> {
    verify_n_28_acyclic_manifest(manifest)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn manifest_bytes() -> Vec<u8> {
        canonical_json_bytes(&json!({
            "build_inputs": {"rust-toolchain.toml": format!("sha256:{}", "2".repeat(64))},
            "contract_schema_version": "nq.c2.backend.contract.v1",
            "identity_domain": MANIFEST_DOMAIN_V1,
            "schema": MANIFEST_SCHEMA_V1,
            "schema_version": 1,
            "source_blobs": {"crates/nq-store/src/capacity_backend.rs": format!("sha256:{}", "1".repeat(64))}
        }))
        .unwrap()
    }

    fn profile_bytes(manifest: &Sha256Digest) -> Vec<u8> {
        canonical_json_bytes(&json!({
            "abis": ["linux-gnu"],
            "allocation_predicate": "posix_fallocate exact length",
            "backend": SOLE_BACKEND_V1,
            "contract_schema_version": "nq.c2.backend.contract.v1",
            "correspondence_predicate": "same retained descriptors",
            "descriptor_reopen_predicate": "nofollow exact inode",
            "device_topology_predicate": "single local block device",
            "directory_sync_predicate": "fsync root directory",
            "filesystem_predicate": "ext4 regular files",
            "identity_domain": PROFILE_DOMAIN_V1,
            "implementation_manifest_identity": manifest,
            "kernel_predicate": "qualified Linux kernel range",
            "mount_option_predicate": "qualified local mount",
            "permitted_variability": ["kernel patch level within qualified range"],
            "schema": PROFILE_SCHEMA_V1,
            "schema_version": 1,
            "sync_predicate": "fdatasync then reopen",
            "syscalls": ["fdatasync", "fstat", "fsync", "openat", "posix_fallocate"],
            "targets": ["x86_64-unknown-linux-gnu"],
            "toolchains": ["pinned-rust-toolchain"]
        }))
        .unwrap()
    }

    #[test]
    fn profile_binds_exact_cycle_free_manifest() {
        let manifest = decode_n_28_implementation_manifest(&manifest_bytes()).unwrap();
        let profile = construct_wu_05_immutable_wu_backend_profile_manifest_backend_identity(
            &profile_bytes(manifest.identity()),
            &manifest_bytes(),
        )
        .unwrap();
        assert_eq!(profile.backend(), SOLE_BACKEND_V1);
    }

    #[test]
    fn manifest_self_member_and_cross_pair_refuse() {
        let cyclic = canonical_json_bytes(&json!({
            "build_inputs": {"rust-toolchain.toml": format!("sha256:{}", "2".repeat(64))},
            "contract_schema_version": "v1",
            "identity_domain": MANIFEST_DOMAIN_V1,
            "schema": MANIFEST_SCHEMA_V1,
            "schema_version": 1,
            "source_blobs": {"nq.c2_backend_implementation_manifest.v1.json": format!("sha256:{}", "1".repeat(64))}
        }))
        .unwrap();
        assert_eq!(
            decode_n_28_implementation_manifest(&cyclic),
            Err(BackendProfileRefusalV1::IncompleteOrCyclicManifest)
        );
    }
}
