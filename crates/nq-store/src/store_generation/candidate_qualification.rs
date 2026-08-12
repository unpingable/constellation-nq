//! Authenticated candidate evidence for the live C2 Store lifecycle.
//!
//! Qualification authority is deliberately distinct from runtime A1/A2.  The
//! production verifier reads one canonical Ed25519 qualification trust root
//! from a fixed, root-owned path, authenticates one canonical candidate
//! certificate, and measures the running Linux image itself.  Certificate and
//! trust-root bytes remain inert evidence; only the sealed result returned to
//! `c2_lifecycle` can participate in process-local Store admission.
//!
//! The qualification procedure (not this runtime verifier) establishes the
//! Git commit-to-tree relation and proves that the manifest source map names
//! the exact tree blobs. Runtime authenticates those exact signed coordinates,
//! recomputes their domain-separated identities, matches the supplied
//! manifest/source map, and measures the running image. Git object semantics,
//! artifact measurement, and Ed25519 security remain qualification premises.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest};
use rustix::fs::{Mode, OFlags, open, openat};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::live_c2::measure_current_runtime_artifact;
use super::signer::manifest::StoreIntegritySignerImplementationManifestV1;

pub(crate) const C2_CANDIDATE_CERTIFICATE_SCHEMA_V1: &str =
    "nq.c2_candidate_qualification_certificate.v1";
pub(crate) const C2_CANDIDATE_CERTIFICATE_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.candidate_qualification_certificate.identity.v1";
pub(crate) const C2_CANDIDATE_CERTIFICATE_SIGNATURE_DOMAIN_V1: &str =
    "nq.c2.candidate_qualification_certificate.signature.v1";
pub(crate) const C2_QUALIFICATION_TRUST_ROOT_SCHEMA_V1: &str = "nq.c2_qualification_trust_root.v1";
pub(crate) const C2_QUALIFICATION_TRUST_ROOT_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.qualification_trust_root.identity.v1";
pub(crate) const C2_QUALIFIED_CANDIDATE_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.qualified_candidate.identity.v1";
const C2_SOURCE_COMMIT_IDENTITY_DOMAIN_V1: &str = "nq.c2.source_commit.identity.v1";
const C2_SOURCE_TREE_IDENTITY_DOMAIN_V1: &str = "nq.c2.source_tree.identity.v1";
const C2_MANIFEST_SOURCE_FILES_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.signer_implementation_manifest.source_files.identity.v1";
const C2_QUALIFICATION_KEY_GENERATION_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.qualification_key_generation.identity.v1";
pub(crate) const C2_QUALIFICATION_TRUST_ROOT_PATH_V1: &str =
    "/etc/nq/c2-qualification-trust-root.v1.json";

const ED25519_ALGORITHM_V1: &str = "ed25519";
const MAX_TRUST_ROOT_BYTES: u64 = 64 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
const MAX_QUALIFICATION_ASSUMPTIONS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationTrustRootBodyV1 {
    schema: String,
    identity_domain: String,
    signature_algorithm: String,
    qualification_scope_identity: Sha256Digest,
    qualification_verifier_contract_identity: Sha256Digest,
    qualification_policy_identity: Sha256Digest,
    qualification_key_generation_identity: Sha256Digest,
    verification_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationTrustRootWireV1 {
    #[serde(flatten)]
    body: QualificationTrustRootBodyV1,
    qualification_trust_root_identity: Sha256Digest,
}

/// Verified fixed-path qualification trust source.
///
/// This value identifies the public qualification issuer.  It is neither a
/// runtime dependency root nor lifecycle authority.
struct StoreQualificationTrustRootV1 {
    wire: QualificationTrustRootWireV1,
    verification_key: VerifyingKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateCertificateUnsignedV1 {
    schema: String,
    identity_domain: String,
    signature_domain: String,
    signature_algorithm: String,
    qualification_trust_root_identity: Sha256Digest,
    qualification_scope_identity: Sha256Digest,
    qualification_verifier_contract_identity: Sha256Digest,
    qualification_policy_identity: Sha256Digest,
    qualification_key_generation_identity: Sha256Digest,
    qualification_claim_identity: Sha256Digest,
    candidate_identity_domain: String,
    git_object_format: String,
    source_commit_oid: String,
    source_tree_oid: String,
    source_commit_identity: Sha256Digest,
    qualified_candidate_identity: Sha256Digest,
    source_tree_identity: Sha256Digest,
    signer_implementation_manifest_identity: Sha256Digest,
    manifest_source_files_identity: Sha256Digest,
    qualification_evidence_identity: Sha256Digest,
    runtime_artifact_identity: Sha256Digest,
    toolchain_identity: Sha256Digest,
    target_profile_identity: Sha256Digest,
    qualification_assumption_identities: BTreeSet<Sha256Digest>,
}

#[derive(Serialize)]
struct CandidateCertificateIdentityBodyV1<'a> {
    #[serde(flatten)]
    unsigned: &'a CandidateCertificateUnsignedV1,
    signature: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateCertificateWireV1 {
    #[serde(flatten)]
    unsigned: CandidateCertificateUnsignedV1,
    signature: String,
    certificate_identity: Sha256Digest,
}

/// Authenticated certificate result consumed only by the sibling live-C2
/// sealing seam.  It is intentionally nonserializable and noncloneable.
pub(crate) struct StoreVerifiedCandidateCertificateV1 {
    qualified_candidate_identity: Sha256Digest,
    source_tree_identity: Sha256Digest,
    runtime_artifact_identity: Sha256Digest,
    signer_implementation_manifest_identity: Sha256Digest,
    qualification_evidence_identity: Sha256Digest,
    certificate_identity: Sha256Digest,
    qualification_trust_root_identity: Sha256Digest,
}

impl StoreVerifiedCandidateCertificateV1 {
    pub(crate) const fn qualified_candidate_identity(&self) -> &Sha256Digest {
        &self.qualified_candidate_identity
    }

    pub(crate) const fn source_tree_identity(&self) -> &Sha256Digest {
        &self.source_tree_identity
    }

    pub(crate) const fn runtime_artifact_identity(&self) -> &Sha256Digest {
        &self.runtime_artifact_identity
    }

    pub(crate) const fn signer_implementation_manifest_identity(&self) -> &Sha256Digest {
        &self.signer_implementation_manifest_identity
    }

    pub(crate) const fn qualification_evidence_identity(&self) -> &Sha256Digest {
        &self.qualification_evidence_identity
    }

    pub(crate) const fn certificate_identity(&self) -> &Sha256Digest {
        &self.certificate_identity
    }

    pub(crate) const fn qualification_trust_root_identity(&self) -> &Sha256Digest {
        &self.qualification_trust_root_identity
    }
}

/// Fail-closed candidate-certificate and qualification-trust refusals.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum C2CandidateVerificationRefusalV1 {
    #[error("the fixed qualification trust source is unavailable")]
    TrustSourceUnavailable,
    #[error("the fixed qualification trust source custody is unsafe")]
    TrustSourceCustody,
    #[error("the qualification trust record is malformed or noncanonical")]
    TrustSourceMalformedOrNoncanonical,
    #[error("the qualification trust-record identity does not recompute")]
    TrustSourceIdentityMismatch,
    #[error("the candidate certificate is malformed, noncanonical, or exceeds its bound")]
    CertificateMalformedOrNoncanonical,
    #[error(
        "the candidate certificate substitutes a closed schema, identity, signature domain, or algorithm"
    )]
    CertificateClosedConstantMismatch,
    #[error("the candidate certificate identity does not recompute")]
    CertificateIdentityMismatch,
    #[error("the qualified candidate/source basis does not recompute exactly")]
    CandidateBasisIdentityMismatch,
    #[error("the candidate certificate is signed by another qualification trust root")]
    WrongQualificationIssuer,
    #[error("the candidate certificate signature is invalid")]
    SignatureInvalid,
    #[error(
        "the candidate certificate does not bind the exact signer implementation manifest basis"
    )]
    ManifestBasisMismatch,
    #[error("the running image does not match the candidate certificate")]
    RuntimeArtifactMismatch,
    #[error("the exact running image cannot be measured")]
    RuntimeMeasurementUnavailable,
}

fn exact_lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(text).ok()?;
    if bytes.len() != N || hex::encode(&bytes) != text {
        return None;
    }
    bytes.try_into().ok()
}

#[derive(Serialize)]
struct FixedIdentityBodyV1<'a> {
    identity_domain: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
struct QualificationKeyGenerationBodyV1<'a> {
    identity_domain: &'static str,
    signature_algorithm: &'static str,
    verification_key: &'a str,
}

#[derive(Serialize)]
struct GitObjectIdentityBodyV1<'a> {
    identity_domain: &'static str,
    git_object_format: &'a str,
    object_id: &'a str,
}

#[derive(Serialize)]
struct ManifestSourceFilesIdentityBodyV1<'a> {
    identity_domain: &'static str,
    source_files: &'a BTreeMap<String, Sha256Digest>,
}

#[derive(Serialize)]
struct QualifiedCandidateIdentityBodyV1<'a> {
    identity_domain: &'static str,
    git_object_format: &'a str,
    source_commit_oid: &'a str,
    source_tree_oid: &'a str,
    source_commit_identity: &'a Sha256Digest,
    source_tree_identity: &'a Sha256Digest,
    signer_implementation_manifest_identity: &'a Sha256Digest,
    manifest_source_files_identity: &'a Sha256Digest,
    runtime_artifact_identity: &'a Sha256Digest,
    toolchain_identity: &'a Sha256Digest,
    target_profile_identity: &'a Sha256Digest,
    qualification_assumption_identities: &'a BTreeSet<Sha256Digest>,
}

fn fixed_identity(domain: &'static str, value: &str) -> Sha256Digest {
    semantic_digest(&FixedIdentityBodyV1 {
        identity_domain: domain,
        value,
    })
    .expect("fixed C2 qualification identity is JSON-representable")
}

fn qualification_scope_identity_v1() -> Sha256Digest {
    fixed_identity(
        "nq.c2.qualification_scope.identity.v1",
        "nq.c2.live_store_integrity_signer_lifecycle.v1",
    )
}

fn qualification_verifier_contract_identity_v1() -> Sha256Digest {
    fixed_identity(
        "nq.c2.qualification_verifier_contract.identity.v1",
        "nq.c2.candidate_certificate_runtime_verifier.v1",
    )
}

fn qualification_policy_identity_v1() -> Sha256Digest {
    fixed_identity(
        "nq.c2.qualification_policy.identity.v1",
        "candidate-freeze+tree-manifest+evidence+runtime-artifact.v1",
    )
}

fn qualification_key_generation_identity_v1(verification_key: &str) -> Sha256Digest {
    semantic_digest(&QualificationKeyGenerationBodyV1 {
        identity_domain: C2_QUALIFICATION_KEY_GENERATION_IDENTITY_DOMAIN_V1,
        signature_algorithm: ED25519_ALGORITHM_V1,
        verification_key,
    })
    .expect("fixed C2 qualification key-generation identity is JSON-representable")
}

fn exact_git_object_id(git_object_format: &str, object_id: &str) -> bool {
    match git_object_format {
        "sha1" => exact_lower_hex::<20>(object_id).is_some(),
        "sha256" => exact_lower_hex::<32>(object_id).is_some(),
        _ => false,
    }
}

fn git_object_identity(
    identity_domain: &'static str,
    git_object_format: &str,
    object_id: &str,
) -> Result<Sha256Digest, C2CandidateVerificationRefusalV1> {
    semantic_digest(&GitObjectIdentityBodyV1 {
        identity_domain,
        git_object_format,
        object_id,
    })
    .map_err(|_| C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)
}

fn manifest_source_files_identity(
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> Result<Sha256Digest, C2CandidateVerificationRefusalV1> {
    semantic_digest(&ManifestSourceFilesIdentityBodyV1 {
        identity_domain: C2_MANIFEST_SOURCE_FILES_IDENTITY_DOMAIN_V1,
        source_files: manifest.source_files(),
    })
    .map_err(|_| C2CandidateVerificationRefusalV1::ManifestBasisMismatch)
}

fn qualified_candidate_identity(
    unsigned: &CandidateCertificateUnsignedV1,
) -> Result<Sha256Digest, C2CandidateVerificationRefusalV1> {
    semantic_digest(&QualifiedCandidateIdentityBodyV1 {
        identity_domain: C2_QUALIFIED_CANDIDATE_IDENTITY_DOMAIN_V1,
        git_object_format: &unsigned.git_object_format,
        source_commit_oid: &unsigned.source_commit_oid,
        source_tree_oid: &unsigned.source_tree_oid,
        source_commit_identity: &unsigned.source_commit_identity,
        source_tree_identity: &unsigned.source_tree_identity,
        signer_implementation_manifest_identity: &unsigned.signer_implementation_manifest_identity,
        manifest_source_files_identity: &unsigned.manifest_source_files_identity,
        runtime_artifact_identity: &unsigned.runtime_artifact_identity,
        toolchain_identity: &unsigned.toolchain_identity,
        target_profile_identity: &unsigned.target_profile_identity,
        qualification_assumption_identities: &unsigned.qualification_assumption_identities,
    })
    .map_err(|_| C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)
}

fn trust_root_identity(
    body: &QualificationTrustRootBodyV1,
) -> Result<Sha256Digest, C2CandidateVerificationRefusalV1> {
    semantic_digest(body)
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical)
}

fn decode_qualification_trust_root_v1(
    bytes: &[u8],
) -> Result<StoreQualificationTrustRootV1, C2CandidateVerificationRefusalV1> {
    let wire: QualificationTrustRootWireV1 = serde_json::from_slice(bytes)
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical)?;
    if canonical_json_bytes(&wire)
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical)?
        != bytes
        || wire.body.schema != C2_QUALIFICATION_TRUST_ROOT_SCHEMA_V1
        || wire.body.identity_domain != C2_QUALIFICATION_TRUST_ROOT_IDENTITY_DOMAIN_V1
        || wire.body.signature_algorithm != ED25519_ALGORITHM_V1
        || wire.body.qualification_scope_identity != qualification_scope_identity_v1()
        || wire.body.qualification_verifier_contract_identity
            != qualification_verifier_contract_identity_v1()
        || wire.body.qualification_policy_identity != qualification_policy_identity_v1()
        || wire.body.qualification_key_generation_identity
            != qualification_key_generation_identity_v1(&wire.body.verification_key)
    {
        return Err(C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical);
    }
    if trust_root_identity(&wire.body)? != wire.qualification_trust_root_identity {
        return Err(C2CandidateVerificationRefusalV1::TrustSourceIdentityMismatch);
    }
    let key_bytes = exact_lower_hex::<32>(&wire.body.verification_key)
        .ok_or(C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical)?;
    let verification_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical)?;
    Ok(StoreQualificationTrustRootV1 {
        wire,
        verification_key,
    })
}

fn validate_trust_directory(directory: &File) -> Result<(), C2CandidateVerificationRefusalV1> {
    let metadata = directory
        .metadata()
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceUnavailable)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(C2CandidateVerificationRefusalV1::TrustSourceCustody);
    }
    Ok(())
}

fn open_fixed_trust_directory_component(
    parent: &File,
    name: &str,
) -> Result<File, C2CandidateVerificationRefusalV1> {
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceUnavailable)?,
    );
    validate_trust_directory(&directory)?;
    Ok(directory)
}

fn fixed_trust_source_bytes() -> Result<Vec<u8>, C2CandidateVerificationRefusalV1> {
    #[cfg(test)]
    if let Some(bytes) = TEST_QUALIFICATION_TRUST_ROOT_BYTES.with(|slot| slot.borrow().clone()) {
        return Ok(bytes);
    }

    let filesystem_root = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceUnavailable)?,
    );
    validate_trust_directory(&filesystem_root)?;
    let etc = open_fixed_trust_directory_component(&filesystem_root, "etc")?;
    let nq = open_fixed_trust_directory_component(&etc, "nq")?;
    let file = File::from(
        openat(
            &nq,
            "c2-qualification-trust-root.v1.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceUnavailable)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_TRUST_ROOT_BYTES
    {
        return Err(C2CandidateVerificationRefusalV1::TrustSourceCustody);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TRUST_ROOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| C2CandidateVerificationRefusalV1::TrustSourceUnavailable)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(C2CandidateVerificationRefusalV1::TrustSourceCustody);
    }
    Ok(bytes)
}

fn load_fixed_qualification_trust_root_v1()
-> Result<StoreQualificationTrustRootV1, C2CandidateVerificationRefusalV1> {
    decode_qualification_trust_root_v1(&fixed_trust_source_bytes()?)
}

fn certificate_signature_preimage(
    unsigned: &CandidateCertificateUnsignedV1,
) -> Result<Vec<u8>, C2CandidateVerificationRefusalV1> {
    let canonical = canonical_json_bytes(unsigned)
        .map_err(|_| C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)?;
    let mut preimage = C2_CANDIDATE_CERTIFICATE_SIGNATURE_DOMAIN_V1
        .as_bytes()
        .to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

fn certificate_identity(
    unsigned: &CandidateCertificateUnsignedV1,
    signature: &str,
) -> Result<Sha256Digest, C2CandidateVerificationRefusalV1> {
    semantic_digest(&CandidateCertificateIdentityBodyV1 {
        unsigned,
        signature,
    })
    .map_err(|_| C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)
}

fn decode_candidate_certificate_v1(
    bytes: &[u8],
) -> Result<CandidateCertificateWireV1, C2CandidateVerificationRefusalV1> {
    if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical);
    }
    let wire: CandidateCertificateWireV1 = serde_json::from_slice(bytes)
        .map_err(|_| C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)?;
    if canonical_json_bytes(&wire)
        .map_err(|_| C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)?
        != bytes
    {
        return Err(C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical);
    }
    if wire.unsigned.schema != C2_CANDIDATE_CERTIFICATE_SCHEMA_V1
        || wire.unsigned.identity_domain != C2_CANDIDATE_CERTIFICATE_IDENTITY_DOMAIN_V1
        || wire.unsigned.signature_domain != C2_CANDIDATE_CERTIFICATE_SIGNATURE_DOMAIN_V1
        || wire.unsigned.signature_algorithm != ED25519_ALGORITHM_V1
        || wire.unsigned.candidate_identity_domain != C2_QUALIFIED_CANDIDATE_IDENTITY_DOMAIN_V1
        || !exact_git_object_id(
            &wire.unsigned.git_object_format,
            &wire.unsigned.source_commit_oid,
        )
        || !exact_git_object_id(
            &wire.unsigned.git_object_format,
            &wire.unsigned.source_tree_oid,
        )
        || wire.unsigned.qualification_assumption_identities.is_empty()
        || wire.unsigned.qualification_assumption_identities.len() > MAX_QUALIFICATION_ASSUMPTIONS
    {
        return Err(C2CandidateVerificationRefusalV1::CertificateClosedConstantMismatch);
    }
    if certificate_identity(&wire.unsigned, &wire.signature)? != wire.certificate_identity {
        return Err(C2CandidateVerificationRefusalV1::CertificateIdentityMismatch);
    }
    if git_object_identity(
        C2_SOURCE_COMMIT_IDENTITY_DOMAIN_V1,
        &wire.unsigned.git_object_format,
        &wire.unsigned.source_commit_oid,
    )? != wire.unsigned.source_commit_identity
        || git_object_identity(
            C2_SOURCE_TREE_IDENTITY_DOMAIN_V1,
            &wire.unsigned.git_object_format,
            &wire.unsigned.source_tree_oid,
        )? != wire.unsigned.source_tree_identity
        || qualified_candidate_identity(&wire.unsigned)?
            != wire.unsigned.qualified_candidate_identity
    {
        return Err(C2CandidateVerificationRefusalV1::CandidateBasisIdentityMismatch);
    }
    Ok(wire)
}

/// Authenticate one exact candidate certificate and bind it to the currently
/// running image.  Success remains inert evidence until the sibling Store
/// verifier seals it into a process-local result.
pub(crate) fn verify_candidate_certificate_for_current_runtime_v1(
    certificate_bytes: &[u8],
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> Result<StoreVerifiedCandidateCertificateV1, C2CandidateVerificationRefusalV1> {
    let trust = load_fixed_qualification_trust_root_v1()?;
    let wire = decode_candidate_certificate_v1(certificate_bytes)?;
    if wire.unsigned.qualification_trust_root_identity
        != trust.wire.qualification_trust_root_identity
        || wire.unsigned.qualification_scope_identity
            != trust.wire.body.qualification_scope_identity
        || wire.unsigned.qualification_verifier_contract_identity
            != trust.wire.body.qualification_verifier_contract_identity
        || wire.unsigned.qualification_policy_identity
            != trust.wire.body.qualification_policy_identity
        || wire.unsigned.qualification_key_generation_identity
            != trust.wire.body.qualification_key_generation_identity
    {
        return Err(C2CandidateVerificationRefusalV1::WrongQualificationIssuer);
    }
    let signature = exact_lower_hex::<64>(&wire.signature)
        .ok_or(C2CandidateVerificationRefusalV1::SignatureInvalid)?;
    trust
        .verification_key
        .verify_strict(
            &certificate_signature_preimage(&wire.unsigned)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| C2CandidateVerificationRefusalV1::SignatureInvalid)?;

    if wire.unsigned.signer_implementation_manifest_identity != *manifest.manifest_identity()
        || wire.unsigned.manifest_source_files_identity != manifest_source_files_identity(manifest)?
        || wire.unsigned.toolchain_identity != *manifest.toolchain_identity()
        || wire.unsigned.target_profile_identity != *manifest.target_profile_identity()
        || wire.unsigned.qualification_assumption_identities
            != *manifest.qualification_assumption_identities()
    {
        return Err(C2CandidateVerificationRefusalV1::ManifestBasisMismatch);
    }

    let measured = measure_current_runtime_artifact()
        .map_err(|_| C2CandidateVerificationRefusalV1::RuntimeMeasurementUnavailable)?;
    if measured != wire.unsigned.runtime_artifact_identity {
        return Err(C2CandidateVerificationRefusalV1::RuntimeArtifactMismatch);
    }

    Ok(StoreVerifiedCandidateCertificateV1 {
        qualified_candidate_identity: wire.unsigned.qualified_candidate_identity,
        source_tree_identity: wire.unsigned.source_tree_identity,
        runtime_artifact_identity: wire.unsigned.runtime_artifact_identity,
        signer_implementation_manifest_identity: wire
            .unsigned
            .signer_implementation_manifest_identity,
        qualification_evidence_identity: wire.unsigned.qualification_evidence_identity,
        certificate_identity: wire.certificate_identity,
        qualification_trust_root_identity: wire.unsigned.qualification_trust_root_identity,
    })
}

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    static TEST_QUALIFICATION_TRUST_ROOT_BYTES: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_qualification_trust_root_v1<R>(
    bytes: Vec<u8>,
    operation: impl FnOnce() -> R,
) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_QUALIFICATION_TRUST_ROOT_BYTES.with(|slot| slot.replace(None));
        }
    }
    TEST_QUALIFICATION_TRUST_ROOT_BYTES.with(|slot| {
        assert!(
            slot.replace(Some(bytes)).is_none(),
            "nested qualification trust fixture"
        );
    });
    let reset = Reset;
    let result = operation();
    drop(reset);
    result
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use ed25519_dalek::{Signer as _, SigningKey};
    use nq_protocol::{canonical_json_bytes, sha256_bytes};
    use serde_json::Value;
    use tempfile::tempdir;

    use super::*;
    use crate::Store;
    use crate::store_generation::c2_lifecycle::{
        C2SignerImplementationManifestV1, StoreC2CandidateRuntimeVerifierV1,
    };
    use crate::store_generation::signer::manifest::{
        SignerImplementationManifestDerivationInputV1, derive_signer_implementation_manifest_v1,
    };

    fn exact_manifest() -> StoreIntegritySignerImplementationManifestV1 {
        derive_signer_implementation_manifest_v1(SignerImplementationManifestDerivationInputV1 {
            custody_format_identity: sha256_bytes(b"candidate-test/custody-format"),
            signer_message_contract_identity: sha256_bytes(b"candidate-test/message-contract"),
            source_file_bytes: BTreeMap::from([
                (
                    "crates/nq-store/src/store_generation/candidate_qualification.rs".to_owned(),
                    b"candidate verifier source".to_vec(),
                ),
                (
                    "schemas/c2/nq.c2_candidate_qualification_certificate.v1.json".to_owned(),
                    b"candidate certificate schema".to_vec(),
                ),
            ]),
            cryptographic_backend_identity: sha256_bytes(b"candidate-test/crypto"),
            toolchain_identity: sha256_bytes(b"candidate-test/toolchain"),
            target_profile_identity: sha256_bytes(b"candidate-test/target"),
            qualification_assumption_identities: BTreeSet::from([
                sha256_bytes(b"candidate-test/assumption-a"),
                sha256_bytes(b"candidate-test/assumption-b"),
            ]),
        })
        .expect("derive exact candidate-test manifest")
    }

    fn trust_root(signing_key: &SigningKey) -> (Vec<u8>, Sha256Digest) {
        let verification_key = hex::encode(signing_key.verifying_key().to_bytes());
        let body = QualificationTrustRootBodyV1 {
            schema: C2_QUALIFICATION_TRUST_ROOT_SCHEMA_V1.to_owned(),
            identity_domain: C2_QUALIFICATION_TRUST_ROOT_IDENTITY_DOMAIN_V1.to_owned(),
            signature_algorithm: ED25519_ALGORITHM_V1.to_owned(),
            qualification_scope_identity: qualification_scope_identity_v1(),
            qualification_verifier_contract_identity: qualification_verifier_contract_identity_v1(),
            qualification_policy_identity: qualification_policy_identity_v1(),
            qualification_key_generation_identity: qualification_key_generation_identity_v1(
                &verification_key,
            ),
            verification_key,
        };
        let qualification_trust_root_identity = trust_root_identity(&body).unwrap();
        let bytes = canonical_json_bytes(&QualificationTrustRootWireV1 {
            body,
            qualification_trust_root_identity: qualification_trust_root_identity.clone(),
        })
        .unwrap();
        (bytes, qualification_trust_root_identity)
    }

    fn signed_certificate(
        signing_key: &SigningKey,
        trust_root_identity: Sha256Digest,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        runtime_artifact_identity: Sha256Digest,
    ) -> Vec<u8> {
        let verification_key = hex::encode(signing_key.verifying_key().to_bytes());
        let git_object_format = "sha1".to_owned();
        let source_commit_oid = "1111111111111111111111111111111111111111".to_owned();
        let source_tree_oid = "2222222222222222222222222222222222222222".to_owned();
        let unsigned = CandidateCertificateUnsignedV1 {
            schema: C2_CANDIDATE_CERTIFICATE_SCHEMA_V1.to_owned(),
            identity_domain: C2_CANDIDATE_CERTIFICATE_IDENTITY_DOMAIN_V1.to_owned(),
            signature_domain: C2_CANDIDATE_CERTIFICATE_SIGNATURE_DOMAIN_V1.to_owned(),
            signature_algorithm: ED25519_ALGORITHM_V1.to_owned(),
            qualification_trust_root_identity: trust_root_identity,
            qualification_scope_identity: qualification_scope_identity_v1(),
            qualification_verifier_contract_identity: qualification_verifier_contract_identity_v1(),
            qualification_policy_identity: qualification_policy_identity_v1(),
            qualification_key_generation_identity: qualification_key_generation_identity_v1(
                &verification_key,
            ),
            qualification_claim_identity: sha256_bytes(b"candidate-test/claim"),
            candidate_identity_domain: C2_QUALIFIED_CANDIDATE_IDENTITY_DOMAIN_V1.to_owned(),
            git_object_format: git_object_format.clone(),
            source_commit_oid: source_commit_oid.clone(),
            source_tree_oid: source_tree_oid.clone(),
            source_commit_identity: git_object_identity(
                C2_SOURCE_COMMIT_IDENTITY_DOMAIN_V1,
                &git_object_format,
                &source_commit_oid,
            )
            .unwrap(),
            qualified_candidate_identity: sha256_bytes(b"candidate-test/candidate"),
            source_tree_identity: git_object_identity(
                C2_SOURCE_TREE_IDENTITY_DOMAIN_V1,
                &git_object_format,
                &source_tree_oid,
            )
            .unwrap(),
            signer_implementation_manifest_identity: manifest.manifest_identity().clone(),
            manifest_source_files_identity: manifest_source_files_identity(manifest).unwrap(),
            qualification_evidence_identity: sha256_bytes(b"candidate-test/evidence"),
            runtime_artifact_identity,
            toolchain_identity: manifest.toolchain_identity().clone(),
            target_profile_identity: manifest.target_profile_identity().clone(),
            qualification_assumption_identities: manifest
                .qualification_assumption_identities()
                .clone(),
        };
        sign_coherent_candidate_basis(signing_key, unsigned)
    }

    fn sign_coherent_candidate_basis(
        signing_key: &SigningKey,
        mut unsigned: CandidateCertificateUnsignedV1,
    ) -> Vec<u8> {
        unsigned.qualified_candidate_identity = qualified_candidate_identity(&unsigned).unwrap();
        sign_unsigned(signing_key, unsigned)
    }

    fn sign_unsigned(
        signing_key: &SigningKey,
        unsigned: CandidateCertificateUnsignedV1,
    ) -> Vec<u8> {
        let signature = hex::encode(
            signing_key
                .sign(&certificate_signature_preimage(&unsigned).unwrap())
                .to_bytes(),
        );
        let certificate_identity = certificate_identity(&unsigned, &signature).unwrap();
        canonical_json_bytes(&CandidateCertificateWireV1 {
            unsigned,
            signature,
            certificate_identity,
        })
        .unwrap()
    }

    fn decode_unsigned(bytes: &[u8]) -> CandidateCertificateUnsignedV1 {
        serde_json::from_slice::<CandidateCertificateWireV1>(bytes)
            .unwrap()
            .unsigned
    }

    fn mutate_json(bytes: &[u8], field: &str, value: Value) -> Vec<u8> {
        let mut document: Value = serde_json::from_slice(bytes).unwrap();
        document[field] = value;
        canonical_json_bytes(&document).unwrap()
    }

    #[test]
    fn canonical_trust_and_certificate_are_deterministic_authenticated_and_replayable() {
        let signing_key = SigningKey::from_bytes(&[61_u8; 32]);
        let manifest = exact_manifest();
        let artifact = measure_current_runtime_artifact().unwrap();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);
        let certificate = signed_certificate(
            &signing_key,
            trust_identity.clone(),
            &manifest,
            artifact.clone(),
        );
        assert_eq!(
            certificate,
            signed_certificate(&signing_key, trust_identity.clone(), &manifest, artifact)
        );

        let decoded_trust = decode_qualification_trust_root_v1(&trust_bytes).unwrap();
        assert_eq!(
            decoded_trust.wire.qualification_trust_root_identity,
            trust_identity
        );
        assert_eq!(
            canonical_json_bytes(&decode_candidate_certificate_v1(&certificate).unwrap()).unwrap(),
            certificate
        );

        with_test_qualification_trust_root_v1(trust_bytes, || {
            let first =
                verify_candidate_certificate_for_current_runtime_v1(&certificate, &manifest)
                    .expect("first exact verification");
            let replay =
                verify_candidate_certificate_for_current_runtime_v1(&certificate, &manifest)
                    .expect("exact certificate replay is fresh evidence verification");
            assert_eq!(first.certificate_identity(), replay.certificate_identity());
            assert_eq!(
                first.qualification_trust_root_identity(),
                replay.qualification_trust_root_identity()
            );
        });
    }

    #[test]
    fn malformed_noncanonical_unknown_duplicate_and_closed_constant_substitution_refuse() {
        let signing_key = SigningKey::from_bytes(&[62_u8; 32]);
        let manifest = exact_manifest();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);
        let certificate = signed_certificate(
            &signing_key,
            trust_identity,
            &manifest,
            measure_current_runtime_artifact().unwrap(),
        );
        let mut whitespace = certificate.clone();
        whitespace.push(b'\n');
        let unknown = mutate_json(&certificate, "unknown", Value::Bool(false));
        let duplicate = String::from_utf8(certificate.clone()).unwrap().replacen(
            "{",
            "{\"schema\":\"nq.c2_candidate_qualification_certificate.v1\",",
            1,
        );
        let wrong_domain = mutate_json(
            &certificate,
            "signature_domain",
            Value::String("nq.c2.wrong.signature.v1".into()),
        );
        with_test_qualification_trust_root_v1(trust_bytes, || {
            for malformed in [whitespace, unknown, duplicate.into_bytes()] {
                assert_eq!(
                    verify_candidate_certificate_for_current_runtime_v1(&malformed, &manifest)
                        .err(),
                    Some(C2CandidateVerificationRefusalV1::CertificateMalformedOrNoncanonical)
                );
            }
            assert_eq!(
                verify_candidate_certificate_for_current_runtime_v1(&wrong_domain, &manifest).err(),
                Some(C2CandidateVerificationRefusalV1::CertificateClosedConstantMismatch)
            );
        });
    }

    #[test]
    fn issuer_signature_and_every_certificate_coordinate_substitution_refuse() {
        let signing_key = SigningKey::from_bytes(&[63_u8; 32]);
        let other_key = SigningKey::from_bytes(&[64_u8; 32]);
        let manifest = exact_manifest();
        let artifact = measure_current_runtime_artifact().unwrap();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);
        let (_, other_trust_identity) = trust_root(&other_key);
        let certificate =
            signed_certificate(&signing_key, trust_identity.clone(), &manifest, artifact);

        let wrong_issuer = signed_certificate(
            &other_key,
            other_trust_identity,
            &manifest,
            measure_current_runtime_artifact().unwrap(),
        );
        let wrong_signature = sign_unsigned(
            &other_key,
            decode_unsigned(&signed_certificate(
                &signing_key,
                trust_identity,
                &manifest,
                measure_current_runtime_artifact().unwrap(),
            )),
        );

        with_test_qualification_trust_root_v1(trust_bytes, || {
            assert_eq!(
                verify_candidate_certificate_for_current_runtime_v1(&wrong_issuer, &manifest).err(),
                Some(C2CandidateVerificationRefusalV1::WrongQualificationIssuer)
            );
            assert_eq!(
                verify_candidate_certificate_for_current_runtime_v1(&wrong_signature, &manifest)
                    .err(),
                Some(C2CandidateVerificationRefusalV1::SignatureInvalid)
            );

            for (field, value) in [
                ("qualification_claim_identity", sha256_bytes(b"wrong-claim")),
                (
                    "qualified_candidate_identity",
                    sha256_bytes(b"wrong-candidate"),
                ),
                ("source_commit_identity", sha256_bytes(b"wrong-commit")),
                ("source_tree_identity", sha256_bytes(b"wrong-tree")),
                (
                    "manifest_source_files_identity",
                    sha256_bytes(b"wrong-source-map"),
                ),
                (
                    "qualification_evidence_identity",
                    sha256_bytes(b"wrong-evidence"),
                ),
                (
                    "signer_implementation_manifest_identity",
                    sha256_bytes(b"wrong-manifest"),
                ),
                ("runtime_artifact_identity", sha256_bytes(b"wrong-artifact")),
                ("toolchain_identity", sha256_bytes(b"wrong-toolchain")),
                ("target_profile_identity", sha256_bytes(b"wrong-target")),
            ] {
                let changed = mutate_json(
                    &certificate,
                    field,
                    Value::String(value.as_str().to_owned()),
                );
                assert!(matches!(
                    verify_candidate_certificate_for_current_runtime_v1(&changed, &manifest),
                    Err(C2CandidateVerificationRefusalV1::CertificateIdentityMismatch)
                        | Err(C2CandidateVerificationRefusalV1::SignatureInvalid)
                ));
            }
        });
    }

    #[test]
    fn authenticated_stale_candidate_derivations_and_manifest_source_map_refuse() {
        let signing_key = SigningKey::from_bytes(&[67_u8; 32]);
        let manifest = exact_manifest();
        let artifact = measure_current_runtime_artifact().unwrap();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);
        let exact = decode_unsigned(&signed_certificate(
            &signing_key,
            trust_identity,
            &manifest,
            artifact,
        ));

        let mut wrong_commit_oid = exact.clone();
        wrong_commit_oid.source_commit_oid = "3333333333333333333333333333333333333333".into();
        let mut wrong_tree_oid = exact.clone();
        wrong_tree_oid.source_tree_oid = "4444444444444444444444444444444444444444".into();
        let mut wrong_candidate_identity = exact.clone();
        wrong_candidate_identity.qualified_candidate_identity = sha256_bytes(b"caller candidate");
        let stale_derivations = [wrong_commit_oid, wrong_tree_oid, wrong_candidate_identity]
            .map(|unsigned| sign_unsigned(&signing_key, unsigned));

        let mut substituted_source_map = exact;
        substituted_source_map.manifest_source_files_identity = sha256_bytes(b"other source map");
        let substituted_source_map =
            sign_coherent_candidate_basis(&signing_key, substituted_source_map);

        with_test_qualification_trust_root_v1(trust_bytes, || {
            for certificate in stale_derivations {
                assert_eq!(
                    verify_candidate_certificate_for_current_runtime_v1(&certificate, &manifest)
                        .err(),
                    Some(C2CandidateVerificationRefusalV1::CandidateBasisIdentityMismatch)
                );
            }
            assert_eq!(
                verify_candidate_certificate_for_current_runtime_v1(
                    &substituted_source_map,
                    &manifest,
                )
                .err(),
                Some(C2CandidateVerificationRefusalV1::ManifestBasisMismatch)
            );
        });
    }

    #[test]
    fn trust_root_scope_policy_key_generation_and_canonical_identity_are_closed() {
        let signing_key = SigningKey::from_bytes(&[68_u8; 32]);
        let (trust_bytes, _) = trust_root(&signing_key);
        let exact: QualificationTrustRootWireV1 = serde_json::from_slice(&trust_bytes).unwrap();

        let mut wrong_scope = exact.clone();
        wrong_scope.body.qualification_scope_identity = sha256_bytes(b"wrong scope");
        wrong_scope.qualification_trust_root_identity =
            trust_root_identity(&wrong_scope.body).unwrap();
        let mut wrong_policy = exact.clone();
        wrong_policy.body.qualification_policy_identity = sha256_bytes(b"wrong policy");
        wrong_policy.qualification_trust_root_identity =
            trust_root_identity(&wrong_policy.body).unwrap();
        let mut wrong_generation = exact.clone();
        wrong_generation.body.qualification_key_generation_identity =
            sha256_bytes(b"caller key generation");
        wrong_generation.qualification_trust_root_identity =
            trust_root_identity(&wrong_generation.body).unwrap();
        let mut wrong_identity = exact.clone();
        wrong_identity.qualification_trust_root_identity = sha256_bytes(b"wrong root identity");

        for malformed in [wrong_scope, wrong_policy, wrong_generation] {
            assert_eq!(
                decode_qualification_trust_root_v1(&canonical_json_bytes(&malformed).unwrap())
                    .err(),
                Some(C2CandidateVerificationRefusalV1::TrustSourceMalformedOrNoncanonical)
            );
        }
        assert_eq!(
            decode_qualification_trust_root_v1(&canonical_json_bytes(&wrong_identity).unwrap())
                .err(),
            Some(C2CandidateVerificationRefusalV1::TrustSourceIdentityMismatch)
        );
    }

    #[test]
    fn writable_trust_path_component_is_rejected() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let directory = File::open(root.path()).unwrap();
        assert_eq!(
            validate_trust_directory(&directory),
            Err(C2CandidateVerificationRefusalV1::TrustSourceCustody)
        );
    }

    #[test]
    fn authenticated_but_wrong_manifest_runtime_toolchain_target_and_assumptions_refuse() {
        let signing_key = SigningKey::from_bytes(&[65_u8; 32]);
        let manifest = exact_manifest();
        let artifact = measure_current_runtime_artifact().unwrap();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);

        let mut cases = Vec::new();
        let mut wrong_manifest = decode_unsigned(&signed_certificate(
            &signing_key,
            trust_identity.clone(),
            &manifest,
            artifact.clone(),
        ));
        wrong_manifest.signer_implementation_manifest_identity = sha256_bytes(b"wrong-manifest");
        cases.push((
            sign_coherent_candidate_basis(&signing_key, wrong_manifest),
            C2CandidateVerificationRefusalV1::ManifestBasisMismatch,
        ));

        let mut wrong_runtime = decode_unsigned(&signed_certificate(
            &signing_key,
            trust_identity.clone(),
            &manifest,
            artifact.clone(),
        ));
        wrong_runtime.runtime_artifact_identity = sha256_bytes(b"wrong-runtime");
        cases.push((
            sign_coherent_candidate_basis(&signing_key, wrong_runtime),
            C2CandidateVerificationRefusalV1::RuntimeArtifactMismatch,
        ));

        for coordinate in ["toolchain", "target", "assumptions"] {
            let mut wrong = decode_unsigned(&signed_certificate(
                &signing_key,
                trust_identity.clone(),
                &manifest,
                artifact.clone(),
            ));
            match coordinate {
                "toolchain" => wrong.toolchain_identity = sha256_bytes(b"wrong-toolchain"),
                "target" => wrong.target_profile_identity = sha256_bytes(b"wrong-target"),
                "assumptions" => {
                    wrong.qualification_assumption_identities =
                        BTreeSet::from([sha256_bytes(b"wrong-assumption")]);
                }
                _ => unreachable!(),
            }
            cases.push((
                sign_coherent_candidate_basis(&signing_key, wrong),
                C2CandidateVerificationRefusalV1::ManifestBasisMismatch,
            ));
        }

        with_test_qualification_trust_root_v1(trust_bytes, || {
            for (certificate, expected) in cases {
                assert_eq!(
                    verify_candidate_certificate_for_current_runtime_v1(&certificate, &manifest)
                        .err(),
                    Some(expected)
                );
            }
        });
    }

    #[test]
    fn schema_runtime_parity_is_exact_for_trust_root_and_candidate_certificate() {
        let trust_schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/c2/nq.c2_qualification_trust_root.v1.json"
        ))
        .unwrap();
        let certificate_schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/c2/nq.c2_candidate_qualification_certificate.v1.json"
        ))
        .unwrap();
        let trust_properties = trust_schema["properties"].as_object().unwrap();
        let certificate_properties = certificate_schema["properties"].as_object().unwrap();
        assert_eq!(trust_schema["additionalProperties"], Value::Bool(false));
        assert_eq!(
            certificate_schema["additionalProperties"],
            Value::Bool(false)
        );
        assert_eq!(
            trust_properties.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "identity_domain".to_owned(),
                "qualification_key_generation_identity".to_owned(),
                "qualification_policy_identity".to_owned(),
                "qualification_scope_identity".to_owned(),
                "qualification_trust_root_identity".to_owned(),
                "qualification_verifier_contract_identity".to_owned(),
                "schema".to_owned(),
                "signature_algorithm".to_owned(),
                "verification_key".to_owned(),
            ])
        );
        assert_eq!(
            certificate_properties
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "candidate_identity_domain".to_owned(),
                "certificate_identity".to_owned(),
                "git_object_format".to_owned(),
                "identity_domain".to_owned(),
                "manifest_source_files_identity".to_owned(),
                "qualification_assumption_identities".to_owned(),
                "qualification_claim_identity".to_owned(),
                "qualification_evidence_identity".to_owned(),
                "qualification_key_generation_identity".to_owned(),
                "qualification_policy_identity".to_owned(),
                "qualification_scope_identity".to_owned(),
                "qualification_trust_root_identity".to_owned(),
                "qualification_verifier_contract_identity".to_owned(),
                "qualified_candidate_identity".to_owned(),
                "runtime_artifact_identity".to_owned(),
                "schema".to_owned(),
                "signature".to_owned(),
                "signature_algorithm".to_owned(),
                "signature_domain".to_owned(),
                "signer_implementation_manifest_identity".to_owned(),
                "source_commit_identity".to_owned(),
                "source_commit_oid".to_owned(),
                "source_tree_identity".to_owned(),
                "source_tree_oid".to_owned(),
                "target_profile_identity".to_owned(),
                "toolchain_identity".to_owned(),
            ])
        );
        assert_eq!(
            trust_schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>(),
            trust_properties.keys().cloned().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            certificate_schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>(),
            certificate_properties
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            certificate_schema["properties"]["schema"]["const"],
            C2_CANDIDATE_CERTIFICATE_SCHEMA_V1
        );
        assert_eq!(
            certificate_schema["properties"]["identity_domain"]["const"],
            C2_CANDIDATE_CERTIFICATE_IDENTITY_DOMAIN_V1
        );
        assert_eq!(
            certificate_schema["properties"]["signature_domain"]["const"],
            C2_CANDIDATE_CERTIFICATE_SIGNATURE_DOMAIN_V1
        );
        let git_object_constraints = certificate_schema["allOf"].as_array().unwrap();
        assert_eq!(git_object_constraints.len(), 2);
        for (constraint, format, oid_pattern) in [
            (&git_object_constraints[0], "sha1", "^[0-9a-f]{40}$"),
            (&git_object_constraints[1], "sha256", "^[0-9a-f]{64}$"),
        ] {
            assert_eq!(
                constraint["if"]["properties"]["git_object_format"]["const"],
                format
            );
            assert_eq!(
                constraint["then"]["properties"]["source_commit_oid"]["pattern"],
                oid_pattern
            );
            assert_eq!(
                constraint["then"]["properties"]["source_tree_oid"]["pattern"],
                oid_pattern
            );
        }
    }

    #[test]
    fn production_verifier_reaches_the_public_lifecycle_without_raw_coordinates() {
        let signing_key = SigningKey::from_bytes(&[66_u8; 32]);
        let internal_manifest = exact_manifest();
        let public_manifest = C2SignerImplementationManifestV1::from_canonical_bytes(
            &internal_manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);
        let certificate = signed_certificate(
            &signing_key,
            trust_identity,
            &internal_manifest,
            measure_current_runtime_artifact().unwrap(),
        );
        let root = tempdir().unwrap();
        let database = root.path().join("store.sqlite");
        let mut store = Store::initialize_unqualified_storage(&database).unwrap();

        with_test_qualification_trust_root_v1(trust_bytes, || {
            let mut reached = false;
            StoreC2CandidateRuntimeVerifierV1::with_verified_c2_lifecycle(
                &mut store,
                &certificate,
                &public_manifest,
                |_lifecycle| reached = true,
            )
            .expect("authenticated production verifier reaches public facade");
            assert!(reached);
        });
    }

    const CANDIDATE_REENTRY_CHILD_ENV: &str = "NQ_C2_CANDIDATE_REENTRY_CHILD_V1";
    const CANDIDATE_REENTRY_TRUST_ENV: &str = "NQ_C2_CANDIDATE_REENTRY_TRUST_V1";
    const CANDIDATE_REENTRY_CERTIFICATE_ENV: &str = "NQ_C2_CANDIDATE_REENTRY_CERTIFICATE_V1";
    const CANDIDATE_REENTRY_MANIFEST_ENV: &str = "NQ_C2_CANDIDATE_REENTRY_MANIFEST_V1";
    const CANDIDATE_REENTRY_STORE_ENV: &str = "NQ_C2_CANDIDATE_REENTRY_STORE_V1";

    #[test]
    fn candidate_reentry_after_exec_requires_fresh_certificate_and_runtime_verification() {
        if env::var_os(CANDIDATE_REENTRY_CHILD_ENV).is_some() {
            let trust_bytes = hex::decode(env::var(CANDIDATE_REENTRY_TRUST_ENV).unwrap()).unwrap();
            let certificate =
                hex::decode(env::var(CANDIDATE_REENTRY_CERTIFICATE_ENV).unwrap()).unwrap();
            let manifest_bytes =
                hex::decode(env::var(CANDIDATE_REENTRY_MANIFEST_ENV).unwrap()).unwrap();
            let manifest =
                C2SignerImplementationManifestV1::from_canonical_bytes(&manifest_bytes).unwrap();
            let mut store = Store::open(env::var(CANDIDATE_REENTRY_STORE_ENV).unwrap()).unwrap();

            with_test_qualification_trust_root_v1(trust_bytes, || {
                let mut reached = false;
                StoreC2CandidateRuntimeVerifierV1::with_verified_c2_lifecycle(
                    &mut store,
                    &certificate,
                    &manifest,
                    |_lifecycle| reached = true,
                )
                .expect("child re-entry performs fresh certificate and runtime verification");
                assert!(reached);
            });
            return;
        }

        let signing_key = SigningKey::from_bytes(&[69_u8; 32]);
        let internal_manifest = exact_manifest();
        let manifest_bytes = internal_manifest.canonical_bytes().unwrap();
        let public_manifest =
            C2SignerImplementationManifestV1::from_canonical_bytes(&manifest_bytes).unwrap();
        let (trust_bytes, trust_identity) = trust_root(&signing_key);
        let certificate = signed_certificate(
            &signing_key,
            trust_identity,
            &internal_manifest,
            measure_current_runtime_artifact().unwrap(),
        );
        let root = tempdir().unwrap();
        let database = root.path().join("store.sqlite");
        let mut store = Store::initialize_unqualified_storage(&database).unwrap();

        with_test_qualification_trust_root_v1(trust_bytes.clone(), || {
            let mut reached = false;
            StoreC2CandidateRuntimeVerifierV1::with_verified_c2_lifecycle(
                &mut store,
                &certificate,
                &public_manifest,
                |_lifecycle| reached = true,
            )
            .expect("parent verification reaches the scoped lifecycle");
            assert!(reached);
        });
        drop(store);

        let output = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "store_generation::candidate_qualification::tests::candidate_reentry_after_exec_requires_fresh_certificate_and_runtime_verification",
            )
            .arg("--nocapture")
            .env(CANDIDATE_REENTRY_CHILD_ENV, "1")
            .env(CANDIDATE_REENTRY_TRUST_ENV, hex::encode(trust_bytes))
            .env(
                CANDIDATE_REENTRY_CERTIFICATE_ENV,
                hex::encode(certificate),
            )
            .env(CANDIDATE_REENTRY_MANIFEST_ENV, hex::encode(manifest_bytes))
            .env(CANDIDATE_REENTRY_STORE_ENV, database)
            .output()
            .expect("run candidate re-entry child");
        assert!(
            output.status.success(),
            "candidate re-entry child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn fixed_trust_source_is_not_runtime_a1_a2_or_caller_selected() {
        assert_eq!(
            C2_QUALIFICATION_TRUST_ROOT_PATH_V1,
            "/etc/nq/c2-qualification-trust-root.v1.json"
        );
        assert!(!C2_QUALIFICATION_TRUST_ROOT_IDENTITY_DOMAIN_V1.contains("runtime_dependency"));
        assert!(!C2_QUALIFICATION_TRUST_ROOT_IDENTITY_DOMAIN_V1.contains("activation"));
        let source = include_str!("candidate_qualification.rs");
        let verifier = source
            .split("pub(crate) fn verify_candidate_certificate_for_current_runtime_v1")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(verifier.contains("load_fixed_qualification_trust_root_v1"));
        assert!(!verifier.contains("GenesisAuthorityCustody"));
        assert!(!verifier.contains("trust_root_bytes:"));
    }
}
