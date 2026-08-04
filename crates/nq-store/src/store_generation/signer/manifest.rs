//! Candidate-bound Store-integrity signer implementation manifest.
//!
//! This record binds implementation inputs for later qualification.  It is
//! deliberately inert: constructing or verifying it yields no signer,
//! standing, custody, currentness, transition, or writer authority.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::result::ManifestResultV2;

const SCHEMA_V1: &str = "nq.c2_store_integrity_signer_implementation_manifest.v1";
const IDENTITY_DOMAIN_V1: &str = "nq.c2.store_integrity_signer.implementation_manifest.v1";
const CRYPTOGRAPHIC_BACKEND_V1: &str = "ed25519-dalek-v2-strict-v1";

/// Exact candidate-bound implementation inputs for the private signer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreIntegritySignerImplementationManifestV1 {
    schema: String,
    identity_domain: String,
    custody_format_identity: Sha256Digest,
    source_files: BTreeMap<String, Sha256Digest>,
    cryptographic_backend: String,
    toolchain: String,
    target_profile: String,
    qualification_assumptions: BTreeSet<String>,
    identity: Sha256Digest,
}

/// Scalar-only manifest refusal; it cannot carry signer authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SignerImplementationManifestRefusalV1 {
    #[error("the signer implementation manifest is incomplete")]
    Incomplete,
    #[error("the signer implementation manifest contains a forbidden generated output")]
    SelfContaining,
    #[error("the signer implementation manifest identity does not recompute")]
    IdentityMismatch,
    #[error("the signer implementation manifest cannot be canonicalized")]
    Canonicalization,
}

#[derive(Serialize)]
struct ManifestPreimage<'a> {
    schema: &'static str,
    identity_domain: &'static str,
    custody_format_identity: &'a Sha256Digest,
    source_files: &'a BTreeMap<String, Sha256Digest>,
    cryptographic_backend: &'static str,
    toolchain: &'a str,
    target_profile: &'a str,
    qualification_assumptions: &'a BTreeSet<String>,
}

fn prohibited_source_member(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        "target/",
        "certificate",
        "registry",
        "qualification-result",
        "implementation_manifest.v1.json",
    ]
    .iter()
    .any(|part| path.contains(part))
}

fn identity_for(
    custody_format_identity: &Sha256Digest,
    source_files: &BTreeMap<String, Sha256Digest>,
    toolchain: &str,
    target_profile: &str,
    qualification_assumptions: &BTreeSet<String>,
) -> Result<Sha256Digest, SignerImplementationManifestRefusalV1> {
    semantic_digest(&ManifestPreimage {
        schema: SCHEMA_V1,
        identity_domain: IDENTITY_DOMAIN_V1,
        custody_format_identity,
        source_files,
        cryptographic_backend: CRYPTOGRAPHIC_BACKEND_V1,
        toolchain,
        target_profile,
        qualification_assumptions,
    })
    .map_err(|_| SignerImplementationManifestRefusalV1::Canonicalization)
}

/// SG-REC-14A constructs one exact, cycle-free implementation manifest.
pub(crate) fn construct_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(
    custody_format_identity: Sha256Digest,
    source_files: BTreeMap<String, Sha256Digest>,
    toolchain: String,
    target_profile: String,
    qualification_assumptions: BTreeSet<String>,
) -> Result<StoreIntegritySignerImplementationManifestV1, SignerImplementationManifestRefusalV1> {
    if source_files.is_empty()
        || toolchain.is_empty()
        || target_profile.is_empty()
        || qualification_assumptions.is_empty()
    {
        return Err(SignerImplementationManifestRefusalV1::Incomplete);
    }
    if source_files
        .keys()
        .any(|path| path.is_empty() || prohibited_source_member(path))
    {
        return Err(SignerImplementationManifestRefusalV1::SelfContaining);
    }
    let identity = identity_for(
        &custody_format_identity,
        &source_files,
        &toolchain,
        &target_profile,
        &qualification_assumptions,
    )?;
    Ok(StoreIntegritySignerImplementationManifestV1 {
        schema: SCHEMA_V1.to_owned(),
        identity_domain: IDENTITY_DOMAIN_V1.to_owned(),
        custody_format_identity,
        source_files,
        cryptographic_backend: CRYPTOGRAPHIC_BACKEND_V1.to_owned(),
        toolchain,
        target_profile,
        qualification_assumptions,
        identity,
    })
}

/// SG-REC-14A recomputes every bound coordinate without granting authority.
pub(crate) fn verify_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> Result<ManifestResultV2, SignerImplementationManifestRefusalV1> {
    if manifest.schema != SCHEMA_V1
        || manifest.identity_domain != IDENTITY_DOMAIN_V1
        || manifest.cryptographic_backend != CRYPTOGRAPHIC_BACKEND_V1
        || manifest.source_files.is_empty()
        || manifest.toolchain.is_empty()
        || manifest.target_profile.is_empty()
        || manifest.qualification_assumptions.is_empty()
    {
        return Err(SignerImplementationManifestRefusalV1::Incomplete);
    }
    if manifest
        .source_files
        .keys()
        .any(|path| path.is_empty() || prohibited_source_member(path))
    {
        return Err(SignerImplementationManifestRefusalV1::SelfContaining);
    }
    let recomputed = identity_for(
        &manifest.custody_format_identity,
        &manifest.source_files,
        &manifest.toolchain,
        &manifest.target_profile,
        &manifest.qualification_assumptions,
    )?;
    if recomputed != manifest.identity {
        return Err(SignerImplementationManifestRefusalV1::IdentityMismatch);
    }
    Ok(ManifestResultV2::ExactImplementationManifest)
}

#[cfg(test)]
mod tests {
    use nq_protocol::sha256_bytes;

    use super::*;

    fn exact_manifest() -> StoreIntegritySignerImplementationManifestV1 {
        construct_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(
            sha256_bytes(b"custody-format"),
            BTreeMap::from([
                ("crates/nq-store/src/store_generation/signer/custody.rs".into(), sha256_bytes(b"custody")),
                ("crates/nq-store/src/store_generation/signer/coordinator.rs".into(), sha256_bytes(b"coordinator")),
            ]),
            "rustc-pinned-by-candidate".into(),
            "x86_64-unknown-linux-gnu".into(),
            BTreeSet::from(["candidate-bound-hostile-and-crash-replay".into()]),
        )
        .unwrap()
    }

    #[test]
    fn exact_manifest_is_inert_and_recomputes() {
        assert_eq!(
            verify_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(&exact_manifest()),
            Ok(ManifestResultV2::ExactImplementationManifest)
        );
    }

    #[test]
    fn generated_or_self_containing_source_refuses() {
        let result = construct_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(
            sha256_bytes(b"custody-format"),
            BTreeMap::from([("target/generated-manifest.json".into(), sha256_bytes(b"bad"))]),
            "toolchain".into(),
            "target".into(),
            BTreeSet::from(["assumption".into()]),
        );
        assert_eq!(
            result,
            Err(SignerImplementationManifestRefusalV1::SelfContaining)
        );
    }
}
