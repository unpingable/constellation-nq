//! Canonical Store-integrity signer implementation evidence and live admission.
//!
//! The wire record in this module identifies one exact implementation basis.
//! Parsing, deriving, possessing, or serializing it never grants signer
//! authority.  The process-local admission wrapper is a separate Store-owned
//! correspondence and is deliberately neither serializable nor cloneable.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::store_generation::live_c2::StoreC2AdmissionBasisV1;

pub(crate) const SIGNER_IMPLEMENTATION_MANIFEST_SCHEMA_V1: &str =
    "nq.c2_store_integrity_signer_implementation_manifest.v1";
pub(crate) const SIGNER_IMPLEMENTATION_MANIFEST_IDENTITY_DOMAIN_V1: &str =
    "nq.c2.store_integrity_signer.implementation_manifest.v1";

const MAX_SOURCE_FILES: usize = 256;
const MAX_ASSUMPTIONS: usize = 256;
const MAX_SOURCE_PATH_BYTES: usize = 512;
const MAX_SOURCE_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_BASIS_BYTES: usize = 64 * 1024 * 1024;

/// Exact byte inputs to deterministic manifest derivation.
///
/// The derivation hashes each exact blob itself; a caller cannot supply a path
/// alongside an asserted source digest.  Qualification separately proves that
/// these bytes are the members of the frozen Git tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SignerImplementationManifestDerivationInputV1 {
    pub(crate) custody_format_identity: Sha256Digest,
    pub(crate) signer_message_contract_identity: Sha256Digest,
    pub(crate) source_file_bytes: BTreeMap<String, Vec<u8>>,
    pub(crate) cryptographic_backend_identity: Sha256Digest,
    pub(crate) toolchain_identity: Sha256Digest,
    pub(crate) target_profile_identity: Sha256Digest,
    pub(crate) qualification_assumption_identities: BTreeSet<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignerImplementationManifestBasisV1 {
    custody_format_identity: Sha256Digest,
    signer_message_contract_identity: Sha256Digest,
    source_files: BTreeMap<String, Sha256Digest>,
    cryptographic_backend_identity: Sha256Digest,
    toolchain_identity: Sha256Digest,
    target_profile_identity: Sha256Digest,
    qualification_assumption_identities: BTreeSet<Sha256Digest>,
}

#[derive(Serialize)]
struct ManifestBodyV1<'a> {
    schema: &'static str,
    identity_domain: &'static str,
    custody_format_identity: &'a Sha256Digest,
    signer_message_contract_identity: &'a Sha256Digest,
    source_files: &'a BTreeMap<String, Sha256Digest>,
    cryptographic_backend_identity: &'a Sha256Digest,
    toolchain_identity: &'a Sha256Digest,
    target_profile_identity: &'a Sha256Digest,
    qualification_assumption_identities: &'a BTreeSet<Sha256Digest>,
}

/// The sole canonical signer implementation-manifest wire record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreIntegritySignerImplementationManifestV1 {
    schema: String,
    identity_domain: String,
    custody_format_identity: Sha256Digest,
    signer_message_contract_identity: Sha256Digest,
    source_files: BTreeMap<String, Sha256Digest>,
    cryptographic_backend_identity: Sha256Digest,
    toolchain_identity: Sha256Digest,
    target_profile_identity: Sha256Digest,
    qualification_assumption_identities: BTreeSet<Sha256Digest>,
    manifest_identity: Sha256Digest,
}

impl StoreIntegritySignerImplementationManifestV1 {
    #[must_use]
    pub(crate) const fn manifest_identity(&self) -> &Sha256Digest {
        &self.manifest_identity
    }

    /// Exact closed MSG-01..MSG-16 contract coordinate used by the Store
    /// backend/profile correspondence. It remains implementation evidence;
    /// returning the digest cannot admit the manifest or mint standing.
    #[must_use]
    pub(crate) const fn signer_message_contract_identity(&self) -> &Sha256Digest {
        &self.signer_message_contract_identity
    }

    #[must_use]
    pub(crate) fn source_files(&self) -> &BTreeMap<String, Sha256Digest> {
        &self.source_files
    }

    #[must_use]
    pub(crate) const fn toolchain_identity(&self) -> &Sha256Digest {
        &self.toolchain_identity
    }

    #[must_use]
    pub(crate) const fn target_profile_identity(&self) -> &Sha256Digest {
        &self.target_profile_identity
    }

    #[must_use]
    pub(crate) const fn qualification_assumption_identities(
        &self,
    ) -> &BTreeSet<Sha256Digest> {
        &self.qualification_assumption_identities
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, SignerImplementationManifestRefusalV1> {
        canonical_json_bytes(self)
            .map_err(|_| SignerImplementationManifestRefusalV1::Canonicalization)
    }

    fn body(&self) -> ManifestBodyV1<'_> {
        ManifestBodyV1 {
            schema: SIGNER_IMPLEMENTATION_MANIFEST_SCHEMA_V1,
            identity_domain: SIGNER_IMPLEMENTATION_MANIFEST_IDENTITY_DOMAIN_V1,
            custody_format_identity: &self.custody_format_identity,
            signer_message_contract_identity: &self.signer_message_contract_identity,
            source_files: &self.source_files,
            cryptographic_backend_identity: &self.cryptographic_backend_identity,
            toolchain_identity: &self.toolchain_identity,
            target_profile_identity: &self.target_profile_identity,
            qualification_assumption_identities: &self.qualification_assumption_identities,
        }
    }
}

/// Typed fail-closed manifest derivation, decoding, and admission refusals.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SignerImplementationManifestRefusalV1 {
    #[error("the signer implementation manifest is incomplete or exceeds a closed bound")]
    Incomplete,
    #[error("the signer implementation manifest source member is not normalized")]
    NoncanonicalSourceMember,
    #[error("the signer implementation manifest contains a generated or self-containing output")]
    SelfContaining,
    #[error("the signer implementation manifest contains a substituted closed constant")]
    SubstitutedClosedConstant,
    #[error("the signer implementation manifest identity does not recompute")]
    IdentityMismatch,
    #[error("the signer implementation manifest is malformed or not exact RFC 8785 bytes")]
    MalformedOrNoncanonical,
    #[error("the signer implementation manifest cannot be canonicalized")]
    Canonicalization,
    #[error("the Store manifest admission coordinates do not correspond exactly")]
    AdmissionMismatch,
    #[error("the Store manifest admission belongs to another process")]
    PriorProcessAdmission,
}

fn normalized_source_member(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_SOURCE_PATH_BYTES
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b'+')
                })
        })
}

fn prohibited_source_member(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    normalized.split('/').any(|segment| segment == "target")
        || normalized.contains("manifest.instance.json")
        || normalized.contains("certificate.instance.json")
}

fn validate_basis(
    basis: &SignerImplementationManifestBasisV1,
) -> Result<(), SignerImplementationManifestRefusalV1> {
    if basis.source_files.is_empty()
        || basis.source_files.len() > MAX_SOURCE_FILES
        || basis.qualification_assumption_identities.is_empty()
        || basis.qualification_assumption_identities.len() > MAX_ASSUMPTIONS
    {
        return Err(SignerImplementationManifestRefusalV1::Incomplete);
    }
    if basis
        .source_files
        .keys()
        .any(|path| !normalized_source_member(path))
    {
        return Err(SignerImplementationManifestRefusalV1::NoncanonicalSourceMember);
    }
    if basis
        .source_files
        .keys()
        .any(|path| prohibited_source_member(path))
    {
        return Err(SignerImplementationManifestRefusalV1::SelfContaining);
    }
    Ok(())
}

fn derive_basis_from_exact_bytes(
    input: SignerImplementationManifestDerivationInputV1,
) -> Result<SignerImplementationManifestBasisV1, SignerImplementationManifestRefusalV1> {
    if input.source_file_bytes.is_empty() || input.source_file_bytes.len() > MAX_SOURCE_FILES {
        return Err(SignerImplementationManifestRefusalV1::Incomplete);
    }
    if input
        .source_file_bytes
        .keys()
        .any(|path| !normalized_source_member(path))
    {
        return Err(SignerImplementationManifestRefusalV1::NoncanonicalSourceMember);
    }
    if input
        .source_file_bytes
        .keys()
        .any(|path| prohibited_source_member(path))
    {
        return Err(SignerImplementationManifestRefusalV1::SelfContaining);
    }
    let total = input
        .source_file_bytes
        .values()
        .try_fold(0_usize, |total, bytes| {
            if bytes.len() > MAX_SOURCE_BLOB_BYTES {
                None
            } else {
                total.checked_add(bytes.len())
            }
        });
    if !matches!(total, Some(value) if value <= MAX_SOURCE_BASIS_BYTES) {
        return Err(SignerImplementationManifestRefusalV1::Incomplete);
    }
    Ok(SignerImplementationManifestBasisV1 {
        custody_format_identity: input.custody_format_identity,
        signer_message_contract_identity: input.signer_message_contract_identity,
        source_files: input
            .source_file_bytes
            .into_iter()
            .map(|(path, bytes)| (path, sha256_bytes(&bytes)))
            .collect(),
        cryptographic_backend_identity: input.cryptographic_backend_identity,
        toolchain_identity: input.toolchain_identity,
        target_profile_identity: input.target_profile_identity,
        qualification_assumption_identities: input.qualification_assumption_identities,
    })
}

fn identity_for(
    basis: &SignerImplementationManifestBasisV1,
) -> Result<Sha256Digest, SignerImplementationManifestRefusalV1> {
    semantic_digest(&ManifestBodyV1 {
        schema: SIGNER_IMPLEMENTATION_MANIFEST_SCHEMA_V1,
        identity_domain: SIGNER_IMPLEMENTATION_MANIFEST_IDENTITY_DOMAIN_V1,
        custody_format_identity: &basis.custody_format_identity,
        signer_message_contract_identity: &basis.signer_message_contract_identity,
        source_files: &basis.source_files,
        cryptographic_backend_identity: &basis.cryptographic_backend_identity,
        toolchain_identity: &basis.toolchain_identity,
        target_profile_identity: &basis.target_profile_identity,
        qualification_assumption_identities: &basis.qualification_assumption_identities,
    })
    .map_err(|_| SignerImplementationManifestRefusalV1::Canonicalization)
}

/// Mechanically derive one exact, cycle-free implementation manifest.
pub(crate) fn derive_signer_implementation_manifest_v1(
    input: SignerImplementationManifestDerivationInputV1,
) -> Result<StoreIntegritySignerImplementationManifestV1, SignerImplementationManifestRefusalV1> {
    let basis = derive_basis_from_exact_bytes(input)?;
    validate_basis(&basis)?;
    let manifest_identity = identity_for(&basis)?;
    Ok(StoreIntegritySignerImplementationManifestV1 {
        schema: SIGNER_IMPLEMENTATION_MANIFEST_SCHEMA_V1.to_owned(),
        identity_domain: SIGNER_IMPLEMENTATION_MANIFEST_IDENTITY_DOMAIN_V1.to_owned(),
        custody_format_identity: basis.custody_format_identity,
        signer_message_contract_identity: basis.signer_message_contract_identity,
        source_files: basis.source_files,
        cryptographic_backend_identity: basis.cryptographic_backend_identity,
        toolchain_identity: basis.toolchain_identity,
        target_profile_identity: basis.target_profile_identity,
        qualification_assumption_identities: basis.qualification_assumption_identities,
        manifest_identity,
    })
}

/// Recompute every bound coordinate.  Success is evidence, never authority.
pub(crate) fn verify_signer_implementation_manifest_v1(
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> Result<(), SignerImplementationManifestRefusalV1> {
    if manifest.schema != SIGNER_IMPLEMENTATION_MANIFEST_SCHEMA_V1
        || manifest.identity_domain != SIGNER_IMPLEMENTATION_MANIFEST_IDENTITY_DOMAIN_V1
    {
        return Err(SignerImplementationManifestRefusalV1::SubstitutedClosedConstant);
    }
    let basis = SignerImplementationManifestBasisV1 {
        custody_format_identity: manifest.custody_format_identity.clone(),
        signer_message_contract_identity: manifest.signer_message_contract_identity.clone(),
        source_files: manifest.source_files.clone(),
        cryptographic_backend_identity: manifest.cryptographic_backend_identity.clone(),
        toolchain_identity: manifest.toolchain_identity.clone(),
        target_profile_identity: manifest.target_profile_identity.clone(),
        qualification_assumption_identities: manifest.qualification_assumption_identities.clone(),
    };
    validate_basis(&basis)?;
    if identity_for(&basis)? != manifest.manifest_identity {
        return Err(SignerImplementationManifestRefusalV1::IdentityMismatch);
    }
    Ok(())
}

/// Parse only the one exact canonical wire representation.
pub(crate) fn decode_signer_implementation_manifest_v1(
    bytes: &[u8],
) -> Result<StoreIntegritySignerImplementationManifestV1, SignerImplementationManifestRefusalV1> {
    let manifest: StoreIntegritySignerImplementationManifestV1 = serde_json::from_slice(bytes)
        .map_err(|_| SignerImplementationManifestRefusalV1::MalformedOrNoncanonical)?;
    if canonical_json_bytes(&manifest)
        .map_err(|_| SignerImplementationManifestRefusalV1::Canonicalization)?
        != bytes
    {
        return Err(SignerImplementationManifestRefusalV1::MalformedOrNoncanonical);
    }
    verify_signer_implementation_manifest_v1(&manifest)?;
    Ok(manifest)
}

/// Process-local Store admission of one exact manifest/candidate/runtime pair.
///
/// There is intentionally no conversion from the serializable manifest and no
/// public raw-parts constructor.  The Store-owned live-C2 driver is the only
/// production caller of the sibling-visible constructor below.
pub(crate) struct StoreAdmittedSignerImplementationManifestV1<'admission, 'store> {
    manifest: &'admission StoreIntegritySignerImplementationManifestV1,
    basis: &'admission StoreC2AdmissionBasisV1<'store>,
    creator_pid: u32,
}

impl StoreAdmittedSignerImplementationManifestV1<'_, '_> {
    pub(crate) const fn manifest(&self) -> &StoreIntegritySignerImplementationManifestV1 {
        self.manifest
    }

    pub(crate) const fn manifest_identity(&self) -> &Sha256Digest {
        &self.manifest.manifest_identity
    }

    pub(crate) const fn qualified_candidate_identity(&self) -> &Sha256Digest {
        self.basis.qualified_candidate_identity()
    }

    pub(crate) const fn source_tree_identity(&self) -> &Sha256Digest {
        self.basis.source_tree_identity()
    }

    pub(crate) const fn runtime_artifact_identity(&self) -> &Sha256Digest {
        self.basis.measured_runtime_artifact_identity()
    }

    pub(crate) const fn store_snapshot_identity(&self) -> &Sha256Digest {
        self.basis.store_snapshot_identity()
    }

    pub(crate) const fn process_identity(&self) -> &Sha256Digest {
        self.basis.process_identity()
    }

    /// Inert identity of the complete manifest/candidate/runtime admission
    /// correspondence. Signed records may retain it, but it cannot be
    /// converted back into this process-local admission.
    pub(crate) fn correspondence_identity(&self) -> Sha256Digest {
        let fields = [
            self.manifest_identity(),
            self.qualified_candidate_identity(),
            self.source_tree_identity(),
            self.runtime_artifact_identity(),
            self.basis.qualification_evidence_identity(),
            self.store_snapshot_identity(),
            self.process_identity(),
        ];
        let mut preimage = b"nq.c2.signer_manifest_admission.correspondence.v1\0".to_vec();
        for field in fields {
            preimage.extend_from_slice(&(field.as_str().len() as u64).to_be_bytes());
            preimage.extend_from_slice(field.as_str().as_bytes());
        }
        sha256_bytes(&preimage)
    }
}

/// Store-private admission seam.  `basis` must be produced by candidate/tree,
/// runtime-artifact, same-snapshot, and fresh-process verification in the live
/// C2 owner; this function does not manufacture any of those premises.
pub(crate) fn admit_signer_implementation_manifest_v1<'admission, 'store>(
    manifest: &'admission StoreIntegritySignerImplementationManifestV1,
    basis: &'admission StoreC2AdmissionBasisV1<'store>,
) -> Result<
    StoreAdmittedSignerImplementationManifestV1<'admission, 'store>,
    SignerImplementationManifestRefusalV1,
> {
    verify_signer_implementation_manifest_v1(manifest)?;
    basis
        .verify_same_process()
        .map_err(|_| SignerImplementationManifestRefusalV1::PriorProcessAdmission)?;
    if manifest.manifest_identity() != basis.qualified_manifest_identity() {
        return Err(SignerImplementationManifestRefusalV1::AdmissionMismatch);
    }
    Ok(StoreAdmittedSignerImplementationManifestV1 {
        manifest,
        basis,
        creator_pid: std::process::id(),
    })
}

pub(crate) fn verify_store_admitted_signer_implementation_manifest_v1<'admission, 'store>(
    admission: &StoreAdmittedSignerImplementationManifestV1<'admission, 'store>,
    expected_manifest: &StoreIntegritySignerImplementationManifestV1,
    expected_basis: &StoreC2AdmissionBasisV1<'store>,
) -> Result<(), SignerImplementationManifestRefusalV1> {
    verify_store_admitted_signer_implementation_manifest_basis_v1(admission, expected_basis)?;
    if !std::ptr::eq(admission.manifest, expected_manifest) {
        return Err(SignerImplementationManifestRefusalV1::AdmissionMismatch);
    }
    Ok(())
}

/// Verify exact borrowed Store-basis provenance without exposing the
/// manifest evidence object or accepting equal detached coordinates.
pub(crate) fn verify_store_admitted_signer_implementation_manifest_basis_v1<'admission, 'store>(
    admission: &StoreAdmittedSignerImplementationManifestV1<'admission, 'store>,
    expected_basis: &StoreC2AdmissionBasisV1<'store>,
) -> Result<(), SignerImplementationManifestRefusalV1> {
    verify_signer_implementation_manifest_v1(admission.manifest)?;
    if admission.creator_pid != std::process::id() || admission.basis.verify_same_process().is_err()
    {
        return Err(SignerImplementationManifestRefusalV1::PriorProcessAdmission);
    }
    if !std::ptr::eq(admission.basis, expected_basis) {
        return Err(SignerImplementationManifestRefusalV1::AdmissionMismatch);
    }
    Ok(())
}

// Preserve the matrix-named SG-REC-14A entry points while making them aliases
// of the sole canonical representation rather than a second contract.
pub(crate) fn construct_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(
    input: SignerImplementationManifestDerivationInputV1,
) -> Result<StoreIntegritySignerImplementationManifestV1, SignerImplementationManifestRefusalV1> {
    derive_signer_implementation_manifest_v1(input)
}

pub(crate) fn verify_sg_rec_14a_implementation_manifest_half_sg_rec_storeintegritysignerimplementationmanifestv1_binds(
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> Result<(), SignerImplementationManifestRefusalV1> {
    verify_signer_implementation_manifest_v1(manifest)
}

#[cfg(test)]
mod tests {
    use nq_protocol::{canonical_json_bytes, sha256_bytes};
    use serde_json::{Value, json};

    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        sha256_bytes(label.as_bytes())
    }

    fn exact_input() -> SignerImplementationManifestDerivationInputV1 {
        SignerImplementationManifestDerivationInputV1 {
            custody_format_identity: digest("custody-format"),
            signer_message_contract_identity: digest("msg-01-through-msg-16"),
            source_file_bytes: BTreeMap::from([
                (
                    "crates/nq-store/src/store_generation/signer/custody.rs".into(),
                    b"custody".to_vec(),
                ),
                (
                    "crates/nq-store/src/store_generation/signer/manifest.rs".into(),
                    b"manifest-derivation-source".to_vec(),
                ),
                (
                    "schemas/c2/nq.c2_store_integrity_signer_implementation_manifest.v1.json"
                        .into(),
                    b"manifest-schema-source".to_vec(),
                ),
            ]),
            cryptographic_backend_identity: digest("ed25519-dalek-v2-strict"),
            toolchain_identity: digest("rust-toolchain"),
            target_profile_identity: digest("x86_64-linux-profile"),
            qualification_assumption_identities: BTreeSet::from([
                digest("sha256-collision-resistance"),
                digest("os-process-freshness"),
            ]),
        }
    }

    fn exact_manifest() -> StoreIntegritySignerImplementationManifestV1 {
        derive_signer_implementation_manifest_v1(exact_input()).unwrap()
    }

    #[test]
    fn canonical_golden_round_trip_and_identity_are_exact() {
        let manifest = exact_manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        const GOLDEN_IDENTITY: &str =
            "sha256:649e9c639f7450ac2b3146634a306028a12b991a0b8096ca382de975db73f19d";
        const GOLDEN_BYTES: &str = r#"{"cryptographic_backend_identity":"sha256:2be6c218614162c331586dc48bac99754907998b77528c90a005e65d5efffff3","custody_format_identity":"sha256:14a45d5e0039028953cc96140892343d36d10d536b51b8783ab0fb051e4c4772","identity_domain":"nq.c2.store_integrity_signer.implementation_manifest.v1","manifest_identity":"sha256:649e9c639f7450ac2b3146634a306028a12b991a0b8096ca382de975db73f19d","qualification_assumption_identities":["sha256:247eb8db741b801c6e6cdeb63ee47af78ee8690695f84117e9537c538603962b","sha256:9f5c14503553cd495acf0040f0b6686afe50375b0cadb78dd4d1f1e9d6b4c704"],"schema":"nq.c2_store_integrity_signer_implementation_manifest.v1","signer_message_contract_identity":"sha256:7cc3fd8da8248cab3ed3d6124b8f8eaf8bfa262c10e466f21d556666d4c7985e","source_files":{"crates/nq-store/src/store_generation/signer/custody.rs":"sha256:21a7f61c15cef4ddedae076d6b7393f1d3d4a9b5c870df60ca0c59b195ef1602","crates/nq-store/src/store_generation/signer/manifest.rs":"sha256:20f69bd23a47db05c7155a50f6ef1b20e8fa97028ad70ab22a24fe72b6875f5e","schemas/c2/nq.c2_store_integrity_signer_implementation_manifest.v1.json":"sha256:6e4c1155668123988a269472cabb354922680c600c7277031f5f16b16d8892bb"},"target_profile_identity":"sha256:145d7cca91428c6d4ad4fc0105bbcfcdcfb4dc4256ebc8f0fa2c42e451356dd7","toolchain_identity":"sha256:335ddbce02d068207f42ecdac988ee267eb014a7a1e7ffe8df7bedd66f716899"}"#;
        assert_eq!(manifest.manifest_identity().as_str(), GOLDEN_IDENTITY);
        assert_eq!(bytes, GOLDEN_BYTES.as_bytes());
        assert_eq!(
            decode_signer_implementation_manifest_v1(&bytes),
            Ok(manifest.clone())
        );

        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value.get("manifest_identity").and_then(Value::as_str),
            Some(manifest.manifest_identity().as_str())
        );
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "cryptographic_backend_identity".into(),
                "custody_format_identity".into(),
                "identity_domain".into(),
                "manifest_identity".into(),
                "qualification_assumption_identities".into(),
                "schema".into(),
                "signer_message_contract_identity".into(),
                "source_files".into(),
                "target_profile_identity".into(),
                "toolchain_identity".into(),
            ])
        );
    }

    #[test]
    fn noncanonical_unknown_and_duplicate_wire_members_refuse() {
        let bytes = exact_manifest().canonical_bytes().unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("authority".into(), json!("none"));
        assert_eq!(
            decode_signer_implementation_manifest_v1(&canonical_json_bytes(&value).unwrap()),
            Err(SignerImplementationManifestRefusalV1::MalformedOrNoncanonical)
        );

        let spaced =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&bytes).unwrap()).unwrap();
        assert_eq!(
            decode_signer_implementation_manifest_v1(&spaced),
            Err(SignerImplementationManifestRefusalV1::MalformedOrNoncanonical)
        );

        let canonical = String::from_utf8(bytes).unwrap();
        let duplicate_schema = canonical.replacen(
            '{',
            r#"{"schema":"nq.c2_store_integrity_signer_implementation_manifest.v1","#,
            1,
        );
        assert_eq!(
            decode_signer_implementation_manifest_v1(duplicate_schema.as_bytes()),
            Err(SignerImplementationManifestRefusalV1::MalformedOrNoncanonical)
        );
    }

    #[test]
    fn every_bound_coordinate_and_source_content_changes_identity() {
        let original = exact_manifest();
        let original_identity = original.manifest_identity().clone();
        let mut mutations: Vec<Box<dyn Fn(&mut SignerImplementationManifestDerivationInputV1)>> = vec![
            Box::new(|b| b.custody_format_identity = digest("changed-custody")),
            Box::new(|b| b.signer_message_contract_identity = digest("changed-messages")),
            Box::new(|b| b.cryptographic_backend_identity = digest("changed-crypto")),
            Box::new(|b| b.toolchain_identity = digest("changed-toolchain")),
            Box::new(|b| b.target_profile_identity = digest("changed-target")),
            Box::new(|b| {
                b.qualification_assumption_identities
                    .insert(digest("changed-assumption"));
            }),
            Box::new(|b| {
                b.source_file_bytes.insert(
                    "crates/nq-store/src/store_generation/signer/custody.rs".into(),
                    b"changed-source-bytes".to_vec(),
                );
            }),
        ];
        for mutation in &mut mutations {
            let mut input = exact_input();
            mutation(&mut input);
            let changed = derive_signer_implementation_manifest_v1(input).unwrap();
            assert_ne!(changed.manifest_identity(), &original_identity);
        }
    }

    #[test]
    fn generated_self_containing_and_non_normalized_paths_refuse() {
        let mut generated = exact_input();
        generated
            .source_file_bytes
            .insert("target/manifest.instance.json".into(), b"bad".to_vec());
        assert_eq!(
            derive_signer_implementation_manifest_v1(generated),
            Err(SignerImplementationManifestRefusalV1::SelfContaining)
        );

        let mut escaped = exact_input();
        escaped
            .source_file_bytes
            .insert("crates/nq-store/../secret".into(), b"bad".to_vec());
        assert_eq!(
            derive_signer_implementation_manifest_v1(escaped),
            Err(SignerImplementationManifestRefusalV1::NoncanonicalSourceMember)
        );
    }

    #[test]
    fn schema_and_runtime_wire_fields_are_exactly_one_shape() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../../schemas/c2/nq.c2_store_integrity_signer_implementation_manifest.v1.json"
        ))
        .unwrap();
        let required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let runtime = serde_json::to_value(exact_manifest())
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(required, properties);
        assert_eq!(required, runtime);
        assert_eq!(
            schema["properties"]["schema"]["const"],
            SIGNER_IMPLEMENTATION_MANIFEST_SCHEMA_V1
        );
        assert_eq!(
            schema["properties"]["identity_domain"]["const"],
            SIGNER_IMPLEMENTATION_MANIFEST_IDENTITY_DOMAIN_V1
        );
    }

    #[test]
    fn changed_manifest_cannot_substitute_for_the_original_evidence() {
        let original = exact_manifest();
        let changed = derive_signer_implementation_manifest_v1({
            let mut input = exact_input();
            input.toolchain_identity = digest("other-toolchain");
            input
        })
        .unwrap();
        assert_ne!(original.manifest_identity(), changed.manifest_identity());
        assert_ne!(
            original.canonical_bytes().unwrap(),
            changed.canonical_bytes().unwrap()
        );
    }
}
