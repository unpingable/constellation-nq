//! Immutable source-schema provenance for the runtime contract package.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};

use crate::{CAPACITY_IJSON_SAFE_INTEGER_MAX_V1, ContractError, Result, RuntimeSchema};

/// Exact skunkworks decision commit from which the package was implemented.
pub const CONTRACT_SOURCE_COMMIT: &str = "d8aba7b728236120e0dfd05ba6feb3e64fc3647d";
/// Exact source tree at the ratified decision commit.
pub const CONTRACT_SOURCE_TREE: &str = "b88a7a9ad380ed770d936f54f6da7eef1a9a15fe";
/// Source path inside the skunkworks repository.
pub const CONTRACT_SOURCE_PATH: &str = "audits/nq-host-role-runtime-contract-v1";

const MANIFEST_BYTES: &[u8] = include_bytes!("../assets/manifest.json");
const NATIVE_CORRESPONDENCE_MANIFEST_BYTES: &[u8] =
    include_bytes!("../assets/native-correspondence-manifest.v1.json");
const CAPACITY_EXTENSION_MANIFEST_BYTES: &[u8] =
    include_bytes!("../assets/custody-capacity-extension-manifest.v1.json");
const CUSTODY_CARRIER_MAP_BYTES: &[u8] = include_bytes!("../assets/nq.custody_carrier_map.v1.json");
const V3_PROJECTION_CAPSULE_BOUND_MANIFEST_BYTES: &[u8] =
    include_bytes!("../assets/nq.v3_projection_capsule_bound_manifest.v1.json");
const V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES: &[u8] =
    include_bytes!("../assets/nq.v3_projection_capsule_bound_manifest.v2.json");
const V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES: &[u8] =
    include_bytes!("../assets/nq.v3_projection_capsule_bound_qualification.v1.json");
const CORRECTED_SPECIMEN_BYTES: &[u8] =
    include_bytes!("../assets/host-role-runtime-records.v1.json");

/// Independent identity of the implementation-era corrected specimen.
pub const CORRECTED_SPECIMEN_IDENTITY: &str =
    "nq.host_role_runtime_specimen.implementation_corrected.v1";
/// SHA-256 of the exact corrected specimen bytes embedded by this package.
pub const CORRECTED_SPECIMEN_SHA256: &str =
    "sha256:263f9ccf4a0de93762188b49701f3da88a87e1d49e6c2a86f6104ba92261d774";
/// Identity of the additive native-correspondence contract surface.
pub const NATIVE_CORRESPONDENCE_EXTENSION_IDENTITY: &str = "nq.native_correspondence_carriers.v1";
/// Content identity of the exact campaign design record from which the
/// additive correspondence carriers were implemented.
pub const NATIVE_CORRESPONDENCE_SOURCE_SHA256: &str =
    "sha256:c2240ce831a45b0cc6f9dec2819a4def100196c0db2e4084155935a71dcc094a";
/// Identity of the additive request/invocation capacity contract surface.
pub const CAPACITY_EXTENSION_IDENTITY: &str = "nq.custody_capacity_contract.v1";
/// Content identity of the exact physical-capacity supplement from which this
/// additive package was implemented.
pub const CAPACITY_EXTENSION_SOURCE_SHA256: &str =
    "sha256:c455c06a36ec38b0ddb6c589c046890267fb5409b9a9a841ca4762786622c5ff";

/// Package provenance record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSource {
    /// Repository identity.
    pub repository: String,
    /// Immutable commit.
    pub commit: String,
    /// Exact tree.
    pub tree: String,
    /// Contract directory.
    pub path: String,
}

/// Content-addressed source record for an additive contract extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentAddressedSource {
    /// Repository identity.
    pub repository: String,
    /// Repository-relative source path.
    pub path: String,
    /// SHA-256 of the exact source-record bytes.
    pub sha256: Sha256Digest,
}

/// One exact schema asset under the provenance rules of its containing
/// manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaAsset {
    /// Contract schema identity.
    pub schema: String,
    /// Source or embedded path identified by the containing manifest.
    pub source_path: String,
    /// SHA-256 of exact source bytes.
    pub sha256: Sha256Digest,
}

/// One exact static asset governed by a content-addressed extension manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticAsset {
    /// Stable asset identity.
    pub identity: String,
    /// JSON schema applied to the exact asset bytes.
    pub schema: String,
    /// Embedded path identified by the containing manifest.
    pub source_path: String,
    /// SHA-256 of exact source bytes.
    pub sha256: Sha256Digest,
}

/// One explicit unearned product gate carried by an additive contract
/// package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityExtensionQualificationGap {
    /// Stable gate identity.
    pub gate: String,
    /// Closed status vocabulary; the retained independent C3 gate is blocked.
    pub status: String,
    /// Exact later evidence required to clear the gate.
    pub required_evidence: String,
    /// Load-bearing product consequence while the gate remains open.
    pub consequence: String,
}

/// Embedded package manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractPackageManifest {
    /// Closed package-manifest schema.
    pub schema: String,
    /// Immutable source revision.
    pub contract_source: ContractSource,
    /// Digest definition.
    pub digest_basis: String,
    /// Exact frozen 3A schema assets supported by this crate.
    pub assets: Vec<SchemaAsset>,
    /// Authority boundaries retained by the package.
    pub nonclaims: Vec<String>,
}

/// Embedded manifest for additive, content-addressed contract schemas.
///
/// It is separate from [`ContractPackageManifest`] so schemas added during
/// Campaign 3B cannot be misrepresented as bytes from the frozen 3A decision
/// commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractExtensionManifest {
    /// Closed extension-manifest schema.
    pub schema: String,
    /// Stable extension identity.
    pub extension_identity: String,
    /// Exact content-addressed campaign source.
    pub source_record: ContentAddressedSource,
    /// Digest definition.
    pub digest_basis: String,
    /// Exact additive schemas supported by this crate.
    pub assets: Vec<SchemaAsset>,
    /// Authority and correspondence boundaries retained by the extension.
    pub nonclaims: Vec<String>,
}

/// Embedded capacity-extension manifest.
///
/// Schema assets and static assets remain separate populations so a static
/// carrier cannot be mistaken for a schema merely because both are JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityExtensionManifest {
    /// Closed capacity-extension manifest schema.
    pub schema: String,
    /// Stable extension identity.
    pub extension_identity: String,
    /// Exact content-addressed campaign source.
    pub source_record: ContentAddressedSource,
    /// Digest definition.
    pub digest_basis: String,
    /// Exact schemas supported by this extension.
    pub schema_assets: Vec<SchemaAsset>,
    /// Exact non-schema static carriers supported by this extension.
    pub static_assets: Vec<StaticAsset>,
    /// Later product-selection gates not earned by the pure C1 package.
    pub qualification_gaps: Vec<CapacityExtensionQualificationGap>,
    /// Authority and correspondence boundaries retained by the extension.
    pub nonclaims: Vec<String>,
}

/// Exact embedded artifacts that jointly earn the positive CAP-H14 boundary.
///
/// The manifest's qualification basis deliberately excludes the qualification
/// reference and gap state. The separately identified carrier then binds that
/// acyclic basis, while the manifest binds the carrier's semantic identity and
/// exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedV3ProjectionCapsuleBoundAssets {
    /// Exact qualified v2 manifest bytes.
    pub manifest_bytes: &'static [u8],
    /// Exact positive qualification-carrier bytes.
    pub qualification_bytes: &'static [u8],
    /// Digest of the acyclic, verdict-bearing v2 manifest projection.
    pub qualification_basis_sha256: Sha256Digest,
    /// Digest of the exact v2 manifest bytes.
    pub manifest_sha256: Sha256Digest,
    /// Digest of the exact qualification-carrier bytes.
    pub qualification_sha256: Sha256Digest,
    /// Exact independently reviewed identity already validated from the carrier.
    pub post_acceptance_review_identity: String,
    /// Exact independently reviewed records path already validated from the carrier.
    pub post_acceptance_review_path: String,
    /// Digest of the exact independently reviewed report bytes.
    pub post_acceptance_review_sha256: Sha256Digest,
}

type QualificationSourceEvidence = (
    BTreeSet<String>,
    BTreeSet<(String, String)>,
    BTreeSet<String>,
);

/// Parses and verifies the embedded frozen-3A package manifest.
///
/// # Errors
///
/// Refuses source substitution, unknown/missing/duplicate assets, malformed
/// digests, or changed nonclaim boundaries.
pub fn verified_package_manifest() -> Result<ContractPackageManifest> {
    let manifest: ContractPackageManifest = serde_json::from_slice(MANIFEST_BYTES)?;
    if manifest.schema != "nq.host_role_contract_package.v1"
        || manifest.contract_source.repository != "skunkworks"
        || manifest.contract_source.commit != CONTRACT_SOURCE_COMMIT
        || manifest.contract_source.tree != CONTRACT_SOURCE_TREE
        || manifest.contract_source.path != CONTRACT_SOURCE_PATH
        || manifest.digest_basis != "sha256 of exact source schema bytes"
    {
        return Err(ContractError::AssetManifestSubstitution);
    }

    let expected = expected_assets();
    let mut seen = BTreeSet::new();
    for asset in &manifest.assets {
        if !seen.insert(asset.schema.as_str()) {
            return Err(ContractError::DuplicateSchemaAsset(asset.schema.clone()));
        }
        let expected_digest = expected
            .get(asset.schema.as_str())
            .ok_or_else(|| ContractError::UnknownSchemaAsset(asset.schema.clone()))?;
        if &asset.sha256 != expected_digest {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.schema.clone(),
            ));
        }
        let expected_path = format!("schemas/{}.schema.json", asset.schema);
        if asset.source_path != expected_path {
            return Err(ContractError::SchemaAssetPathMismatch(asset.schema.clone()));
        }
        let embedded = embedded_schema_bytes(&asset.schema)
            .ok_or_else(|| ContractError::MissingSchemaAsset(asset.schema.clone()))?;
        if sha256_bytes(embedded) != asset.sha256 {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.schema.clone(),
            ));
        }
    }
    if seen.len() != expected.len() {
        return Err(ContractError::MissingSchemaAssets);
    }
    for schema in RuntimeSchema::ALL
        .into_iter()
        .filter(|schema| schema.is_frozen_3a())
    {
        if !seen.contains(schema.as_str()) {
            return Err(ContractError::MissingSchemaAsset(
                schema.as_str().to_owned(),
            ));
        }
    }
    if !seen.contains("nq.host_role_common.v1")
        || manifest.nonclaims
            != [
                "schema digest binding is not live-engine correspondence",
                "contract possession grants no invocation or administrative authority",
                "the package owns no recurrence, posture, reliance, or action",
            ]
    {
        return Err(ContractError::AssetManifestSubstitution);
    }
    Ok(manifest)
}

/// Parses and verifies the additive physical-capacity extension package.
///
/// This verifies the extension's exact embedded bytes, the frozen blocked-v1
/// candidate, the additive presence-based CAP-H14 v2 qualification pair, and
/// its still-independent Store-owned C3 qualification-gap declaration.
///
/// # Errors
///
/// Refuses source substitution, unknown/missing/duplicate schema or static
/// assets, digest/path substitution, malformed static carriers, and weakened
/// nonclaims.
pub fn verified_capacity_extension_manifest() -> Result<CapacityExtensionManifest> {
    let manifest: CapacityExtensionManifest =
        serde_json::from_slice(CAPACITY_EXTENSION_MANIFEST_BYTES)?;
    if manifest.schema != "nq.host_role_contract_capacity_extension_package.v1"
        || manifest.extension_identity != CAPACITY_EXTENSION_IDENTITY
        || manifest.source_record.repository != "skunkworks"
        || manifest.source_record.path
            != "audits/nq-host-role-runtime-seam-v1/records/physical-aggregate-custody-capacity-supplement.md"
        || manifest.source_record.sha256.as_str() != CAPACITY_EXTENSION_SOURCE_SHA256
        || manifest.digest_basis != "sha256 of exact embedded asset bytes"
    {
        return Err(ContractError::AssetManifestSubstitution);
    }

    let expected_schemas = expected_capacity_schema_assets();
    let mut seen_schemas = BTreeSet::new();
    for asset in &manifest.schema_assets {
        if !seen_schemas.insert(asset.schema.as_str()) {
            return Err(ContractError::DuplicateSchemaAsset(asset.schema.clone()));
        }
        let expected_digest = expected_schemas
            .get(asset.schema.as_str())
            .ok_or_else(|| ContractError::UnknownSchemaAsset(asset.schema.clone()))?;
        if &asset.sha256 != expected_digest {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.schema.clone(),
            ));
        }
        let expected_path = format!("schemas/{}.schema.json", asset.schema);
        if asset.source_path != expected_path {
            return Err(ContractError::SchemaAssetPathMismatch(asset.schema.clone()));
        }
        let embedded = embedded_schema_bytes(&asset.schema)
            .ok_or_else(|| ContractError::MissingSchemaAsset(asset.schema.clone()))?;
        if sha256_bytes(embedded) != asset.sha256 {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.schema.clone(),
            ));
        }
    }
    if seen_schemas.len() != expected_schemas.len()
        || RuntimeSchema::ALL
            .into_iter()
            .filter(|schema| schema.is_capacity_extension())
            .any(|schema| !seen_schemas.contains(schema.as_str()))
        || !seen_schemas.contains("nq.custody_reservation_plan.v1")
        || !seen_schemas.contains("nq.custody_carrier_map.v1")
        || !seen_schemas.contains("nq.v3_projection_capsule_bound_manifest.v1")
        || !seen_schemas.contains("nq.v3_projection_capsule_bound_manifest.v2")
        || !seen_schemas.contains("nq.v3_projection_capsule_bound_qualification.v1")
    {
        return Err(ContractError::MissingSchemaAssets);
    }

    let expected_static = expected_capacity_static_assets();
    let mut seen_static = BTreeSet::new();
    for asset in &manifest.static_assets {
        if !seen_static.insert(asset.identity.as_str()) {
            return Err(ContractError::DuplicateSchemaAsset(asset.identity.clone()));
        }
        let expected = expected_static
            .get(asset.identity.as_str())
            .ok_or_else(|| ContractError::UnknownSchemaAsset(asset.identity.clone()))?;
        if asset.schema != expected.0
            || asset.source_path != expected.1
            || asset.sha256 != expected.2
        {
            return Err(ContractError::AssetManifestSubstitution);
        }
        let bytes = embedded_capacity_static_asset(&asset.identity)
            .ok_or_else(|| ContractError::MissingSchemaAsset(asset.identity.clone()))?;
        if sha256_bytes(bytes) != asset.sha256 {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.identity.clone(),
            ));
        }
    }
    if seen_static.len() != expected_static.len() {
        return Err(ContractError::MissingSchemaAssets);
    }

    verified_custody_carrier_map()?;
    inspected_candidate_v3_projection_capsule_bound_manifest()?;
    require_qualified_v3_projection_capsule_bound_manifest_v2()?;
    validate_capacity_extension_boundaries(&manifest)?;
    Ok(manifest)
}

fn validate_capacity_extension_boundaries(manifest: &CapacityExtensionManifest) -> Result<()> {
    if manifest.qualification_gaps
        != [CapacityExtensionQualificationGap {
            gate: STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE.into(),
            status: "blocked".into(),
            required_evidence: "Store-owned construction binding the exact qualified manifest, evaluator, source set, candidate output, and derived projection-capsule bound".into(),
            consequence: "capacity allocation records remain authority-neutral and cannot enter product graph or completed delivery selection".into(),
        }]
        || manifest.nonclaims
        != [
            "capacity contract validation performs no filesystem allocation or Store mutation",
            "a reservation plan grants no invocation, reliance, authorization, or action",
            "a capacity allocation record does not establish request acceptance, launch, or diagnostic result",
            "capacity allocation validation establishes internal arithmetic only, not evaluator/source-set correspondence or Store-owned construction",
            "allocation identity neutralizes only its root identity, derived occurrence identities, and allocation backlinks",
            "schema and static-asset validation is not live-engine correspondence",
        ]
    {
        return Err(ContractError::AssetManifestSubstitution);
    }
    Ok(())
}

/// Verifies and returns the exact custody-carrier map.
///
/// # Errors
///
/// Refuses digest, schema, equation, component, or nonclaim substitution.
pub fn verified_custody_carrier_map() -> Result<&'static [u8]> {
    verify_capacity_static_asset("nq.custody_carrier_map.v1", CUSTODY_CARRIER_MAP_BYTES)?;
    let value: serde_json::Value = serde_json::from_slice(CUSTODY_CARRIER_MAP_BYTES)?;
    crate::schema::validate_capacity_document("nq.custody_carrier_map.v1", &value)?;
    validate_custody_carrier_map(&value)?;
    Ok(CUSTODY_CARRIER_MAP_BYTES)
}

/// Inspects and returns the exact candidate V3 projection-capsule bound
/// manifest.
///
/// The embedded candidate is required to state that `CAP-H14` remains
/// blocked. Successful inspection establishes only schema, provenance, and
/// boundary integrity; it does not qualify the bound for pre-effect capacity
/// decisions.
///
/// # Errors
///
/// Refuses digest, schema, source-cut, cardinality, field-family, semantic
/// variant, or nonclaim substitution.
pub fn inspected_candidate_v3_projection_capsule_bound_manifest() -> Result<&'static [u8]> {
    verify_capacity_static_asset(
        "nq.v3_projection_capsule_bound_manifest.v1",
        V3_PROJECTION_CAPSULE_BOUND_MANIFEST_BYTES,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_BYTES)?;
    crate::schema::validate_capacity_document(
        "nq.v3_projection_capsule_bound_manifest.v1",
        &value,
    )?;
    validate_v3_projection_capsule_bound_manifest(&value)?;
    Ok(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_BYTES)
}

/// Requires the candidate V3 projection-capsule bound to have no blocked
/// qualification gate.
///
/// Candidate inspection remains independently available for audit. This
/// stricter helper is the only suitable contract-graph gate for a completed
/// production selection: it derives the refusal from the exact embedded
/// machine-readable gap records and accepts no caller override.
///
/// # Errors
///
/// Returns [`ContractError::CapacityAssetValidation`] naming every blocked
/// gate after first completing exact candidate inspection.
pub fn require_qualified_v3_projection_capsule_bound_manifest() -> Result<&'static [u8]> {
    let bytes = inspected_candidate_v3_projection_capsule_bound_manifest()?;
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let blocked = value["qualification_gaps"]
        .as_array()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_manifest.v1",
                "qualification-gap inventory absent",
            )
        })?
        .iter()
        .filter(|gap| gap["status"].as_str() == Some("blocked"))
        .filter_map(|gap| gap["gate"].as_str())
        .collect::<Vec<_>>();
    if blocked.is_empty() {
        Ok(bytes)
    } else {
        Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            &format!(
                "production qualification blocked by gate(s): {}",
                blocked.join(", ")
            ),
        ))
    }
}

/// Inspects the additive qualified-v2 projection-capsule bound manifest.
///
/// This establishes the exact v2 census and its acyclic qualification-basis
/// digest. It does not by itself establish CAP-H14: callers requiring the
/// positive gate must use
/// [`require_qualified_v3_projection_capsule_bound_manifest_v2`], which also
/// verifies the separate qualification carrier and the bidirectional binding.
///
/// # Errors
///
/// Refuses schema, source-cut, census, basis, gap-state, or nonclaim
/// substitution.
pub fn inspected_qualified_v3_projection_capsule_bound_manifest_v2() -> Result<&'static [u8]> {
    verify_capacity_static_asset(
        "nq.v3_projection_capsule_bound_manifest.v2",
        V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES)?;
    crate::schema::validate_capacity_document(
        "nq.v3_projection_capsule_bound_manifest.v2",
        &value,
    )?;
    validate_v3_projection_capsule_bound_manifest_v2(&value)?;
    Ok(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES)
}

/// Verifies the positive CAP-H14 qualification carrier as a standalone
/// content-addressed artifact.
///
/// Standalone verification proves its closed evidence shape, typed
/// disposition conditionals, exact populations, accepted resource budget,
/// semantic identity, and non-authority boundary. The joint accessor remains
/// responsible for matching it to the exact v2 manifest basis and bytes.
///
/// # Errors
///
/// Refuses missing, substituted, duplicated, unbudgeted, contradictory, or
/// incompletely attributed qualification evidence.
pub fn verified_v3_projection_capsule_bound_qualification_v1() -> Result<&'static [u8]> {
    verify_capacity_static_asset(
        "nq.v3_projection_capsule_bound_qualification.v1",
        V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES)?;
    crate::schema::validate_capacity_document(
        "nq.v3_projection_capsule_bound_qualification.v1",
        &value,
    )?;
    validate_v3_projection_capsule_bound_qualification_v1(&value)?;
    Ok(V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES)
}

/// Requires the complete, presence-based positive CAP-H14 artifact pair.
///
/// An empty v2 gap list is intentionally insufficient. Qualification is
/// earned only when the independently embedded carrier verifies, binds the
/// exact acyclic v2 basis, and is itself bound by semantic identity and exact
/// byte digest from the v2 manifest.
///
/// This pure C1 gate grants no C2 physical-carrier authority and does not
/// satisfy the independent C3 Store-owned construction gate.
///
/// # Errors
///
/// Refuses either absent/invalid artifact or any cross-artifact substitution.
pub fn require_qualified_v3_projection_capsule_bound_manifest_v2()
-> Result<QualifiedV3ProjectionCapsuleBoundAssets> {
    let manifest_bytes = inspected_qualified_v3_projection_capsule_bound_manifest_v2()?;
    let qualification_bytes = verified_v3_projection_capsule_bound_qualification_v1()?;
    let manifest: serde_json::Value = serde_json::from_slice(manifest_bytes)?;
    let qualification: serde_json::Value = serde_json::from_slice(qualification_bytes)?;
    let (qualification_basis_sha256, qualification_sha256) =
        validate_v3_projection_capsule_qualification_pair(
            &manifest,
            &qualification,
            qualification_bytes,
        )?;
    let review = &qualification["implementation_bindings"]["post_acceptance_review"];
    let post_acceptance_review_identity = review["identity"]
        .as_str()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "validated post-acceptance review identity is absent",
            )
        })?
        .to_owned();
    let post_acceptance_review_path = review["path"]
        .as_str()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "validated post-acceptance review path is absent",
            )
        })?
        .to_owned();
    let post_acceptance_review_sha256 =
        Sha256Digest::parse(review["sha256"].as_str().ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "validated post-acceptance review digest is absent",
            )
        })?)
        .map_err(|_| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "validated post-acceptance review digest is malformed",
            )
        })?;

    Ok(QualifiedV3ProjectionCapsuleBoundAssets {
        manifest_bytes,
        qualification_bytes,
        qualification_basis_sha256,
        manifest_sha256: sha256_bytes(manifest_bytes),
        qualification_sha256,
        post_acceptance_review_identity,
        post_acceptance_review_path,
        post_acceptance_review_sha256,
    })
}

fn validate_v3_projection_capsule_qualification_pair(
    manifest: &serde_json::Value,
    qualification: &serde_json::Value,
    qualification_bytes: &[u8],
) -> Result<(Sha256Digest, Sha256Digest)> {
    let qualification_basis_sha256 = v2_qualification_basis_digest(manifest)?;
    let manifest_basis = manifest["qualification_basis"]["digest"]
        .as_str()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_manifest.v2",
                "qualification basis digest absent",
            )
        })?;
    let carrier_basis = qualification["qualification_basis"]["digest"]
        .as_str()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "qualification basis digest absent",
            )
        })?;
    if manifest_basis != qualification_basis_sha256.as_str()
        || carrier_basis != qualification_basis_sha256.as_str()
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v2",
            "qualification basis binding differs",
        ));
    }

    let qualification_sha256 = sha256_bytes(qualification_bytes);
    let qualification_id = qualification_semantic_identity(qualification)?;
    if manifest["cap_h14_qualification"]["schema"].as_str()
        != Some("nq.v3_projection_capsule_bound_qualification.v1")
        || manifest["cap_h14_qualification"]["qualification_id"].as_str()
            != Some(qualification_id.as_str())
        || manifest["cap_h14_qualification"]["canonical_bytes_sha256"].as_str()
            != Some(qualification_sha256.as_str())
        || qualification["qualification_id"].as_str() != Some(qualification_id.as_str())
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v2",
            "positive qualification identity or exact-byte binding differs",
        ));
    }
    Ok((qualification_basis_sha256, qualification_sha256))
}

/// Machine-readable name of the later gate that must remain closed until the
/// Store, rather than a caller, constructs and verifies the exact capacity
/// allocation from the qualified capsule-bound evaluator output.
pub const STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE: &str =
    "C3-STORE-OWNED-CAPACITY-ALLOCATION-CONSTRUCTION";

/// Refuse product selection of a capacity allocation until the Store-owned
/// construction and source/output correspondence required by Checkpoint C3
/// exists.
///
/// Clearing the independent CAP-H14 bound-qualification gap must not make a
/// caller-carried `projection_capsule_bound_bytes` value authoritative.  The
/// eventual C3 implementation must bind the exact qualified manifest,
/// evaluator, source-set, candidate output, and derived bound before replacing
/// this gate.
///
/// # Errors
///
/// Always returns [`ContractError::CapacityAssetValidation`] naming the exact
/// later checkpoint. C1 is a pure authority-neutral contract boundary and
/// cannot satisfy this product-selection gate.
pub fn require_store_owned_capacity_allocation_construction() -> Result<()> {
    let manifest = verified_capacity_extension_manifest()?;
    let blocked = manifest
        .qualification_gaps
        .iter()
        .filter(|gap| gap.status == "blocked")
        .map(|gap| gap.gate.as_str())
        .collect::<Vec<_>>();
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(capacity_asset_error(
            "nq.custody_capacity_allocation.v1",
            &format!(
                "product allocation selection blocked by gate(s): {}",
                blocked.join(", ")
            ),
        ))
    }
}

/// Parses and verifies the additive native-correspondence schema manifest.
///
/// # Errors
///
/// Refuses source-record substitution, unknown/missing/duplicate assets,
/// malformed digests, or changed nonclaim boundaries.
pub fn verified_native_correspondence_manifest() -> Result<ContractExtensionManifest> {
    let manifest: ContractExtensionManifest =
        serde_json::from_slice(NATIVE_CORRESPONDENCE_MANIFEST_BYTES)?;
    if manifest.schema != "nq.host_role_contract_extension_package.v1"
        || manifest.extension_identity != NATIVE_CORRESPONDENCE_EXTENSION_IDENTITY
        || manifest.source_record.repository != "skunkworks"
        || manifest.source_record.path
            != "audits/nq-host-role-runtime-seam-v1/records/native-profile-clock-correspondence-design.md"
        || manifest.source_record.sha256.as_str() != NATIVE_CORRESPONDENCE_SOURCE_SHA256
        || manifest.digest_basis != "sha256 of exact embedded schema bytes"
    {
        return Err(ContractError::AssetManifestSubstitution);
    }

    let expected = expected_native_correspondence_assets();
    let mut seen = BTreeSet::new();
    for asset in &manifest.assets {
        if !seen.insert(asset.schema.as_str()) {
            return Err(ContractError::DuplicateSchemaAsset(asset.schema.clone()));
        }
        let expected_digest = expected
            .get(asset.schema.as_str())
            .ok_or_else(|| ContractError::UnknownSchemaAsset(asset.schema.clone()))?;
        if &asset.sha256 != expected_digest {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.schema.clone(),
            ));
        }
        let expected_path = format!("schemas/{}.schema.json", asset.schema);
        if asset.source_path != expected_path {
            return Err(ContractError::SchemaAssetPathMismatch(asset.schema.clone()));
        }
        let embedded = embedded_schema_bytes(&asset.schema)
            .ok_or_else(|| ContractError::MissingSchemaAsset(asset.schema.clone()))?;
        if sha256_bytes(embedded) != asset.sha256 {
            return Err(ContractError::SchemaAssetDigestMismatch(
                asset.schema.clone(),
            ));
        }
    }
    if seen.len() != expected.len()
        || RuntimeSchema::ALL
            .into_iter()
            .filter(|schema| schema.is_native_correspondence())
            .any(|schema| !seen.contains(schema.as_str()))
        || manifest.nonclaims
            != [
                "correspondence carriers do not equate production and native identities",
                "clock qualification establishes no finite UTC accuracy or cross-host coherence",
                "deadline evaluation grants no invocation, reliance, authorization, or action",
                "schema validation is not live-engine correspondence",
            ]
    {
        return Err(ContractError::AssetManifestSubstitution);
    }
    Ok(manifest)
}

/// Verifies and returns the implementation-era corrected fixture.
///
/// This fixture is derived from the 3A decision specimen but is not claimed to
/// be byte-identical to it. Its correction record preserves that distinction.
///
/// # Errors
///
/// Refuses digest, identity, source, or correction-record substitution.
pub fn verified_corrected_specimen() -> Result<&'static [u8]> {
    if sha256_bytes(CORRECTED_SPECIMEN_BYTES).as_str() != CORRECTED_SPECIMEN_SHA256 {
        return Err(ContractError::AssetManifestSubstitution);
    }
    let value: serde_json::Value = serde_json::from_slice(CORRECTED_SPECIMEN_BYTES)?;
    if value["derivative_identity"] != CORRECTED_SPECIMEN_IDENTITY
        || value["normative_source_commit"] != CONTRACT_SOURCE_COMMIT
        || value["correction_record"]["normative_effect"]
            != "none; ratified contract law is unchanged"
        || value["correction_record"]["source_specimen_status"]
            != "3A source specimen defect remains preserved in immutable history"
    {
        return Err(ContractError::AssetManifestSubstitution);
    }
    Ok(CORRECTED_SPECIMEN_BYTES)
}

pub(crate) fn embedded_capacity_static_asset(identity: &str) -> Option<&'static [u8]> {
    match identity {
        "nq.custody_carrier_map.v1" => Some(CUSTODY_CARRIER_MAP_BYTES),
        "nq.v3_projection_capsule_bound_manifest.v1" => {
            Some(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_BYTES)
        }
        "nq.v3_projection_capsule_bound_manifest.v2" => {
            Some(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES)
        }
        "nq.v3_projection_capsule_bound_qualification.v1" => {
            Some(V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES)
        }
        _ => None,
    }
}

fn verify_capacity_static_asset(identity: &str, bytes: &[u8]) -> Result<()> {
    let expected = expected_capacity_static_assets()
        .remove(identity)
        .ok_or_else(|| ContractError::UnknownSchemaAsset(identity.to_owned()))?;
    if expected.0 != identity || sha256_bytes(bytes) != expected.2 {
        return Err(ContractError::SchemaAssetDigestMismatch(
            identity.to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One exact immutable carrier map is audited as a closed unit.
fn validate_custody_carrier_map(value: &serde_json::Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| ContractError::CapacityAssetValidation {
            asset: "nq.custody_carrier_map.v1".to_owned(),
            detail: "asset is not an object".to_owned(),
        })?;
    let expected_components = [
        "request_and_decision_bytes",
        "raw_evidence_bytes",
        "normalized_bytes",
        "projected_bytes",
        "diagnostic_artifact_bytes",
        "dependency_closure_bytes",
        "commit_checkpoint_overhead_bytes",
        "mandatory_delivery_ledger_bytes",
    ];
    let actual_components = object["semantic_components"]
        .as_array()
        .ok_or_else(|| capacity_asset_error("nq.custody_carrier_map.v1", "components absent"))?
        .iter()
        .map(|value| value.as_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| capacity_asset_error("nq.custody_carrier_map.v1", "component not string"))?;
    if actual_components != expected_components {
        return Err(capacity_asset_error(
            "nq.custody_carrier_map.v1",
            "semantic component inventory differs",
        ));
    }

    let expected_mappings = [
        (
            "request_and_decision_bytes",
            "canonical_record_extent",
            "exact_bounded_request_decision_records_plus_format_fit_m",
        ),
        (
            "raw_evidence_bytes",
            "arena_raw_section",
            "typed_acquisition_carrier_plus_framing_fit_r",
        ),
        (
            "normalized_bytes",
            "arena_final_closure",
            "capsule_manifest_accounts_field_and_v_covers_it",
        ),
        (
            "projected_bytes",
            "arena_final_closure",
            "capsule_manifest_accounts_field_and_v_covers_it",
        ),
        (
            "diagnostic_artifact_bytes",
            "arena_final_closure",
            "closed_terminal_artifact_branch_fits_v",
        ),
        (
            "dependency_closure_bytes",
            "arena_dependency_section",
            "authenticated_dependency_closure_fits_d",
        ),
        (
            "commit_checkpoint_overhead_bytes",
            "canonical_record_extent",
            "capacity_reservation_launch_checkpoint_projection_records_fit_m",
        ),
        (
            "mandatory_delivery_ledger_bytes",
            "delivery_ledger_extent",
            "policy_maximal_delivery_chain_plus_framing_fits_l",
        ),
    ];
    let actual_mappings = object["component_mappings"]
        .as_array()
        .ok_or_else(|| capacity_asset_error("nq.custody_carrier_map.v1", "mappings absent"))?;
    if actual_mappings.len() != expected_mappings.len()
        || actual_mappings
            .iter()
            .zip(expected_mappings)
            .any(|(actual, expected)| {
                actual["semantic_component"].as_str() != Some(expected.0)
                    || actual["primary_carrier"].as_str() != Some(expected.1)
                    || actual["constraint"].as_str() != Some(expected.2)
            })
    {
        return Err(capacity_asset_error(
            "nq.custody_carrier_map.v1",
            "component mapping differs",
        ));
    }
    let equations = &object["equations"];
    let expected_equations = [
        ("semantic_sum", "S=sum_checked(eight_semantic_components)"),
        (
            "reservation_exactness",
            "total_required_bytes=S;reserved_bytes=S",
        ),
        ("arena_layout", "F=arena_layout_v1(D,R,V,P,A)"),
        (
            "append_extent_layout",
            "extent_length=align_up_checked(3*A+payload_bound,A)",
        ),
        ("retained_charge", "T=F+M+L"),
        (
            "store_usage",
            "U=B+G+sum(retained_or_charged_T)+missing_committed_bytes",
        ),
        ("post_allocation_usage", "post=U+candidate_T"),
        (
            "single_execution_limit",
            "max(S,V)<=maximum_single_execution_closure_bytes",
        ),
        ("delivery_not_required", "s_delivery=0;L=0;queue_slots=0"),
    ];
    if expected_equations
        .into_iter()
        .any(|(field, expected)| equations[field].as_str() != Some(expected))
        || object["alignment_bytes"].as_u64() != Some(4_096)
        || object["schema"].as_str() != Some("nq.custody_carrier_map.v1")
        || object["rule_identity"].as_str() != Some("nq.custody_carrier_map.v1")
        || object["rule_version"].as_str() != Some("1")
        || object["canonicalization_identity"].as_str() != Some("rfc8785-jcs-sha256-v1")
        || object["nonclaims"]
            != serde_json::json!([
                "the carrier map performs no filesystem allocation",
                "semantic adequacy does not establish physical carrier allocation",
                "unused capacity in one carrier cannot be borrowed by another",
                "the carrier map grants no invocation, reliance, authorization, or action",
                "exact source or asset digest correspondence does not establish deployed build or live execution correspondence"
            ])
    {
        return Err(capacity_asset_error(
            "nq.custody_carrier_map.v1",
            "fixed rule or nonclaim differs",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One exact candidate census is audited as a closed unit.
fn validate_v3_projection_capsule_bound_manifest(value: &serde_json::Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "asset is not an object",
        )
    })?;
    if object["schema"].as_str() != Some("nq.v3_projection_capsule_bound_manifest.v1")
        || object["manifest_identity"].as_str()
            != Some("nq.v3_projection_capsule_bound_manifest.v1")
        || object["manifest_version"].as_str() != Some("1")
        || object["capsule_schema"].as_str() != Some("nq.governed_projection_capsule.v1")
        || object["capsule_implementation_source_path"].as_str()
            != Some("crates/nq-store/src/governed_projection_capsule.rs")
        || object["capsule_implementation_source_sha256"].as_str()
            != Some("sha256:033b57efb16437a2379307dba0ea495810891bbaeb378462f9b8cf054b5011d3")
        || object["generic_field_count"].as_u64() != Some(16)
        || object["generic_pointer_family_count"].as_u64() != Some(17)
        || object["capsule_field_count"].as_u64() != Some(151)
        || object["scalar_maxima"]["positive_publication_sequence"].as_u64()
            != Some(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1)
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "fixed identity or count differs",
        ));
    }
    let sources = object["bounded_json_sources"].as_array().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "descriptor source inventory absent",
        )
    })?;
    let expected_sources = [
        "provider_intake_context",
        "provider_intake_interpretation",
        "provider_intake_native_outcome",
        "run_execution_identity",
        "run_resource_outcome",
        "refusal_detail",
        "coverage_detail",
        "observation_subject",
        "observation_payload",
        "report_error_detail",
        "canonical_report",
        "validated_report",
        "next_checkpoint",
        "status_detail",
        "runtime_record_canonical_bytes",
    ];
    if sources.len() != expected_sources.len()
        || sources.iter().zip(expected_sources).any(|(source, key)| {
            source["descriptor_key"].as_str() != Some(key)
                || source["descriptor_pointer"].as_str() != Some("")
                || !source["source_record_schema"].is_null()
                || source["required_descriptor_type_identity"].as_str()
                    != Some("nq.protocol.BoundedJsonDescriptor.v1")
        })
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "descriptor type or source inventory differs",
        ));
    }
    let expected_generic = [
        (
            "/collection/intake/context",
            "bounded_canonical_json",
            "provider_intake_context",
        ),
        (
            "/collection/intake/interpretation",
            "bounded_canonical_json",
            "provider_intake_interpretation",
        ),
        (
            "/collection/intake/native_outcome",
            "bounded_canonical_json",
            "provider_intake_native_outcome",
        ),
        (
            "/collection/run/execution_identity",
            "bounded_canonical_json",
            "run_execution_identity",
        ),
        (
            "/collection/run/resource_outcome",
            "bounded_canonical_json",
            "run_resource_outcome",
        ),
        (
            "/collection/submission/disposition/refusal/detail",
            "bounded_canonical_json",
            "refusal_detail",
        ),
        (
            "/collection/submission/disposition/report/coverage/*/detail",
            "bounded_canonical_json",
            "coverage_detail",
        ),
        (
            "/collection/submission/disposition/report/observations/*/coverage/*/detail",
            "bounded_canonical_json",
            "coverage_detail",
        ),
        (
            "/collection/submission/disposition/report/observations/*/subject",
            "bounded_canonical_json",
            "observation_subject",
        ),
        (
            "/collection/submission/disposition/report/observations/*/payload",
            "bounded_canonical_json",
            "observation_payload",
        ),
        (
            "/collection/submission/disposition/report/errors/*/detail",
            "bounded_canonical_json",
            "report_error_detail",
        ),
        (
            "/collection/submission/disposition/report/canonical_report",
            "bounded_canonical_json",
            "canonical_report",
        ),
        (
            "/collection/submission/disposition/report/validated_report",
            "bounded_canonical_json",
            "validated_report",
        ),
        (
            "/collection/submission/disposition/report/next_checkpoint",
            "bounded_canonical_json",
            "next_checkpoint",
        ),
        ("/status/detail", "bounded_canonical_json", "status_detail"),
        (
            "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody",
            "exact_pre_effect_bytes",
            "authenticated_runtime_dependency_custody",
        ),
        (
            "/diagnostic/local_origin/execution_binding/runtime_records/records/*/canonical_bytes",
            "bounded_canonical_json",
            "runtime_record_canonical_bytes",
        ),
    ];
    let generic = object["generic_pointer_bounds"].as_array().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "generic pointer inventory absent",
        )
    })?;
    let actual_generic = generic
        .iter()
        .filter_map(|row| {
            Some((
                row["pointer_family"].as_str()?,
                row["classification"].as_str()?,
                row["bound_source"].as_str()?,
            ))
        })
        .collect::<BTreeSet<_>>();
    let expected_generic = expected_generic.into_iter().collect::<BTreeSet<_>>();
    let inventory = object["capsule_field_inventory"]
        .as_array()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_manifest.v1",
                "exhaustive field inventory absent",
            )
        })?;
    let allowed_classifications = [
        "fixed_literal",
        "exact_pre_effect_bytes",
        "scalar_maximum",
        "option_or_enum",
        "bounded_collection",
        "bounded_canonical_json",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let inventory_rows = inventory
        .iter()
        .filter_map(|row| {
            Some((
                row["pointer_family"].as_str()?,
                row["classification"].as_str()?,
                row["bound_source"].as_str()?,
            ))
        })
        .collect::<BTreeSet<_>>();
    let descriptor_governed_open_semantics = object["descriptor_governed_open_semantics"]
        .as_array()
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_manifest.v1",
                "descriptor-governed open-semantic inventory absent",
            )
        })?;
    let semantic_outcome_variants =
        object["semantic_outcome_variants"]
            .as_array()
            .ok_or_else(|| {
                capacity_asset_error(
                    "nq.v3_projection_capsule_bound_manifest.v1",
                    "closed semantic-family inventory absent",
                )
            })?;
    let semantic_exclusions = object["semantic_exclusions"].as_array().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "semantic exclusion inventory absent",
        )
    })?;
    let exact_semantic_sections = [
        (
            semantic_outcome_variants,
            50,
            "sha256:4a6b0bdb1699539ac8ea3e279d346325eb9b254f22e709f0c911320c72c5c2e2",
        ),
        (
            semantic_exclusions,
            9,
            "sha256:f5b6a11cbf97fed9ce256faa50b1247b940ac3dc200bb7e475e847d67b3ea943",
        ),
        (
            descriptor_governed_open_semantics,
            276,
            "sha256:b520701a84bdd66a791b072604454bb572467d33da1ab6fef5dfe6feb2896feb",
        ),
    ];
    for (rows, expected_len, expected_digest) in exact_semantic_sections {
        if rows.len() != expected_len
            || sha256_bytes(&canonical_json_bytes(rows)?).as_str() != expected_digest
        {
            return Err(capacity_asset_error(
                "nq.v3_projection_capsule_bound_manifest.v1",
                "exact semantic census or closed vocabulary differs",
            ));
        }
    }
    let expected_semantic_source_closure = [
        (
            "crates/nq-core/src/engine.rs",
            "sha256:3cd147fd850fc21916f40622025fca96f492c45333f72d51ba3cf9a7c3cc467b",
        ),
        (
            "crates/nq-core/src/governed_custody_projection.rs",
            "sha256:57f29f1b56b315f36b4a14b987e6955139e95c8386adf353323662bc5593dcab",
        ),
        (
            "crates/nq-core/src/governed_execution_binding.rs",
            "sha256:4abbe4f6adb1a55173a204073bdcddbad34b3cf97dc03b155c031f16d33fe68c",
        ),
        (
            "crates/nq-core/src/identity.rs",
            "sha256:9d0aa94cd53a0e17d7ce3908d7c0f1234dc44a9fcb3782c7097452ce822c16ca",
        ),
        (
            "crates/nq-core/src/provider_intake.rs",
            "sha256:9e70cb179351714ac24675965662447aa2824999b41a51c72aa3666ffce93f86",
        ),
        (
            "crates/nq-core/src/runner.rs",
            "sha256:6846b67e1223481053e462b5da3d773257d9131442c9aaf6cf62925423c3b74a",
        ),
        (
            "crates/nq-core/src/runtime.rs",
            "sha256:d07b2cec9b468f925089302f034c3063b32e000674d90c07b6973e698570137b",
        ),
        (
            "crates/nq-helper-sandbox/src/lib.rs",
            "sha256:39cc09d634c566b8ee46c0095dd379836fdd2584c9aabd3e43a2d674d550904a",
        ),
        (
            "crates/nq-host-role-contract/src/identity.rs",
            "sha256:c3ecda9e5fa3bd6b0f0fdb0f089e3d0c6bfbea92fb24f403feab16003e788ac1",
        ),
        (
            "crates/nq-host-role-contract/src/record.rs",
            "sha256:476373e7ff3742917c5e418b23c38521e0f422254d06d8278c6ad4b034bda972",
        ),
        (
            "crates/nq-profiles/src/descriptor.rs",
            "sha256:278cdace530b2ce56d8c76fcb79add75086732b4fd7e5fc39a24aa119a0ec9e2",
        ),
        (
            "crates/nq-profiles/src/validation.rs",
            "sha256:8a47889d515e9bff09e8c9514e87711d9923827ce0aedfbebcd0368416b19417",
        ),
        (
            "crates/nq-protocol/src/ids.rs",
            "sha256:7b26bff64bcc5375a73c9c40c3713b8f4bfb9a9c28c43ed18a103c42c5258dd8",
        ),
        (
            "crates/nq-protocol/src/model.rs",
            "sha256:441ac0ec37d51440686b665d77d83ced0c9c59ee757f29e9da4ce34b8ab0eaf8",
        ),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let semantic_source_closure = semantic_outcome_variants
        .iter()
        .chain(semantic_exclusions)
        .chain(descriptor_governed_open_semantics)
        .filter_map(|row| Some((row["source_path"].as_str()?, row["source_sha256"].as_str()?)))
        .collect::<BTreeSet<_>>();
    if semantic_source_closure != expected_semantic_source_closure {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "semantic source closure differs",
        ));
    }
    let descriptor_keys = expected_sources.into_iter().collect::<BTreeSet<_>>();
    let allowed_open_semantic_reasons = [
        "application- or profile-controlled JSON vocabulary is bounded structurally and bytewise by the exact pre-effect descriptor; that bound does not establish semantic validity, continuity, standing, or authorization, and the vocabulary is not a closed NQ semantic family",
        "production identity, topology, or runtime token is bounded structurally and bytewise by the exact pre-effect descriptor; that bound does not establish semantic validity, continuity, standing, or authorization, and the token is not a closed NQ semantic family",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let open_semantic_rows = descriptor_governed_open_semantics
        .iter()
        .filter_map(|row| {
            Some((
                row["descriptor_key"].as_str()?,
                row["source_identity"].as_str()?,
                row["source_path"].as_str()?,
                row["source_sha256"].as_str()?,
                row["json_pointer"].as_str()?,
                row["reason"].as_str()?,
            ))
        })
        .collect::<BTreeSet<_>>();
    if object["physical_branches"]
        .as_array()
        .is_none_or(|branches| branches.len() != 3)
        || generic.len() != 17
        || actual_generic != expected_generic
        || inventory.len() != 151
        || inventory_rows.len() != inventory.len()
        || !expected_generic.is_subset(&inventory_rows)
        || inventory_rows
            .iter()
            .any(|(pointer, classification, source)| {
                pointer.is_empty()
                    || !pointer.starts_with('/')
                    || source.is_empty()
                    || !allowed_classifications.contains(classification)
            })
        || semantic_outcome_variants.is_empty()
        || semantic_exclusions.is_empty()
        || descriptor_governed_open_semantics.is_empty()
        || open_semantic_rows.len() != descriptor_governed_open_semantics.len()
        || open_semantic_rows.iter().any(
            |(descriptor_key, source_identity, source_path, source_sha256, pointer, reason)| {
                !descriptor_keys.contains(descriptor_key)
                    || source_identity.is_empty()
                    || source_path.is_empty()
                    || !source_sha256.starts_with("sha256:")
                    || (!pointer.is_empty() && !pointer.starts_with('/'))
                    || !allowed_open_semantic_reasons.contains(reason)
            },
        )
        || object["symbolic_shape_derivations"]
            != serde_json::json!([
                {
                    "branch": "admitted",
                    "shape_evaluator_identity":
                        "nq.v3_projection_capsule_symbolic_shape_admitted.v1"
                },
                {
                    "branch": "non_success_no_submission",
                    "shape_evaluator_identity":
                        "nq.v3_projection_capsule_symbolic_shape_no_submission.v1"
                },
                {
                    "branch": "non_success_rejected_submission",
                    "shape_evaluator_identity":
                        "nq.v3_projection_capsule_symbolic_shape_rejected_submission.v1"
                }
            ])
        || object["symbolic_shape_method"]
            != serde_json::json!({
                "carrier_shape_source": "production typed branch serializer shapes",
                "substitution": "exact symbolic substitution of committed maxima",
                "cross_check": "independent hand-derived JCS object and array arithmetic",
                "materialization_claim": "none"
            })
        || object["qualification_gaps"]
            != serde_json::json!([
                {
                    "gate": "CAP-H14",
                    "status": "blocked",
                    "required_evidence": "maximal exact production values for every closed branch serialized by the production canonical serializer",
                    "current_evidence": "symbolic production-shape substitution cross-checked by independent JCS arithmetic",
                    "consequence": "this candidate manifest does not qualify the V3 capsule bound or satisfy the Campaign 3B stopping rule"
                }
            ])
        || object["bound_evaluator_identity"].as_str()
            != Some("nq.v3_projection_capsule_bound_evaluator.v1")
        || object["nonclaims"]
            != serde_json::json!([
                "observed capsule length cannot select or enlarge a pre-effect bound",
                "the authenticated dependency closure remains exact pre-effect input rather than generic JSON",
                "symbolic shape derivation does not claim infeasibly maximal typed values were materialized or serialized",
                "the bound manifest performs no provider effect or filesystem allocation",
                "the bound manifest grants no invocation, diagnostic result, reliance, authorization, or action"
            ])
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v1",
            "physical, field, or semantic inventory is incomplete",
        ));
    }
    Ok(())
}

fn v2_qualification_basis_digest(value: &serde_json::Value) -> Result<Sha256Digest> {
    let mut projection = value.clone();
    let object = projection.as_object_mut().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v2",
            "qualification-basis source is not an object",
        )
    })?;
    for excluded in [
        "qualification_basis",
        "cap_h14_qualification",
        "qualification_gaps",
    ] {
        if object.remove(excluded).is_none() {
            return Err(capacity_asset_error(
                "nq.v3_projection_capsule_bound_manifest.v2",
                "qualification-basis excluded field is absent",
            ));
        }
    }
    Ok(sha256_bytes(&canonical_json_bytes(&projection)?))
}

fn qualification_semantic_identity(value: &serde_json::Value) -> Result<Sha256Digest> {
    let mut projection = value.clone();
    let object = projection.as_object_mut().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "qualification identity source is not an object",
        )
    })?;
    if object.remove("qualification_id").is_none() {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "qualification identity field is absent",
        ));
    }
    Ok(sha256_bytes(&canonical_json_bytes(&projection)?))
}

fn pre_review_qualification_projection_digest(value: &serde_json::Value) -> Result<Sha256Digest> {
    let mut projection = value.clone();
    let object = projection.as_object_mut().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "pre-review projection source is not an object",
        )
    })?;
    if object.remove("qualification_id").is_none() {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "pre-review projection qualification identity is absent",
        ));
    }
    let implementation_bindings = object
        .get_mut("implementation_bindings")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "pre-review implementation bindings are absent",
            )
        })?;
    if implementation_bindings
        .remove("post_acceptance_review")
        .is_none()
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "pre-review review binding is absent",
        ));
    }
    Ok(sha256_bytes(&canonical_json_bytes(&projection)?))
}

fn validate_v3_projection_capsule_bound_manifest_v2(value: &serde_json::Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v2",
            "asset is not an object",
        )
    })?;
    if object["schema"].as_str() != Some("nq.v3_projection_capsule_bound_manifest.v2")
        || object["manifest_identity"].as_str()
            != Some("nq.v3_projection_capsule_bound_manifest.v2")
        || object["manifest_version"].as_str() != Some("2")
        || object["qualification_basis"]["projection_identity"].as_str()
            != Some("nq.v3_projection_capsule_bound_qualification_basis.v1")
        || object["cap_h14_qualification"]["schema"].as_str()
            != Some("nq.v3_projection_capsule_bound_qualification.v1")
        || object["qualification_gaps"]
            .as_array()
            .is_none_or(|gaps| !gaps.is_empty())
        || object["symbolic_shape_method"]["materialization_claim"].as_str()
            != Some(
                "typed per-evidence disposition in nq.v3_projection_capsule_bound_qualification.v1",
            )
        || object["nonclaims"]
            != serde_json::json!([
                "observed capsule length cannot select or enlarge a pre-effect bound",
                "the authenticated dependency closure remains exact pre-effect input rather than generic JSON",
                "typed qualification evidence does not authorize physical allocation or Store mutation",
                "the qualified bound manifest does not establish Store-owned source/evaluator correspondence or satisfy C3-STORE-OWNED-CAPACITY-ALLOCATION-CONSTRUCTION",
                "the bound manifest grants no invocation, diagnostic result, reliance, authorization, or action"
            ])
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v2",
            "fixed qualification identity, gap state, or nonclaim differs",
        ));
    }
    let basis = v2_qualification_basis_digest(value)?;
    if object["qualification_basis"]["digest"].as_str() != Some(basis.as_str()) {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_manifest.v2",
            "qualification-basis digest differs",
        ));
    }

    // Reuse the historical v1 census validator after an explicit,
    // semantics-preserving projection back to the frozen candidate surface.
    // This cannot qualify v1: the projected blocked gap exists only in the
    // temporary validation value.
    let mut historical = value.clone();
    let historical_object = historical.as_object_mut().expect("checked object");
    historical_object.remove("qualification_basis");
    historical_object.remove("cap_h14_qualification");
    historical_object["schema"] =
        serde_json::Value::String("nq.v3_projection_capsule_bound_manifest.v1".into());
    historical_object["manifest_identity"] =
        serde_json::Value::String("nq.v3_projection_capsule_bound_manifest.v1".into());
    historical_object["manifest_version"] = serde_json::Value::String("1".into());
    historical_object["symbolic_shape_method"]["materialization_claim"] =
        serde_json::Value::String("none".into());
    historical_object["qualification_gaps"] = serde_json::json!([
        {
            "gate": "CAP-H14",
            "status": "blocked",
            "required_evidence": "maximal exact production values for every closed branch serialized by the production canonical serializer",
            "current_evidence": "symbolic production-shape substitution cross-checked by independent JCS arithmetic",
            "consequence": "this candidate manifest does not qualify the V3 capsule bound or satisfy the Campaign 3B stopping rule"
        }
    ]);
    historical_object["nonclaims"] = serde_json::json!([
        "observed capsule length cannot select or enlarge a pre-effect bound",
        "the authenticated dependency closure remains exact pre-effect input rather than generic JSON",
        "symbolic shape derivation does not claim infeasibly maximal typed values were materialized or serialized",
        "the bound manifest performs no provider effect or filesystem allocation",
        "the bound manifest grants no invocation, diagnostic result, reliance, authorization, or action"
    ]);
    validate_v3_projection_capsule_bound_manifest(&historical)
}

#[allow(clippy::too_many_lines)] // One exact immutable eight-disposition carrier is audited closed.
fn validate_v3_projection_capsule_bound_qualification_v1(value: &serde_json::Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "asset is not an object",
        )
    })?;
    if object["schema"].as_str() != Some("nq.v3_projection_capsule_bound_qualification.v1")
        || object["gate"].as_str() != Some("CAP-H14")
        || object["status"].as_str() != Some("qualified")
        || object["qualification_basis"]["projection_identity"].as_str()
            != Some("nq.v3_projection_capsule_bound_qualification_basis.v1")
        || object["qualification_budget"]["schema"].as_str()
            != Some("nq.v3_projection_capsule_materialization_budget.v1")
        || object["qualification_budget"]["identity"].as_str()
            != Some("nq.host-role-runtime-seam.cap-h14-materialization-budget.v1")
        || object["qualification_budget"]["maximum_single_canonical_witness_bytes"].as_u64()
            != Some(16_777_216)
        || object["qualification_budget"]["closed_shape_count"].as_u64() != Some(4)
        || object["qualification_budget"]["maximum_total_preallocated_witness_bytes"].as_u64()
            != Some(67_108_864)
        || object["qualification_budget"]["maximum_parallel_witnesses"].as_u64() != Some(1)
        || object["qualification_budget"]["enforcement_identity"].as_str()
            != Some("nq.v3_projection_capsule_materialization_preallocation.v1")
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "fixed qualification identity or accepted budget differs",
        ));
    }
    validate_v3_projection_capsule_qualification_bindings(object)?;
    validate_v3_projection_capsule_materialization_attempts(object)?;

    let manifest: serde_json::Value =
        serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES)?;
    validate_v3_projection_capsule_qualification_census(object, &manifest)?;

    let dispositions = object["evidence_dispositions"].as_array().ok_or_else(|| {
        capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "typed evidence disposition inventory absent",
        )
    })?;
    let expected_dispositions = serde_json::json!([
        {
            "evidence_id": "nq.cap-h14.tractable-descriptor-component.v1",
            "scope": "descriptor_component",
            "subject_identity": "nq.bounded-json-descriptor.2-4-3-2-2-3.v1",
            "disposition": "ATTAINABLE-MATERIALIZED",
            "symbolic_ceiling_bytes": 121,
            "actual_canonical_bytes": 121,
            "production_witness_sha256":
                "sha256:d03d6778f9ae980e590eea7283bc96a135aa34cb254f876a176fe2c56f4a49de",
            "unattainability_proof_identity": null,
            "budget_identity": null,
            "source_constraints_identity": "nq.protocol.BoundedJsonDescriptor.v1",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        },
        {
            "evidence_id": "nq.cap-h14.zero-key-two-member-descriptor.v1",
            "scope": "descriptor_component",
            "subject_identity": "nq.bounded-json-descriptor.2-2-0-0-0-1.v1",
            "disposition": "UNATTAINABLE-PROVED",
            "symbolic_ceiling_bytes": 19,
            "actual_canonical_bytes": 10,
            "production_witness_sha256":
                "sha256:54755e5a76e179ba48aa9c21a030a938f63fcc7d7b7bd964754f2cb1795e8e1a",
            "unattainability_proof_identity":
                "nq.bounded-json-descriptor.unique-object-key-unattainability.v1",
            "budget_identity": null,
            "source_constraints_identity": "nq.protocol.BoundedJsonDescriptor.v1",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": 901,
            "unattainability_proof_sha256":
                "sha256:b404ec65da8bffd5b053416a388eceb012725f3fa1cdb3030330bb2aef495858"
        },
        {
            "evidence_id": "nq.cap-h14.shape.admitted-all-report-level.v1",
            "scope": "closed_shape",
            "subject_identity": "nq.v3_projection_capsule.shape.admitted.all-report-level.v1",
            "disposition": "INFEASIBLE-UNDER-IDENTIFIED-BUDGET",
            "symbolic_ceiling_bytes": 133_038_721,
            "actual_canonical_bytes": null,
            "production_witness_sha256": null,
            "unattainability_proof_identity": null,
            "budget_identity":
                "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
            "source_constraints_identity": "nq.v3_projection_capsule_bound_manifest.v2",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        },
        {
            "evidence_id":
                "nq.cap-h14.shape.admitted-one-per-observation-then-nested.v1",
            "scope": "closed_shape",
            "subject_identity":
                "nq.v3_projection_capsule.shape.admitted.one-per-observation-then-nested.v1",
            "disposition": "INFEASIBLE-UNDER-IDENTIFIED-BUDGET",
            "symbolic_ceiling_bytes": 133_034_626,
            "actual_canonical_bytes": null,
            "production_witness_sha256": null,
            "unattainability_proof_identity": null,
            "budget_identity":
                "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
            "source_constraints_identity": "nq.v3_projection_capsule_bound_manifest.v2",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        },
        {
            "evidence_id": "nq.cap-h14.shape.non-success-no-submission.v1",
            "scope": "closed_shape",
            "subject_identity":
                "nq.v3_projection_capsule.shape.non-success-no-submission.v1",
            "disposition": "ATTAINABLE-MATERIALIZED",
            "symbolic_ceiling_bytes": 68_127,
            "actual_canonical_bytes": 68_127,
            "production_witness_sha256":
                "sha256:b8b5c2a6af80d544c1977fec8521bfbadd80c728e0af4c7f17f4cb87dd8492ca",
            "unattainability_proof_identity": null,
            "budget_identity": null,
            "source_constraints_identity": "nq.v3_projection_capsule_bound_manifest.v2",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        },
        {
            "evidence_id":
                "nq.cap-h14.shape.non-success-rejected-submission.v1",
            "scope": "closed_shape",
            "subject_identity":
                "nq.v3_projection_capsule.shape.non-success-rejected-submission.v1",
            "disposition": "ATTAINABLE-MATERIALIZED",
            "symbolic_ceiling_bytes": 74_768,
            "actual_canonical_bytes": 74_768,
            "production_witness_sha256":
                "sha256:4c13e0ee18899a1d5490b0ad1752612009ab9cfcfc45a93b10e7b9adfca6f99a",
            "unattainability_proof_identity": null,
            "budget_identity": null,
            "source_constraints_identity": "nq.v3_projection_capsule_bound_manifest.v2",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        },
        {
            "evidence_id": "nq.cap-h14.large-generic-descriptor-component.v1",
            "scope": "generic_domain",
            "subject_identity": "nq.bounded-json-descriptor.2-0-u32-max-0-0-1.v1",
            "disposition": "INFEASIBLE-UNDER-IDENTIFIED-BUDGET",
            "symbolic_ceiling_bytes": 25_769_803_771_u64,
            "actual_canonical_bytes": null,
            "production_witness_sha256": null,
            "unattainability_proof_identity": null,
            "budget_identity":
                "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
            "source_constraints_identity": "nq.protocol.BoundedJsonDescriptor.v1",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        },
        {
            "evidence_id": "nq.cap-h14.large-generic-full-capsule.v1",
            "scope": "generic_domain",
            "subject_identity":
                "nq.v3_projection_capsule.large-generic-descriptor-full-capsule.v1",
            "disposition": "INFEASIBLE-UNDER-IDENTIFIED-BUDGET",
            "symbolic_ceiling_bytes": 3_509_873_159_972_371_u64,
            "actual_canonical_bytes": null,
            "production_witness_sha256": null,
            "unattainability_proof_identity": null,
            "budget_identity":
                "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
            "source_constraints_identity": "nq.v3_projection_capsule_bound_manifest.v2",
            "arithmetic_identity":
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            "unattainability_proof_canonical_bytes": null,
            "unattainability_proof_sha256": null
        }
    ]);
    if object["evidence_dispositions"] != expected_dispositions {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "exact evidence identity, scope, subject, source, arithmetic, or witness differs",
        ));
    }
    let mut seen = BTreeSet::new();
    for evidence in dispositions {
        let evidence_id = evidence["evidence_id"].as_str().ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "evidence identity absent",
            )
        })?;
        if !seen.insert(evidence_id) {
            return Err(capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "duplicate evidence identity",
            ));
        }
        let symbolic = evidence["symbolic_ceiling_bytes"].as_u64().ok_or_else(|| {
            capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "symbolic ceiling absent",
            )
        })?;
        let actual = evidence["actual_canonical_bytes"].as_u64();
        let witness = evidence["production_witness_sha256"].as_str();
        let proof = evidence["unattainability_proof_identity"].as_str();
        let proof_bytes = evidence["unattainability_proof_canonical_bytes"].as_u64();
        let proof_sha256 = evidence["unattainability_proof_sha256"].as_str();
        let budget = evidence["budget_identity"].as_str();
        let conditional_holds = match evidence["disposition"].as_str() {
            Some("ATTAINABLE-MATERIALIZED") => {
                actual == Some(symbolic)
                    && witness.is_some()
                    && proof.is_none()
                    && proof_bytes.is_none()
                    && proof_sha256.is_none()
                    && budget.is_none()
            }
            Some("UNATTAINABLE-PROVED") => {
                actual.is_some_and(|bytes| bytes < symbolic)
                    && witness.is_some()
                    && proof.is_some()
                    && proof_bytes.is_some()
                    && proof_sha256.is_some()
                    && budget.is_none()
            }
            Some("INFEASIBLE-UNDER-IDENTIFIED-BUDGET") => {
                symbolic
                    > object["qualification_budget"]["maximum_single_canonical_witness_bytes"]
                        .as_u64()
                        .unwrap_or(0)
                    && actual.is_none()
                    && witness.is_none()
                    && proof.is_none()
                    && proof_bytes.is_none()
                    && proof_sha256.is_none()
                    && budget == Some("nq.host-role-runtime-seam.cap-h14-materialization-budget.v1")
            }
            _ => false,
        };
        if !conditional_holds {
            return Err(capacity_asset_error(
                "nq.v3_projection_capsule_bound_qualification.v1",
                "typed evidence disposition conditional differs",
            ));
        }
    }
    if seen.len() != 8 {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "typed evidence disposition population differs",
        ));
    }

    let expected_nonclaims = serde_json::json!([
        "CAP-H14 qualification does not establish Store-owned source/evaluator correspondence or satisfy C3-STORE-OWNED-CAPACITY-ALLOCATION-CONSTRUCTION",
        "qualification-budget enforcement performs no runtime custody allocation or Store mutation",
        "qualification evidence grants no invocation, diagnostic result, reliance, authorization, or action",
        "a finite symbolic ceiling is not a claim that its global literal maximum is attainable",
        "materialization feasibility does not alter the symbolic ceiling or admit observed-length sizing",
        "qualification of the pure C1 bound does not authorize C2 physical carriers, filesystem effects, provider launch, or delivery"
    ]);
    if object["nonclaims"] != expected_nonclaims {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "qualification nonclaims differ",
        ));
    }
    let qualification_id = qualification_semantic_identity(value)?;
    if object["qualification_id"].as_str() != Some(qualification_id.as_str()) {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "qualification semantic identity differs",
        ));
    }
    let pre_review_digest = pre_review_qualification_projection_digest(value)?;
    let review = &object["implementation_bindings"]["post_acceptance_review"];
    if review["qualification_basis_sha256"].as_str()
        != object["qualification_basis"]["digest"].as_str()
        || review["pre_review_projection_sha256"].as_str() != Some(pre_review_digest.as_str())
    {
        return Err(capacity_asset_error(
            "nq.v3_projection_capsule_bound_qualification.v1",
            "post-acceptance review does not bind the exact acyclic review cut",
        ));
    }
    Ok(())
}

fn exact_source_binding(
    value: &serde_json::Value,
    identity: &str,
    path: &str,
    sha256: &str,
) -> bool {
    value
        == &serde_json::json!({
            "identity": identity,
            "path": path,
            "sha256": sha256
        })
}

#[allow(clippy::too_many_lines)] // Every verdict-affecting source cut is exact.
fn validate_v3_projection_capsule_qualification_bindings(
    qualification: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    const ASSET: &str = "nq.v3_projection_capsule_bound_qualification.v1";
    const STORE_CAPACITY_SOURCE_SHA256: &str =
        "sha256:fb197b52948521199336e07bbbc2e74e8d890f83cb702725a5be206f0f44e7db";
    let policy = &qualification["policy_bindings"];
    if !exact_source_binding(
        &policy["operator_decision"],
        "nq.host-role-runtime-seam.cap-h13-h14-clarification.2026-07-30",
        "audits/nq-host-role-runtime-seam-v1/records/cap-h13-h14-operator-decision.md",
        "sha256:d01ea3451d6e477adedcf090a8f147ceb8ba9c3927ee89b2cd6bd96212a1c6ed",
    ) || !exact_source_binding(
        &policy["materialization_budget_decision"],
        "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
        "audits/nq-host-role-runtime-seam-v1/records/cap-h14-materialization-budget-decision.md",
        "sha256:9a4adb9610cda4f32be23f5f31260d4e70e9792342cd84e29cc4617d84bc4728",
    ) || !exact_source_binding(
        &policy["controlling_supplement"],
        "nq.host-role-runtime-seam.physical-aggregate-custody-capacity-supplement.v1",
        "audits/nq-host-role-runtime-seam-v1/records/physical-aggregate-custody-capacity-supplement.md",
        "sha256:c455c06a36ec38b0ddb6c589c046890267fb5409b9a9a841ca4762786622c5ff",
    ) || !exact_source_binding(
        &policy["accepted_adjudication"],
        "nq.host-role-runtime-seam.cap-h14-symbolic-bound-adjudication.v1",
        "audits/nq-host-role-runtime-seam-v1/records/cap-h14-symbolic-bound-adjudication.md",
        "sha256:be1a42bdb3b92958c2fae506c56eed6dac1191d58ad7070aa8b4d37dfbad8c70",
    ) {
        return Err(capacity_asset_error(
            ASSET,
            "operator policy, budget, supplement, or adjudication binding differs",
        ));
    }

    let implementation = &qualification["implementation_bindings"];
    if !exact_source_binding(
        &implementation["evaluator"],
        "nq.v3_projection_capsule_bound_evaluator.v1",
        "crates/nq-store/src/governed_projection_capacity.rs",
        STORE_CAPACITY_SOURCE_SHA256,
    ) || !exact_source_binding(
        &implementation["canonical_serializer"],
        "nq.production-canonical-json.v1",
        "crates/nq-store/src/governed_projection_capsule.rs",
        "sha256:033b57efb16437a2379307dba0ea495810891bbaeb378462f9b8cf054b5011d3",
    ) || !exact_source_binding(
        &implementation["independent_arithmetic"],
        "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
        "crates/nq-store/src/governed_projection_capacity.rs",
        STORE_CAPACITY_SOURCE_SHA256,
    ) || !exact_source_binding(
        &implementation["test_source"],
        "nq.v3_projection_capsule_bound_qualification_tests.v1",
        "crates/nq-store/src/governed_projection_capacity.rs",
        STORE_CAPACITY_SOURCE_SHA256,
    ) || !exact_source_binding(
        &qualification["qualification_budget"]["enforcement_binding"],
        "nq.v3_projection_capsule_materialization_preallocation.v1",
        "crates/nq-store/src/governed_projection_capacity.rs",
        STORE_CAPACITY_SOURCE_SHA256,
    ) {
        return Err(capacity_asset_error(
            ASSET,
            "evaluator, serializer, independent arithmetic, test, or enforcement binding differs",
        ));
    }
    let review = &implementation["post_acceptance_review"];
    if review["identity"].as_str()
        != Some("nq.host-role-runtime-seam.cap-h14-gen4-post-acceptance-review.v3")
        || review["path"].as_str()
            != Some(
                "audits/nq-host-role-runtime-seam-v1/c1-gen4-r2-enrolled-activation-candidate-2/CAP-H14-GEN4-POST-ACCEPTANCE-REVIEW.v3.md",
            )
        || review["sha256"].as_str()
            != Some("sha256:9b380cc23bc2115ad1f78402763e05a16a1d8b90f6aa4a32c9cae7420baa60a1")
    {
        return Err(capacity_asset_error(
            ASSET,
            "final post-acceptance review binding is absent or substituted",
        ));
    }

    if qualification["qualification_budget"]["preallocation_receipt"]
        != serde_json::json!({
            "schema": "nq.v3_projection_capsule_qualification_budget_enforcement_receipt.v1",
            "receipt_identity": "nq.v3_projection_capsule_qualification_budget_enforcement_receipt.v1",
            "receipt_sha256": "sha256:2c4f886cd7831a4f3f797922dbd3ba5a7053bb1c6fed106cfb9735fa2fea7db9",
            "budget_identity": "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
            "preallocated_workspace_bytes": 67_108_864,
            "slot_count": 4,
            "slot_bytes": 16_777_216,
            "maximum_observed_parallel_materializations": 1,
            "allocated_block_bytes": 67_108_864,
            "result": "preallocation-verified"
        })
    {
        return Err(capacity_asset_error(
            ASSET,
            "budget preallocation receipt binding differs",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Four exact attempt receipts and their joins remain one closed audit.
fn validate_v3_projection_capsule_materialization_attempts(
    qualification: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    const ASSET: &str = "nq.v3_projection_capsule_bound_qualification.v1";
    let budget_receipt = "sha256:2c4f886cd7831a4f3f797922dbd3ba5a7053bb1c6fed106cfb9735fa2fea7db9";
    let expected = serde_json::json!([
        {
            "branch": "admitted",
            "distribution": "all_report_level",
            "budget_receipt_sha256": budget_receipt,
            "attempt_receipt_canonical_bytes": 465,
            "attempt_receipt_sha256":
                "sha256:8fc3267c0b965648570b442fdfbc4ef194c46c26dfd366b71237759f5d3f590f",
            "slot_index": 0,
            "attempt_identity":
                "nq.cap-h14.materialization-attempt.admitted-all-report-level.v1",
            "disposition": "pre-materialization-refused-budget",
            "output_length_bytes": null,
            "output_sha256": null,
            "refusal_reason": "symbolic-ceiling-exceeds-single-materialization-budget",
            "observed_parallel_materializations": 0
        },
        {
            "branch": "admitted",
            "distribution": "one_per_observation_then_nested",
            "budget_receipt_sha256": budget_receipt,
            "attempt_receipt_canonical_bytes": 495,
            "attempt_receipt_sha256":
                "sha256:460f4112b5255b8adecd051e4371d1233fe9e7682473c55b004c39e17584d698",
            "slot_index": 1,
            "attempt_identity":
                "nq.cap-h14.materialization-attempt.admitted-one-per-observation-then-nested.v1",
            "disposition": "pre-materialization-refused-budget",
            "output_length_bytes": null,
            "output_sha256": null,
            "refusal_reason": "symbolic-ceiling-exceeds-single-materialization-budget",
            "observed_parallel_materializations": 0
        },
        {
            "branch": "non_success_no_submission",
            "distribution": "not_applicable",
            "budget_receipt_sha256": budget_receipt,
            "attempt_receipt_canonical_bytes": 476,
            "attempt_receipt_sha256":
                "sha256:e6bc2b6941f1ca468f93b6d791beb0e1c098f3c9a3210c41ac5379dbda886b06",
            "slot_index": 2,
            "attempt_identity":
                "nq.cap-h14.materialization-attempt.non-success-no-submission.v1",
            "disposition": "materialized",
            "output_length_bytes": 68_127,
            "output_sha256":
                "sha256:b8b5c2a6af80d544c1977fec8521bfbadd80c728e0af4c7f17f4cb87dd8492ca",
            "refusal_reason": null,
            "observed_parallel_materializations": 1
        },
        {
            "branch": "non_success_rejected_submission",
            "distribution": "not_applicable",
            "budget_receipt_sha256": budget_receipt,
            "attempt_receipt_canonical_bytes": 488,
            "attempt_receipt_sha256":
                "sha256:d22d912fa0e667522ba59402356cb931a071822dc34c7906ab45c8370e88edcd",
            "slot_index": 3,
            "attempt_identity":
                "nq.cap-h14.materialization-attempt.non-success-rejected-submission.v1",
            "disposition": "materialized",
            "output_length_bytes": 74_768,
            "output_sha256":
                "sha256:4c13e0ee18899a1d5490b0ad1752612009ab9cfcfc45a93b10e7b9adfca6f99a",
            "refusal_reason": null,
            "observed_parallel_materializations": 1
        }
    ]);
    if qualification["materialization_attempts"] != expected {
        return Err(capacity_asset_error(
            ASSET,
            "materialization attempt/slot receipts differ",
        ));
    }
    let shape_rows = qualification["census"]["shapes"]["rows"]
        .as_array()
        .ok_or_else(|| capacity_asset_error(ASSET, "shape evidence rows absent"))?;
    let attempts = expected
        .as_array()
        .expect("closed materialization attempt inventory");
    if shape_rows.len() != attempts.len()
        || shape_rows.iter().zip(attempts).any(|(shape, attempt)| {
            shape["branch"] != attempt["branch"]
                || shape["distribution"] != attempt["distribution"]
                || shape["attempt_identity"] != attempt["attempt_identity"]
        })
    {
        return Err(capacity_asset_error(
            ASSET,
            "shape evidence does not exactly join its materialization attempt",
        ));
    }
    let evidence = qualification["evidence_dispositions"]
        .as_array()
        .ok_or_else(|| capacity_asset_error(ASSET, "shape disposition inventory absent"))?;
    for (shape, attempt) in shape_rows.iter().zip(attempts) {
        let evidence_id = shape["evidence_case_id"]
            .as_str()
            .ok_or_else(|| capacity_asset_error(ASSET, "shape evidence identity absent"))?;
        let matching = evidence
            .iter()
            .filter(|row| row["evidence_id"].as_str() == Some(evidence_id))
            .collect::<Vec<_>>();
        let [disposition] = matching.as_slice() else {
            return Err(capacity_asset_error(
                ASSET,
                "shape does not resolve exactly one evidence disposition",
            ));
        };
        let common_join = disposition["scope"] == "closed_shape"
            && disposition["symbolic_ceiling_bytes"] == shape["canonical_bytes"];
        let attempt_join = match attempt["disposition"].as_str() {
            Some("materialized") => {
                disposition["disposition"] == "ATTAINABLE-MATERIALIZED"
                    && disposition["actual_canonical_bytes"] == attempt["output_length_bytes"]
                    && disposition["production_witness_sha256"] == attempt["output_sha256"]
                    && disposition["budget_identity"].is_null()
            }
            Some("pre-materialization-refused-budget") => {
                disposition["disposition"] == "INFEASIBLE-UNDER-IDENTIFIED-BUDGET"
                    && disposition["actual_canonical_bytes"].is_null()
                    && disposition["production_witness_sha256"].is_null()
                    && disposition["budget_identity"]
                        == "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1"
            }
            _ => false,
        };
        if !common_join || !attempt_join {
            return Err(capacity_asset_error(
                ASSET,
                "shape, attempt, and typed disposition do not exactly join",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One exact 151/38/4 qualification census is load-bearing.
fn validate_v3_projection_capsule_qualification_census(
    qualification: &serde_json::Map<String, serde_json::Value>,
    manifest: &serde_json::Value,
) -> Result<()> {
    const ASSET: &str = "nq.v3_projection_capsule_bound_qualification.v1";
    let manifest_fields = manifest["capsule_field_inventory"]
        .as_array()
        .ok_or_else(|| capacity_asset_error(ASSET, "v2 field census absent"))?;
    let field_rows = qualification["census"]["fields"]["rows"]
        .as_array()
        .ok_or_else(|| capacity_asset_error(ASSET, "qualified field census absent"))?;
    if manifest_fields.len() != 151 || field_rows.len() != 151 {
        return Err(capacity_asset_error(
            ASSET,
            "qualified field census population differs",
        ));
    }

    let descriptor_sources = manifest["bounded_json_sources"]
        .as_array()
        .ok_or_else(|| capacity_asset_error(ASSET, "bounded-JSON source census absent"))?
        .iter()
        .filter_map(|row| row["descriptor_key"].as_str())
        .collect::<BTreeSet<_>>();
    let generic_cases = [
        "nq.cap-h14.large-generic-descriptor-component.v1",
        "nq.cap-h14.large-generic-full-capsule.v1",
        "nq.cap-h14.tractable-descriptor-component.v1",
        "nq.cap-h14.zero-key-two-member-descriptor.v1",
    ];
    let shape_case = |branch: &str, distribution: &str| match (branch, distribution) {
        ("admitted", "all_report_level") => Some("nq.cap-h14.shape.admitted-all-report-level.v1"),
        ("admitted", "one_per_observation_then_nested") => {
            Some("nq.cap-h14.shape.admitted-one-per-observation-then-nested.v1")
        }
        ("non_success_no_submission", "not_applicable") => {
            Some("nq.cap-h14.shape.non-success-no-submission.v1")
        }
        ("non_success_rejected_submission", "not_applicable") => {
            Some("nq.cap-h14.shape.non-success-rejected-submission.v1")
        }
        _ => None,
    };

    let mut source_evidence = BTreeMap::<String, QualificationSourceEvidence>::new();
    let mut stripped_fields = Vec::with_capacity(field_rows.len());
    for (expected, row) in manifest_fields.iter().zip(field_rows) {
        let pointer = row["pointer_family"]
            .as_str()
            .ok_or_else(|| capacity_asset_error(ASSET, "field pointer absent"))?;
        let classification = row["classification"]
            .as_str()
            .ok_or_else(|| capacity_asset_error(ASSET, "field classification absent"))?;
        let source = row["bound_source"]
            .as_str()
            .ok_or_else(|| capacity_asset_error(ASSET, "field bound source absent"))?;
        let stripped = serde_json::json!({
            "pointer_family": pointer,
            "classification": classification,
            "bound_source": source
        });
        if &stripped != expected {
            return Err(capacity_asset_error(
                ASSET,
                "qualified field row does not exactly project to the v2 manifest",
            ));
        }
        stripped_fields.push(stripped);

        let shape_values = row["applicable_shapes"]
            .as_array()
            .ok_or_else(|| capacity_asset_error(ASSET, "field shape scopes absent"))?;
        let shapes = shape_values
            .iter()
            .filter_map(|shape| {
                Some((
                    shape["branch"].as_str()?.to_owned(),
                    shape["distribution"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeSet<_>>();
        let canonical_shapes = shapes
            .iter()
            .map(|(branch, distribution)| {
                serde_json::json!({"branch": branch, "distribution": distribution})
            })
            .collect::<Vec<_>>();
        if shapes.is_empty()
            || shapes.len() != shape_values.len()
            || serde_json::Value::Array(canonical_shapes) != row["applicable_shapes"]
        {
            return Err(capacity_asset_error(
                ASSET,
                "field shape scopes are empty, duplicated, unknown, or unsorted",
            ));
        }
        let mut expected_cases = shapes
            .iter()
            .map(|(branch, distribution)| {
                shape_case(branch, distribution).ok_or_else(|| {
                    capacity_asset_error(ASSET, "field names an unknown qualification shape")
                })
            })
            .collect::<Result<BTreeSet<_>>>()?
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if descriptor_sources.contains(source) {
            expected_cases.extend(generic_cases.into_iter().map(str::to_owned));
        }
        let case_values = row["evidence_case_ids"]
            .as_array()
            .ok_or_else(|| capacity_asset_error(ASSET, "field evidence cases absent"))?;
        let cases = case_values
            .iter()
            .filter_map(|case| case.as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>();
        let canonical_cases = cases
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>();
        if cases != expected_cases
            || cases.len() != case_values.len()
            || serde_json::Value::Array(canonical_cases) != row["evidence_case_ids"]
        {
            return Err(capacity_asset_error(
                ASSET,
                "field evidence cases do not exactly resolve its shape/source obligations",
            ));
        }
        let (pointers, source_shapes, source_cases) =
            source_evidence.entry(source.to_owned()).or_default();
        pointers.insert(pointer.to_owned());
        source_shapes.extend(shapes);
        source_cases.extend(cases);
    }

    let manifest_field_value = serde_json::Value::Array(stripped_fields);
    let manifest_source_value = serde_json::Value::Array(
        source_evidence
            .keys()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );
    let qualification_sources = source_evidence
        .into_iter()
        .map(|(source_identity, (pointers, shapes, cases))| {
            serde_json::json!({
                "source_identity": source_identity,
                "pointer_families": pointers.into_iter().collect::<Vec<_>>(),
                "applicable_shapes": shapes
                    .into_iter()
                    .map(|(branch, distribution)| serde_json::json!({
                        "branch": branch,
                        "distribution": distribution
                    }))
                    .collect::<Vec<_>>(),
                "evidence_case_ids": cases.into_iter().collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let qualification_source_value = serde_json::Value::Array(qualification_sources);
    if qualification_source_value != qualification["census"]["sources"]["rows"] {
        return Err(capacity_asset_error(
            ASSET,
            "source evidence map is not the exact derived union of field evidence",
        ));
    }

    let manifest_shapes = serde_json::json!([
        {
            "branch": "admitted",
            "distribution": "all_report_level",
            "canonical_bytes": 133_038_721
        },
        {
            "branch": "admitted",
            "distribution": "one_per_observation_then_nested",
            "canonical_bytes": 133_034_626
        },
        {
            "branch": "non_success_no_submission",
            "distribution": "not_applicable",
            "canonical_bytes": 68_127
        },
        {
            "branch": "non_success_rejected_submission",
            "distribution": "not_applicable",
            "canonical_bytes": 74_768
        }
    ]);
    let qualification_shapes = qualification["census"]["shapes"]["rows"]
        .as_array()
        .ok_or_else(|| capacity_asset_error(ASSET, "qualified shape census absent"))?;
    let stripped_shapes = serde_json::Value::Array(
        qualification_shapes
            .iter()
            .map(|row| {
                serde_json::json!({
                    "branch": row["branch"],
                    "distribution": row["distribution"],
                    "canonical_bytes": row["canonical_bytes"]
                })
            })
            .collect(),
    );
    if stripped_shapes != manifest_shapes {
        return Err(capacity_asset_error(
            ASSET,
            "qualified shape rows do not exactly project to the closed shape census",
        ));
    }

    for (name, manifest_rows, qualification_rows, population, qualified_digest) in [
        (
            "fields",
            &manifest_field_value,
            &qualification["census"]["fields"]["rows"],
            151_u64,
            "sha256:955cbe8b2748a99a18a573aa508ae945c7ff9864d5246ae0fb4e8f123cd125fc",
        ),
        (
            "sources",
            &manifest_source_value,
            &qualification["census"]["sources"]["rows"],
            38_u64,
            "sha256:5e135de48c3c261fa5cd4c529e37927d4b04ad053912705d5072b5021a971766",
        ),
        (
            "shapes",
            &manifest_shapes,
            &qualification["census"]["shapes"]["rows"],
            4_u64,
            "sha256:c8b6fd782762c13434d1b5d9ec25c8a1bfce5225d7af24732e71aa3c26bb67f9",
        ),
    ] {
        let census = &qualification["census"][name];
        let manifest_digest = sha256_bytes(&canonical_json_bytes(manifest_rows)?);
        let qualification_digest = sha256_bytes(&canonical_json_bytes(qualification_rows)?);
        if census["population"].as_u64() != Some(population)
            || census["manifest_rows_sha256"].as_str() != Some(manifest_digest.as_str())
            || census["qualification_rows_sha256"].as_str() != Some(qualified_digest)
            || qualification_digest.as_str() != qualified_digest
        {
            return Err(capacity_asset_error(
                ASSET,
                "manifest/qualification census digest or population differs",
            ));
        }
    }
    Ok(())
}

fn capacity_asset_error(asset: &str, detail: &str) -> ContractError {
    ContractError::CapacityAssetValidation {
        asset: asset.to_owned(),
        detail: detail.to_owned(),
    }
}

pub(crate) fn embedded_schema_bytes(schema: &str) -> Option<&'static [u8]> {
    macro_rules! asset {
        ($name:literal) => {
            include_bytes!(concat!("../assets/schemas/", $name, ".schema.json")).as_slice()
        };
    }
    Some(match schema {
        "nq.host_role_common.v1" => asset!("nq.host_role_common.v1"),
        "nq.role_manifest.v1" => asset!("nq.role_manifest.v1"),
        "nq.buffer_delivery_policy.v1" => asset!("nq.buffer_delivery_policy.v1"),
        "nq.static_profile_cohort_manifest.v1" => {
            asset!("nq.static_profile_cohort_manifest.v1")
        }
        "nq.node_enrollment.v1" => asset!("nq.node_enrollment.v1"),
        "nq.host_role_relation.v1" => asset!("nq.host_role_relation.v1"),
        "nq.runtime_activation.v1" => asset!("nq.runtime_activation.v1"),
        "nq.witness_attachment.v1" => asset!("nq.witness_attachment.v1"),
        "nq.host_role_lifecycle_event.v1" => asset!("nq.host_role_lifecycle_event.v1"),
        "nq.witness_lifecycle_event.v1" => asset!("nq.witness_lifecycle_event.v1"),
        "nq.node_key_lifecycle_event.v1" => asset!("nq.node_key_lifecycle_event.v1"),
        "nq.restore_activation_proof.v1" => asset!("nq.restore_activation_proof.v1"),
        "nq.diagnostic_invocation_request.v1" => {
            asset!("nq.diagnostic_invocation_request.v1")
        }
        "nq.invocation_decision.v1" => asset!("nq.invocation_decision.v1"),
        "nq.operation_authorization.v1" => asset!("nq.operation_authorization.v1"),
        "nq.custody_reservation.v1" => asset!("nq.custody_reservation.v1"),
        "nq.custody_reservation_plan.v1" => asset!("nq.custody_reservation_plan.v1"),
        "nq.custody_capacity_allocation.v1" => asset!("nq.custody_capacity_allocation.v1"),
        "nq.custody_carrier_map.v1" => asset!("nq.custody_carrier_map.v1"),
        "nq.v3_projection_capsule_bound_manifest.v1" => {
            asset!("nq.v3_projection_capsule_bound_manifest.v1")
        }
        "nq.v3_projection_capsule_bound_manifest.v2" => {
            asset!("nq.v3_projection_capsule_bound_manifest.v2")
        }
        "nq.v3_projection_capsule_bound_qualification.v1" => {
            asset!("nq.v3_projection_capsule_bound_qualification.v1")
        }
        "nq.execution_launch.v1" => asset!("nq.execution_launch.v1"),
        "nq.native_profile_qualification.v1" => {
            asset!("nq.native_profile_qualification.v1")
        }
        "nq.native_clock_qualification.v1" => asset!("nq.native_clock_qualification.v1"),
        "nq.deadline_evaluation.v1" => asset!("nq.deadline_evaluation.v1"),
        "nq.execution_identity_binding.v2" => asset!("nq.execution_identity_binding.v2"),
        "nq.authenticated_artifact_envelope.v1" => {
            asset!("nq.authenticated_artifact_envelope.v1")
        }
        "nq.artifact_delivery_attempt.v1" => asset!("nq.artifact_delivery_attempt.v1"),
        "nightshift.artifact_custody_receipt.v1" => {
            asset!("nightshift.artifact_custody_receipt.v1")
        }
        "nq.artifact_delivery_record.v1" => asset!("nq.artifact_delivery_record.v1"),
        "nq.inspector_result_set.v1" => asset!("nq.inspector_result_set.v1"),
        "nq.inspector_snapshot.v1" => asset!("nq.inspector_snapshot.v1"),
        "nq.inspector_read_receipt.v1" => asset!("nq.inspector_read_receipt.v1"),
        "nq.decommission_ledger_snapshot.v1" => {
            asset!("nq.decommission_ledger_snapshot.v1")
        }
        "nq.decommission_cut.v1" => asset!("nq.decommission_cut.v1"),
        _ => return None,
    })
}

fn expected_capacity_schema_assets() -> BTreeMap<&'static str, Sha256Digest> {
    [
        (
            "nq.custody_reservation_plan.v1",
            "sha256:ab7a8deb0b122e08d74f8df65ef975e2f04b6c843802f165f24edee1f9a50855",
        ),
        (
            "nq.custody_capacity_allocation.v1",
            "sha256:d0b70a0a8746520024175d8d4f8a2496bee08d36672325a305f84a2339aac21e",
        ),
        (
            "nq.custody_carrier_map.v1",
            "sha256:9c911882c6fface9dc8882ecc1ed76a240380715faa5a160afef44e84816b770",
        ),
        (
            "nq.v3_projection_capsule_bound_manifest.v1",
            "sha256:9d52629189cbfbd34a01b1b23161da1bbfb2296af70d42f594437a7ff166ef41",
        ),
        (
            "nq.v3_projection_capsule_bound_manifest.v2",
            "sha256:3dc592698ede4b619f9a198020754b03b13877122a29cea33f15ce690fae313a",
        ),
        (
            "nq.v3_projection_capsule_bound_qualification.v1",
            "sha256:9566f17f30c03bffcdd9f0921e6b49b9e4dda55b19ad38d0ffd676d05dd73c5c",
        ),
    ]
    .into_iter()
    .map(|(schema, digest)| {
        (
            schema,
            Sha256Digest::parse(digest).expect("embedded capacity schema digest is valid"),
        )
    })
    .collect()
}

fn expected_capacity_static_assets()
-> BTreeMap<&'static str, (&'static str, &'static str, Sha256Digest)> {
    [
        (
            "nq.custody_carrier_map.v1",
            (
                "nq.custody_carrier_map.v1",
                "nq.custody_carrier_map.v1.json",
                "sha256:6fa5b977cbf3dc01481452aa08822053eaa3a71954ba0f11e3d7051f00d4c240",
            ),
        ),
        (
            "nq.v3_projection_capsule_bound_manifest.v1",
            (
                "nq.v3_projection_capsule_bound_manifest.v1",
                "nq.v3_projection_capsule_bound_manifest.v1.json",
                "sha256:e470d4245d2c660a6fcee26549c53dd205a3884d9f279815405c83b2ae02528b",
            ),
        ),
        (
            "nq.v3_projection_capsule_bound_manifest.v2",
            (
                "nq.v3_projection_capsule_bound_manifest.v2",
                "nq.v3_projection_capsule_bound_manifest.v2.json",
                "sha256:a91bae86a5956f6a63edccf562a0373958fd4174d7319d9b2830694ff311b51b",
            ),
        ),
        (
            "nq.v3_projection_capsule_bound_qualification.v1",
            (
                "nq.v3_projection_capsule_bound_qualification.v1",
                "nq.v3_projection_capsule_bound_qualification.v1.json",
                "sha256:97b5d4c0025cc26093d514df1a192510dc14af9f74444e5d56066a85da4353d2",
            ),
        ),
    ]
    .into_iter()
    .map(|(identity, (schema, path, digest))| {
        (
            identity,
            (
                schema,
                path,
                Sha256Digest::parse(digest)
                    .expect("embedded capacity static-asset digest is valid"),
            ),
        )
    })
    .collect()
}

fn expected_native_correspondence_assets() -> BTreeMap<&'static str, Sha256Digest> {
    [
        (
            "nq.native_profile_qualification.v1",
            "sha256:0b68fc97e82e57f40ef315ed352bd36d2ed1fef818553125345f8c299c565fc5",
        ),
        (
            "nq.native_clock_qualification.v1",
            "sha256:e68c3ab69104ba71557c71b6cfa336aa3b645e155a2de8bf01f59c79bcd83c9e",
        ),
        (
            "nq.deadline_evaluation.v1",
            "sha256:c4a01a920d38860e5e85bc55bc66637005d0eb4f50740e3ebb92bb3977fdf5f8",
        ),
    ]
    .into_iter()
    .map(|(schema, digest)| {
        (
            schema,
            Sha256Digest::parse(digest).expect("embedded schema digest is valid"),
        )
    })
    .collect()
}

#[allow(clippy::too_many_lines)] // Exact immutable asset table is clearer as one closed list.
fn expected_assets() -> BTreeMap<&'static str, Sha256Digest> {
    [
        (
            "nq.host_role_common.v1",
            "sha256:59c14b188594f01ab8c0bac815f54d7926abd981605adc63374f848d96fa2d87",
        ),
        (
            "nq.role_manifest.v1",
            "sha256:8723c6b69bdb1e064814d5288ca8b3f5024255f7432924cf0abfd84764057ea5",
        ),
        (
            "nq.buffer_delivery_policy.v1",
            "sha256:767d9f8ed7d4e74bf27b20e7fac1b4e7223f63b727840054b250fabbf0a5a22c",
        ),
        (
            "nq.static_profile_cohort_manifest.v1",
            "sha256:4ee7034802886f77a0e4780d074687950ee71bf9b57df0e39c6c79ee990a83fa",
        ),
        (
            "nq.node_enrollment.v1",
            "sha256:c6c7fc6220b4979f47d9f677d210fbaa2d6a70704e990e0fd517a6a66b212391",
        ),
        (
            "nq.host_role_relation.v1",
            "sha256:071bb272d5b9f0732999c09c6463e3b64dc6e83f22f3d1ea788704dff00ba818",
        ),
        (
            "nq.runtime_activation.v1",
            "sha256:1c02cc5b065b59f1a82d0bec13dadbd796cd1b3509e941514a23b01b65b378bd",
        ),
        (
            "nq.witness_attachment.v1",
            "sha256:7369eb42aa476151b6bf35fb873b7abf3958d3eb50892b27cbebeac66b0a3a56",
        ),
        (
            "nq.host_role_lifecycle_event.v1",
            "sha256:26e6428cfff786b031a0f04f4ebfb229abeaaac60b732455728d60ffe25222cc",
        ),
        (
            "nq.witness_lifecycle_event.v1",
            "sha256:89a123e1ec903403586e46aba344f5821e00c2291b5e0cbf98f185750dab9fc1",
        ),
        (
            "nq.node_key_lifecycle_event.v1",
            "sha256:57391a6abd8bcf244d48d56029bf5e16bf20e837733d1a6b1bd765bd883aa0d4",
        ),
        (
            "nq.restore_activation_proof.v1",
            "sha256:7e19ed14cb244dded478da2d96569ca7dcd5cca9f0e9dc4e24b1e6f8954584dd",
        ),
        (
            "nq.diagnostic_invocation_request.v1",
            "sha256:1279160180198a0fca0012666e76929079eb61a294cb54348c642ad5258f81a1",
        ),
        (
            "nq.invocation_decision.v1",
            "sha256:d6c18753a5def17012101c51f8a21f4f778ad0150710b7e4a53a230d184fb90b",
        ),
        (
            "nq.operation_authorization.v1",
            "sha256:82b3b670383ea3eb9fd3dfad9cc9ca5cc9d830898ae5a753033dd2cdb4d9f321",
        ),
        (
            "nq.custody_reservation.v1",
            "sha256:7da0319bfdfd88860ec863888c37d2483b5cd916454f62ac00eb84e8736b9cd2",
        ),
        (
            "nq.execution_launch.v1",
            "sha256:738784ea3714c6181cf77df1dbc6b08e936bb377ef750cd1c361416b4f755d9c",
        ),
        (
            "nq.execution_identity_binding.v2",
            "sha256:b4a8ce2b583275fbd6e2b695bc3cf4592691f0e819c2b2074fd22b4c815fabd1",
        ),
        (
            "nq.authenticated_artifact_envelope.v1",
            "sha256:f60d7f7230d44e525b993ef8d64c451ae9a5af7fe752575278d0e244b96a743a",
        ),
        (
            "nq.artifact_delivery_attempt.v1",
            "sha256:d04b04281b82f183a1677ca39c8981c100f2389ee413d1f33c9a86b1205ffa1e",
        ),
        (
            "nightshift.artifact_custody_receipt.v1",
            "sha256:6997135c65b81bd6c90c400ad22878fbfcd84b61c659623fd5a86a6bbf34e4ad",
        ),
        (
            "nq.artifact_delivery_record.v1",
            "sha256:3c90437eab55b84d1f9919967d362159809695ff8f5b54779e095a08d1dc60e3",
        ),
        (
            "nq.inspector_result_set.v1",
            "sha256:ce8965ed1a04184e345f543c95551e447dd1180fda48b9660db2c008242f8094",
        ),
        (
            "nq.inspector_snapshot.v1",
            "sha256:7475c3318b613cbf3c7e9f25f87ce53fefbe8f1904a019eb3d4eb2f5821b6100",
        ),
        (
            "nq.inspector_read_receipt.v1",
            "sha256:565eedc08d509b5fbcc8e1c8fc22c9b0fbc6e3567f9f00696ebf1c98d6f8e78d",
        ),
        (
            "nq.decommission_ledger_snapshot.v1",
            "sha256:d1380447895230dad5de69629e1f8e5dc12396e9e0abec20f3b4d9cf7ecc92d9",
        ),
        (
            "nq.decommission_cut.v1",
            "sha256:4df5d4389df00923b78f536c6842329e28518c371df75e66fcaf5d3c7a01ed41",
        ),
    ]
    .into_iter()
    .map(|(schema, digest)| {
        (
            schema,
            Sha256Digest::parse(digest).expect("embedded schema digest is valid"),
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CUSTODY_CARRIER_MAP_BYTES, STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE,
        V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES,
        V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES,
        inspected_candidate_v3_projection_capsule_bound_manifest,
        require_qualified_v3_projection_capsule_bound_manifest,
        require_qualified_v3_projection_capsule_bound_manifest_v2,
        require_store_owned_capacity_allocation_construction,
        validate_capacity_extension_boundaries, validate_custody_carrier_map,
        validate_v3_projection_capsule_bound_manifest_v2,
        validate_v3_projection_capsule_bound_qualification_v1,
        validate_v3_projection_capsule_qualification_pair, verified_capacity_extension_manifest,
    };

    #[test]
    fn carrier_map_usage_includes_missing_committed_bytes_and_mutation_refuses() {
        let value: serde_json::Value =
            serde_json::from_slice(CUSTODY_CARRIER_MAP_BYTES).expect("embedded carrier map");
        validate_custody_carrier_map(&value).expect("exact carrier map");
        assert_eq!(
            value["equations"]["store_usage"],
            "U=B+G+sum(retained_or_charged_T)+missing_committed_bytes"
        );

        let mut omitted = value;
        omitted["equations"]["store_usage"] = "U=B+G+sum(retained_or_charged_T)".into();
        assert!(validate_custody_carrier_map(&omitted).is_err());
    }

    #[test]
    fn candidate_v3_bound_is_inspectable_but_not_production_qualified() {
        inspected_candidate_v3_projection_capsule_bound_manifest()
            .expect("blocked candidate remains inspectable");
        let error = require_qualified_v3_projection_capsule_bound_manifest()
            .expect_err("CAP-H14 must block production qualification");
        assert!(error.to_string().contains("CAP-H14"));
        assert!(
            error
                .to_string()
                .contains("production qualification blocked")
        );
    }

    #[test]
    fn qualified_v2_is_presence_based_while_historical_v1_remains_blocked() {
        let qualified = require_qualified_v3_projection_capsule_bound_manifest_v2()
            .expect("exact v2 manifest and separate qualification carrier");
        assert_eq!(
            qualified.qualification_basis_sha256.as_str(),
            "sha256:f5945a389d9fd94ce9e2b3625cc0970acf904628793028f5adfbce27dcad82cb"
        );

        let historical = require_qualified_v3_projection_capsule_bound_manifest()
            .expect_err("historical v1 remains frozen and blocked");
        assert!(historical.to_string().contains("CAP-H14"));

        let mut manifest: serde_json::Value =
            serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_BYTES)
                .expect("v2 manifest");
        let qualification: serde_json::Value =
            serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES)
                .expect("qualification carrier");
        manifest["cap_h14_qualification"]["qualification_id"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        manifest["cap_h14_qualification"]["canonical_bytes_sha256"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        validate_v3_projection_capsule_bound_manifest_v2(&manifest)
            .expect("an empty gap list alone remains a structurally valid v2 candidate");
        assert!(
            validate_v3_projection_capsule_qualification_pair(
                &manifest,
                &qualification,
                V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES,
            )
            .is_err(),
            "an empty gap list without the exact positive carrier must not qualify"
        );
    }

    #[test]
    fn exact_cap_h14_evidence_and_authority_boundaries_are_load_bearing() {
        let qualification: serde_json::Value =
            serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES)
                .expect("qualification carrier");
        validate_v3_projection_capsule_bound_qualification_v1(&qualification)
            .expect("exact carrier");

        let mut mutations = Vec::new();

        let mut missing = qualification.clone();
        missing["evidence_dispositions"]
            .as_array_mut()
            .expect("evidence inventory")
            .pop();
        mutations.push(("missing evidence", missing));

        let mut duplicate = qualification.clone();
        let duplicate_row = duplicate["evidence_dispositions"][0].clone();
        duplicate["evidence_dispositions"]
            .as_array_mut()
            .expect("evidence inventory")
            .push(duplicate_row);
        mutations.push(("duplicate evidence", duplicate));

        let mut relabeled = qualification.clone();
        relabeled["evidence_dispositions"][0]["evidence_id"] = "nq.cap-h14.relabelled.v1".into();
        mutations.push(("relabeled evidence", relabeled));

        let mut disposition = qualification.clone();
        disposition["evidence_dispositions"][1]["disposition"] = "ATTAINABLE-MATERIALIZED".into();
        mutations.push(("changed disposition", disposition));

        let mut map_digest = qualification.clone();
        map_digest["census"]["fields"]["qualification_rows_sha256"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        mutations.push(("changed census digest", map_digest));

        let mut attempt = qualification.clone();
        attempt["materialization_attempts"][2]["output_sha256"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        mutations.push(("changed materialization witness", attempt));

        let mut proof = qualification.clone();
        proof["evidence_dispositions"][1]["unattainability_proof_sha256"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        mutations.push(("changed unattainability proof", proof));

        let mut policy = qualification.clone();
        policy["policy_bindings"]["accepted_adjudication"]["sha256"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        mutations.push(("changed policy binding", policy));

        let mut review = qualification.clone();
        review["implementation_bindings"]["post_acceptance_review"]["pre_review_projection_sha256"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        mutations.push(("changed review binding", review));

        let mut nonclaim = qualification;
        nonclaim["nonclaims"][0] = "C3 is satisfied".into();
        mutations.push(("weakened C3 nonclaim", nonclaim));

        for (name, mutation) in mutations {
            assert!(
                validate_v3_projection_capsule_bound_qualification_v1(&mutation).is_err(),
                "{name} must refuse"
            );
        }
    }

    #[test]
    fn caller_carried_allocation_remains_blocked_independently_of_cap_h14() {
        require_qualified_v3_projection_capsule_bound_manifest_v2()
            .expect("pure C1 CAP-H14 qualification");
        let qualification: serde_json::Value =
            serde_json::from_slice(V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_BYTES)
                .expect("qualified carrier");
        let ceiling = qualification["census"]["shapes"]["rows"][0]["canonical_bytes"]
            .as_u64()
            .expect("closed-shape ceiling");
        for caller_candidate in [ceiling - 1, ceiling, ceiling + 1] {
            let error = require_store_owned_capacity_allocation_construction()
                .expect_err("C1 cannot select a product allocation at C-1, C, or C+1");
            assert!(
                error
                    .to_string()
                    .contains(STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE),
                "candidate {caller_candidate} must still stop at exact C3"
            );
        }
        let error = require_store_owned_capacity_allocation_construction()
            .expect_err("C1 cannot select a product allocation");
        assert!(
            error
                .to_string()
                .contains(STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE)
        );
        let manifest = verified_capacity_extension_manifest().expect("capacity manifest");
        assert_eq!(manifest.qualification_gaps.len(), 1);
        assert!(
            manifest.qualification_gaps[0]
                .required_evidence
                .contains("source set")
        );
        assert!(
            manifest.qualification_gaps[0]
                .required_evidence
                .contains("derived projection-capsule bound")
        );
    }

    #[test]
    fn c3_product_selection_gap_is_closed_and_load_bearing() {
        let manifest = verified_capacity_extension_manifest().expect("capacity manifest");
        for mutation in ["remove", "rename", "duplicate", "status", "nonclaim"] {
            let mut changed = manifest.clone();
            match mutation {
                "remove" => changed.qualification_gaps.clear(),
                "rename" => changed.qualification_gaps[0].gate.push_str("-substituted"),
                "duplicate" => changed
                    .qualification_gaps
                    .push(changed.qualification_gaps[0].clone()),
                "status" => changed.qualification_gaps[0].status = "qualified".into(),
                "nonclaim" => changed.nonclaims[3].push_str("-weakened"),
                _ => unreachable!(),
            }
            assert!(
                validate_capacity_extension_boundaries(&changed).is_err(),
                "{mutation} must refuse"
            );
        }
    }
}
