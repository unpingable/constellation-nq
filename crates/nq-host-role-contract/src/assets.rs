//! Immutable source-schema provenance for the runtime contract package.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, sha256_bytes};
use serde::{Deserialize, Serialize};

use crate::{ContractError, Result, RuntimeSchema};

/// Exact skunkworks decision commit from which the package was implemented.
pub const CONTRACT_SOURCE_COMMIT: &str = "d8aba7b728236120e0dfd05ba6feb3e64fc3647d";
/// Exact source tree at the ratified decision commit.
pub const CONTRACT_SOURCE_TREE: &str = "b88a7a9ad380ed770d936f54f6da7eef1a9a15fe";
/// Source path inside the skunkworks repository.
pub const CONTRACT_SOURCE_PATH: &str = "audits/nq-host-role-runtime-contract-v1";

const MANIFEST_BYTES: &[u8] = include_bytes!("../assets/manifest.json");

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

/// One exact source schema asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaAsset {
    /// Contract schema identity.
    pub schema: String,
    /// Path at the immutable source commit.
    pub source_path: String,
    /// SHA-256 of exact source bytes.
    pub sha256: Sha256Digest,
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
    /// Exact schema assets supported by this crate.
    pub assets: Vec<SchemaAsset>,
    /// Authority boundaries retained by the package.
    pub nonclaims: Vec<String>,
}

/// Parses and verifies the embedded package manifest.
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
    for schema in RuntimeSchema::ALL {
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
        "nq.execution_launch.v1" => asset!("nq.execution_launch.v1"),
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
