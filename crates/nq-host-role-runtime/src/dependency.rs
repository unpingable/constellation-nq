//! Compatibility surface over the pure dependency-custody verifier.
//!
//! The shared crate owns the exact carriers and their authentication errors.
//! This module preserves the existing host-runtime type paths and maps every
//! shared refusal into the corresponding host-runtime refusal without
//! flattening distinctions.

pub use nq_host_role_dependency_custody::{
    ADMISSION_RECEIPT_SET_SCHEMA, AUTHORITY_ADMISSION_SNAPSHOT_SCHEMA,
    AdmissionReceiptSetAvailability, AdmissionReceiptSetCustody, AdmissionSignatureAlgorithm,
    AuthenticatedRuntimeDependencyClosure, AuthenticatedSourceResolution, AuthorityAdmission,
    AuthorityAdmissionKind, AuthorityAdmissionSnapshot, AuthoritySourcePurpose,
    AuthoritySourceRequirement, AuthoritySourceResult, AuthoritySourceState,
    DependencyAdmissionKind, DependencyAdmissionReceipt, DependencyCustodyError,
    ED25519_TRUST_ANCHOR_SCHEMA, EXTERNAL_DEPENDENCY_SNAPSHOT_SCHEMA, Ed25519TrustAnchor,
    ExactDependencyCustodyBinding, ExactExternalDependency, ExternalDependencyAvailability,
    ExternalDependencySnapshot, ExternalSourcePurpose, ExternalSourceRequirement,
    ExternalSourceResult, ExternalSourceState, RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA,
    RUNTIME_DEPENDENCY_GENERATION_SCHEMA, RuntimeDependencies, RuntimeDependencyGeneration,
    RuntimeDependencyGenerationCustody, SignedAdmissionReceiptSet,
};

use super::RuntimeError;

impl From<DependencyCustodyError> for RuntimeError {
    #[allow(clippy::too_many_lines)] // Exhaustive one-to-one mapping is intentionally auditable.
    fn from(error: DependencyCustodyError) -> Self {
        match error {
            DependencyCustodyError::Contract(error) => Self::Contract(error),
            DependencyCustodyError::Json(error) => Self::Json(error),
            DependencyCustodyError::Canonicalization(error) => Self::Canonicalization(error),
            DependencyCustodyError::NonCanonicalExternalDependencySnapshot => {
                Self::NonCanonicalExternalDependencySnapshot
            }
            DependencyCustodyError::UnknownExternalDependencySnapshotSchema(schema) => {
                Self::UnknownExternalDependencySnapshotSchema(schema)
            }
            DependencyCustodyError::ExternalDependencySnapshotNotCanonical => {
                Self::ExternalDependencySnapshotNotCanonical
            }
            DependencyCustodyError::NonCanonicalAuthorityAdmissionSnapshot => {
                Self::NonCanonicalAuthorityAdmissionSnapshot
            }
            DependencyCustodyError::UnknownAuthorityAdmissionSnapshotSchema(schema) => {
                Self::UnknownAuthorityAdmissionSnapshotSchema(schema)
            }
            DependencyCustodyError::AuthorityAdmissionSnapshotNotCanonical => {
                Self::AuthorityAdmissionSnapshotNotCanonical
            }
            DependencyCustodyError::MaterializedRuntimeRecordOffLedger(schema) => {
                Self::MaterializedRuntimeRecordOffLedger(schema)
            }
            DependencyCustodyError::ProviderIntakeOffLedger => Self::ProviderIntakeOffLedger,
            DependencyCustodyError::ExternalDependencyBytesMalformed => {
                Self::ExternalDependencyBytesMalformed
            }
            DependencyCustodyError::ExternalDependencyAvailabilityMismatch => {
                Self::ExternalDependencyAvailabilityMismatch
            }
            DependencyCustodyError::ExternalDependencyByteSubstitution(record_id) => {
                Self::ExternalDependencyByteSubstitution(record_id)
            }
            DependencyCustodyError::ExternalDependencyReceiptReplay => {
                Self::ExternalDependencyReceiptReplay
            }
            DependencyCustodyError::ExternalDependencyMissing(record_id) => {
                Self::ExternalDependencyMissing(record_id)
            }
            DependencyCustodyError::ExternalDependencyUnavailable(record_id) => {
                Self::ExternalDependencyUnavailable(record_id)
            }
            DependencyCustodyError::AuthorityAdmissionKindMismatch => {
                Self::AuthorityAdmissionKindMismatch
            }
            DependencyCustodyError::AuthorityAdmissionReceiptReplay => {
                Self::AuthorityAdmissionReceiptReplay
            }
            DependencyCustodyError::AuthorityRecordNotAdmitted(record_id) => {
                Self::AuthorityRecordNotAdmitted(record_id)
            }
            DependencyCustodyError::AuthenticationEvidenceNotAdmitted(record_id) => {
                Self::AuthenticationEvidenceNotAdmitted(record_id)
            }
            DependencyCustodyError::NonCanonicalDependencyTrustAnchor => {
                Self::NonCanonicalDependencyTrustAnchor
            }
            DependencyCustodyError::UnknownDependencyTrustAnchorSchema(schema) => {
                Self::UnknownDependencyTrustAnchorSchema(schema)
            }
            DependencyCustodyError::DependencyTrustAnchorPublicKeyMalformed => {
                Self::DependencyTrustAnchorPublicKeyMalformed
            }
            DependencyCustodyError::DependencyTrustAnchorSubstitution { expected, observed } => {
                Self::DependencyTrustAnchorSubstitution { expected, observed }
            }
            DependencyCustodyError::NonCanonicalAdmissionReceiptSet => {
                Self::NonCanonicalAdmissionReceiptSet
            }
            DependencyCustodyError::UnknownAdmissionReceiptSetSchema(schema) => {
                Self::UnknownAdmissionReceiptSetSchema(schema)
            }
            DependencyCustodyError::AdmissionReceiptSetNotCanonical => {
                Self::AdmissionReceiptSetNotCanonical
            }
            DependencyCustodyError::AdmissionReceiptReplay => Self::AdmissionReceiptReplay,
            DependencyCustodyError::AdmissionReceiptSetUnavailable => {
                Self::AdmissionReceiptSetUnavailable
            }
            DependencyCustodyError::AdmissionReceiptSetAvailabilityMismatch => {
                Self::AdmissionReceiptSetAvailabilityMismatch
            }
            DependencyCustodyError::AdmissionReceiptSetByteSubstitution => {
                Self::AdmissionReceiptSetByteSubstitution
            }
            DependencyCustodyError::AdmissionReceiptSetSignatureMalformed => {
                Self::AdmissionReceiptSetSignatureMalformed
            }
            DependencyCustodyError::AdmissionReceiptSetSignatureInvalid => {
                Self::AdmissionReceiptSetSignatureInvalid
            }
            DependencyCustodyError::AdmissionReceiptSetBindingMismatch => {
                Self::AdmissionReceiptSetBindingMismatch
            }
            DependencyCustodyError::DependencyAdmissionReceiptMissing => {
                Self::DependencyAdmissionReceiptMissing
            }
            DependencyCustodyError::DependencyAdmissionReceiptSubstitution => {
                Self::DependencyAdmissionReceiptSubstitution
            }
            DependencyCustodyError::ExtraneousDependencyAdmissionReceipt => {
                Self::ExtraneousDependencyAdmissionReceipt
            }
            DependencyCustodyError::NonCanonicalRuntimeDependencyGeneration => {
                Self::NonCanonicalRuntimeDependencyGeneration
            }
            DependencyCustodyError::NonCanonicalRuntimeDependencyGenerationCustody => {
                Self::NonCanonicalRuntimeDependencyGenerationCustody
            }
            DependencyCustodyError::UnknownRuntimeDependencyGenerationCustodySchema(schema) => {
                Self::UnknownRuntimeDependencyGenerationCustodySchema(schema)
            }
            DependencyCustodyError::RuntimeDependencyGenerationCustodyMalformed => {
                Self::RuntimeDependencyGenerationCustodyMalformed
            }
            DependencyCustodyError::UnknownRuntimeDependencyGenerationSchema(schema) => {
                Self::UnknownRuntimeDependencyGenerationSchema(schema)
            }
            DependencyCustodyError::RuntimeDependencyGenerationSubstitution => {
                Self::RuntimeDependencyGenerationSubstitution
            }
            DependencyCustodyError::CustodyBindingLengthZero => Self::CustodyBindingLengthZero,
            DependencyCustodyError::CustodyLengthOverflow => Self::CustodyLengthOverflow,
            DependencyCustodyError::CustodyLengthMismatch { expected, observed } => {
                Self::CustodyLengthMismatch { expected, observed }
            }
            DependencyCustodyError::CustodyDigestMismatch { expected, observed } => {
                Self::CustodyDigestMismatch { expected, observed }
            }
            DependencyCustodyError::ExternalSourceRequirementInvalid => {
                Self::ExternalSourceRequirementInvalid
            }
            DependencyCustodyError::AuthoritySourceRequirementInvalid => {
                Self::AuthoritySourceRequirementInvalid
            }
            DependencyCustodyError::DuplicateExternalSourceRequirement => {
                Self::DuplicateExternalSourceRequirement
            }
            DependencyCustodyError::DuplicateAuthoritySourceRequirement => {
                Self::DuplicateAuthoritySourceRequirement
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use nq_protocol::{CanonicalizationError, sha256_bytes};

    use super::*;

    pub(crate) use nq_host_role_dependency_custody::test_support::authenticated_runtime_fixture;

    macro_rules! assert_maps {
        ($source:expr, $pattern:pat $(if $guard:expr)?) => {
            assert!(
                matches!(RuntimeError::from($source), $pattern $(if $guard)?),
                "dependency-custody refusal mapping changed"
            );
        };
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_dependency_custody_refusal_maps_without_class_flattening() {
        assert_maps!(
            DependencyCustodyError::Contract(
                nq_host_role_contract::ContractError::RecordMustBeObject
            ),
            RuntimeError::Contract(nq_host_role_contract::ContractError::RecordMustBeObject)
        );
        assert_maps!(
            DependencyCustodyError::Json(
                serde_json::from_slice::<serde_json::Value>(b"{").expect_err("invalid JSON")
            ),
            RuntimeError::Json(_)
        );
        assert_maps!(
            DependencyCustodyError::Canonicalization(CanonicalizationError::UnsafeInteger(
                "9007199254740992".to_owned()
            )),
            RuntimeError::Canonicalization(CanonicalizationError::UnsafeInteger(value))
                if value == "9007199254740992"
        );
        assert_maps!(
            DependencyCustodyError::NonCanonicalExternalDependencySnapshot,
            RuntimeError::NonCanonicalExternalDependencySnapshot
        );
        assert_maps!(
            DependencyCustodyError::UnknownExternalDependencySnapshotSchema("schema".to_owned()),
            RuntimeError::UnknownExternalDependencySnapshotSchema(schema) if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencySnapshotNotCanonical,
            RuntimeError::ExternalDependencySnapshotNotCanonical
        );
        assert_maps!(
            DependencyCustodyError::NonCanonicalAuthorityAdmissionSnapshot,
            RuntimeError::NonCanonicalAuthorityAdmissionSnapshot
        );
        assert_maps!(
            DependencyCustodyError::UnknownAuthorityAdmissionSnapshotSchema("schema".to_owned()),
            RuntimeError::UnknownAuthorityAdmissionSnapshotSchema(schema) if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::AuthorityAdmissionSnapshotNotCanonical,
            RuntimeError::AuthorityAdmissionSnapshotNotCanonical
        );
        assert_maps!(
            DependencyCustodyError::MaterializedRuntimeRecordOffLedger("schema".to_owned()),
            RuntimeError::MaterializedRuntimeRecordOffLedger(schema) if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::ProviderIntakeOffLedger,
            RuntimeError::ProviderIntakeOffLedger
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencyBytesMalformed,
            RuntimeError::ExternalDependencyBytesMalformed
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencyAvailabilityMismatch,
            RuntimeError::ExternalDependencyAvailabilityMismatch
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencyByteSubstitution("record".to_owned()),
            RuntimeError::ExternalDependencyByteSubstitution(record) if record == "record"
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencyReceiptReplay,
            RuntimeError::ExternalDependencyReceiptReplay
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencyMissing("record".to_owned()),
            RuntimeError::ExternalDependencyMissing(record) if record == "record"
        );
        assert_maps!(
            DependencyCustodyError::ExternalDependencyUnavailable("record".to_owned()),
            RuntimeError::ExternalDependencyUnavailable(record) if record == "record"
        );
        assert_maps!(
            DependencyCustodyError::AuthorityAdmissionKindMismatch,
            RuntimeError::AuthorityAdmissionKindMismatch
        );
        assert_maps!(
            DependencyCustodyError::AuthorityAdmissionReceiptReplay,
            RuntimeError::AuthorityAdmissionReceiptReplay
        );
        assert_maps!(
            DependencyCustodyError::AuthorityRecordNotAdmitted("record".to_owned()),
            RuntimeError::AuthorityRecordNotAdmitted(record) if record == "record"
        );
        assert_maps!(
            DependencyCustodyError::AuthenticationEvidenceNotAdmitted("record".to_owned()),
            RuntimeError::AuthenticationEvidenceNotAdmitted(record) if record == "record"
        );
        assert_maps!(
            DependencyCustodyError::NonCanonicalDependencyTrustAnchor,
            RuntimeError::NonCanonicalDependencyTrustAnchor
        );
        assert_maps!(
            DependencyCustodyError::UnknownDependencyTrustAnchorSchema("schema".to_owned()),
            RuntimeError::UnknownDependencyTrustAnchorSchema(schema) if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::DependencyTrustAnchorPublicKeyMalformed,
            RuntimeError::DependencyTrustAnchorPublicKeyMalformed
        );
        let expected = sha256_bytes(b"expected");
        let observed = sha256_bytes(b"observed");
        assert_maps!(
            DependencyCustodyError::DependencyTrustAnchorSubstitution {
                expected: expected.clone(),
                observed: observed.clone(),
            },
            RuntimeError::DependencyTrustAnchorSubstitution {
                expected: mapped_expected,
                observed: mapped_observed,
            } if mapped_expected == expected && mapped_observed == observed
        );
        assert_maps!(
            DependencyCustodyError::NonCanonicalAdmissionReceiptSet,
            RuntimeError::NonCanonicalAdmissionReceiptSet
        );
        assert_maps!(
            DependencyCustodyError::UnknownAdmissionReceiptSetSchema("schema".to_owned()),
            RuntimeError::UnknownAdmissionReceiptSetSchema(schema) if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetNotCanonical,
            RuntimeError::AdmissionReceiptSetNotCanonical
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptReplay,
            RuntimeError::AdmissionReceiptReplay
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetUnavailable,
            RuntimeError::AdmissionReceiptSetUnavailable
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetAvailabilityMismatch,
            RuntimeError::AdmissionReceiptSetAvailabilityMismatch
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetByteSubstitution,
            RuntimeError::AdmissionReceiptSetByteSubstitution
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetSignatureMalformed,
            RuntimeError::AdmissionReceiptSetSignatureMalformed
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetSignatureInvalid,
            RuntimeError::AdmissionReceiptSetSignatureInvalid
        );
        assert_maps!(
            DependencyCustodyError::AdmissionReceiptSetBindingMismatch,
            RuntimeError::AdmissionReceiptSetBindingMismatch
        );
        assert_maps!(
            DependencyCustodyError::DependencyAdmissionReceiptMissing,
            RuntimeError::DependencyAdmissionReceiptMissing
        );
        assert_maps!(
            DependencyCustodyError::DependencyAdmissionReceiptSubstitution,
            RuntimeError::DependencyAdmissionReceiptSubstitution
        );
        assert_maps!(
            DependencyCustodyError::ExtraneousDependencyAdmissionReceipt,
            RuntimeError::ExtraneousDependencyAdmissionReceipt
        );
        assert_maps!(
            DependencyCustodyError::NonCanonicalRuntimeDependencyGeneration,
            RuntimeError::NonCanonicalRuntimeDependencyGeneration
        );
        assert_maps!(
            DependencyCustodyError::NonCanonicalRuntimeDependencyGenerationCustody,
            RuntimeError::NonCanonicalRuntimeDependencyGenerationCustody
        );
        assert_maps!(
            DependencyCustodyError::UnknownRuntimeDependencyGenerationCustodySchema(
                "schema".to_owned()
            ),
            RuntimeError::UnknownRuntimeDependencyGenerationCustodySchema(schema)
                if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::RuntimeDependencyGenerationCustodyMalformed,
            RuntimeError::RuntimeDependencyGenerationCustodyMalformed
        );
        assert_maps!(
            DependencyCustodyError::UnknownRuntimeDependencyGenerationSchema("schema".to_owned()),
            RuntimeError::UnknownRuntimeDependencyGenerationSchema(schema) if schema == "schema"
        );
        assert_maps!(
            DependencyCustodyError::RuntimeDependencyGenerationSubstitution,
            RuntimeError::RuntimeDependencyGenerationSubstitution
        );
        assert_maps!(
            DependencyCustodyError::CustodyBindingLengthZero,
            RuntimeError::CustodyBindingLengthZero
        );
        assert_maps!(
            DependencyCustodyError::CustodyLengthOverflow,
            RuntimeError::CustodyLengthOverflow
        );
        assert_maps!(
            DependencyCustodyError::CustodyLengthMismatch {
                expected: 17,
                observed: 19,
            },
            RuntimeError::CustodyLengthMismatch {
                expected: 17,
                observed: 19
            }
        );
        let expected = sha256_bytes(b"expected custody");
        let observed = sha256_bytes(b"observed custody");
        assert_maps!(
            DependencyCustodyError::CustodyDigestMismatch {
                expected: expected.clone(),
                observed: observed.clone(),
            },
            RuntimeError::CustodyDigestMismatch {
                expected: mapped_expected,
                observed: mapped_observed,
            } if mapped_expected == expected && mapped_observed == observed
        );
        assert_maps!(
            DependencyCustodyError::ExternalSourceRequirementInvalid,
            RuntimeError::ExternalSourceRequirementInvalid
        );
        assert_maps!(
            DependencyCustodyError::AuthoritySourceRequirementInvalid,
            RuntimeError::AuthoritySourceRequirementInvalid
        );
        assert_maps!(
            DependencyCustodyError::DuplicateExternalSourceRequirement,
            RuntimeError::DuplicateExternalSourceRequirement
        );
        assert_maps!(
            DependencyCustodyError::DuplicateAuthoritySourceRequirement,
            RuntimeError::DuplicateAuthoritySourceRequirement
        );
    }
}
