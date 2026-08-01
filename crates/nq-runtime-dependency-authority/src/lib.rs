//! Pure C1 Gen4 runtime-dependency authority evidence verification.
//!
//! This crate owns strict native A1, A2, revocation, and migration carriers;
//! Ed25519 verification; content-chain resolution; Store-independent
//! candidate bindings; and sealed generatively branded establishment evidence.
//! It deliberately has no dependency on `nq-store`, host-role runtime, or the
//! pinned dependency-custody resolver.  Store enumeration remains the sole
//! completeness testimony.

mod brand;
mod error;
mod framing;
mod records;
mod resolution;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use brand::{
    ControllingActivationSnapshot, ResolvedControllingActivation, VerificationBrand,
    VerifiedActivationRevocation, VerifiedOperatorAuthorityRotation,
    VerifiedResidentActivationSuccessor, with_verification_brand,
};
pub use error::AuthorityError;
pub use records::{
    ACTIVATION_REVOCATION_SCHEMA, AUTHORITY_POLICY_VERSION, AUTHORITY_SCHEMA_VERSION,
    ActivationContext, ActivationExpectations, ActivationRevocationRecord, AuthorityCut,
    ED25519_SIGNATURE_ALGORITHM, ESTABLISHMENT_RECEIPT_SCHEMA, EstablishmentArm,
    EstablishmentReceiptTranscript, GenesisAuthorityCustody, MIGRATION_RECEIPT_SCHEMA,
    MigrationDisposition, MigrationExpectations, MigrationReceipt, MigrationReceiptBytes,
    OPERATOR_AUTHORITY_SCHEMA, OldRootState, OperatorAuthorityRecord, PresentedAuthorityRecord,
    PresentedAuthoritySet, RESIDENT_ACTIVATION_SCHEMA, RUNTIME_DEPENDENCY_ADMISSION_SCOPE,
    ResidentActivationRecord, RestartExpectations, digest_genesis_authority_custody,
    digest_presented_authority_set,
};
pub use resolution::{
    resolve_for_restart, verify_activation_revocation, verify_for_establishment,
    verify_operator_authority_rotation, verify_resident_activation_successor,
};
