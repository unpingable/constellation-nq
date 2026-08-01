//! Typed refusal results for runtime-dependency authority verification.

use thiserror::Error;

/// Every semantic refusal emitted by the bounded authority verifier.
///
/// Variants deliberately preserve the failed law instead of flattening
/// failures into a generic signature or validation error.  The Store and
/// runtime layers can therefore retain the same refusal distinction without
/// parsing error text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthorityError {
    /// A framed transcript exceeded the representable length limit.
    #[error("authority transcript exceeds the length-framing limit")]
    FramingOverflow,

    /// The custody-carried A1 bytes were not a decodable A1 record.
    #[error("custody A1 record is malformed")]
    A1Malformed,
    /// A decoded A1 record was not exact canonical JSON.
    #[error("A1 record bytes are not exact canonical JSON")]
    A1NonCanonical,
    /// The A1 schema identifier is unknown.
    #[error("A1 schema is unsupported")]
    A1SchemaUnsupported,
    /// The A1 schema version is unknown.
    #[error("A1 schema version is unsupported")]
    A1VersionUnsupported,
    /// An A1 asserted digest did not match its framed canonical payload.
    #[error("A1 record digest does not match its canonical payload")]
    A1DigestMismatch,
    /// An A1 Ed25519 verification key was malformed.
    #[error("A1 Ed25519 verification key is malformed")]
    A1VerificationKeyMalformed,
    /// An A1 named an unsupported signature algorithm.
    #[error("A1 signature algorithm is unsupported")]
    A1SignatureAlgorithmUnsupported,
    /// An A1 rotation signature was malformed.
    #[error("A1 rotation signature is malformed")]
    A1SignatureMalformed,
    /// An A1 rotation signature did not verify under its predecessor.
    #[error("A1 rotation signature is invalid")]
    A1SignatureInvalid,
    /// The custody A1 was not a genesis A1.
    #[error("custody A1 unexpectedly names a predecessor or signature")]
    A1GenesisShapeMismatch,
    /// A Store-resident A1 attempted to introduce another genesis.
    #[error("post-genesis A1 is missing its predecessor or signature")]
    A1RotationShapeMismatch,
    /// An A1 rotation names a predecessor absent from the presented set.
    #[error("A1 predecessor chain has a gap")]
    A1Gap,
    /// More than one A1 rotation names the same predecessor.
    #[error("A1 predecessor chain forks")]
    A1Fork,
    /// The A1 predecessor graph contains a cycle.
    #[error("A1 predecessor chain contains a cycle")]
    A1Cycle,
    /// An A1 record identity was duplicated.
    #[error("A1 record identity is duplicated")]
    A1DuplicateIdentity,
    /// An A1 rotation changed operator principal identity.
    #[error("A1 rotation changes operator principal identity")]
    A1PrincipalMismatch,
    /// An A1 rotation did not advance the key generation exactly.
    #[error("A1 key-generation chain has a gap or rollback")]
    A1KeyGenerationMismatch,
    /// An A1 cut did not follow its predecessor at a strictly later value.
    #[error("A1 rotation cut is not strictly later than its predecessor")]
    A1CutNotLater,

    /// The custody-carried A2 bytes were not a decodable activation record.
    #[error("custody A2 record is malformed")]
    A2Malformed,
    /// A decoded A2 record was not exact canonical JSON.
    #[error("A2 record bytes are not exact canonical JSON")]
    A2NonCanonical,
    /// The A2 schema identifier is unknown.
    #[error("A2 schema is unsupported")]
    A2SchemaUnsupported,
    /// The A2 schema version is unknown.
    #[error("A2 schema version is unsupported")]
    A2VersionUnsupported,
    /// An A2 asserted digest did not match its framed canonical payload.
    #[error("A2 activation digest does not match its canonical payload")]
    A2DigestMismatch,
    /// An A2 named an unsupported signature algorithm.
    #[error("A2 signature algorithm is unsupported")]
    A2SignatureAlgorithmUnsupported,
    /// An A2 operator signature was malformed.
    #[error("A2 operator signature is malformed")]
    A2SignatureMalformed,
    /// An A2 operator signature did not verify under its named A1 generation.
    #[error("A2 operator signature is invalid")]
    A2SignatureInvalid,
    /// The custody A2 context or predecessor shape is not a lawful chain root.
    #[error("custody A2 establishment context or predecessor shape is invalid")]
    A2GenesisShapeMismatch,
    /// A Store-resident A2 is not a properly linked successor.
    #[error("post-genesis A2 is not a properly linked successor")]
    A2SuccessorShapeMismatch,
    /// An A2 record identity was duplicated.
    #[error("A2 activation identity is duplicated")]
    A2DuplicateIdentity,
    /// An A2 names an absent predecessor activation.
    #[error("A2 activation chain has a gap")]
    ActivationGap,
    /// More than one A2 names the same predecessor activation.
    #[error("A2 activation chain forks")]
    ActivationFork,
    /// The A2 predecessor graph contains a cycle.
    #[error("A2 activation chain contains a cycle")]
    ActivationCycle,
    /// The live-tip calculation produced no activation.
    #[error("authority resolution has no lawful live activation tip")]
    NoLiveActivation,
    /// The live-tip calculation produced more than one activation.
    #[error("authority resolution has multiple lawful live activation tips")]
    MultipleLiveActivations,
    /// The structurally controlling activation was prospectively revoked.
    #[error("the controlling activation tip is revoked")]
    ControllingActivationRevoked,
    /// The structurally controlling activation expired at the resolution cut.
    #[error("the controlling activation tip is expired at the authority cut")]
    ControllingActivationExpired,
    /// An expiry cut is not strictly later than the activation it limits.
    #[error("activation expiry cut is not strictly later than its activation cut")]
    ExpiryCutInvalid,

    /// Revocation bytes were not a decodable revocation record.
    #[error("revocation record is malformed")]
    RevocationMalformed,
    /// A decoded revocation was not exact canonical JSON.
    #[error("revocation record bytes are not exact canonical JSON")]
    RevocationNonCanonical,
    /// The revocation schema identifier is unknown.
    #[error("revocation schema is unsupported")]
    RevocationSchemaUnsupported,
    /// The revocation schema version is unknown.
    #[error("revocation schema version is unsupported")]
    RevocationVersionUnsupported,
    /// A revocation asserted digest did not match its framed payload.
    #[error("revocation digest does not match its canonical payload")]
    RevocationDigestMismatch,
    /// A revocation names an unsupported signature algorithm.
    #[error("revocation signature algorithm is unsupported")]
    RevocationSignatureAlgorithmUnsupported,
    /// A revocation signature was malformed.
    #[error("revocation signature is malformed")]
    RevocationSignatureMalformed,
    /// A revocation signature did not verify under its named A1 generation.
    #[error("revocation signature is invalid")]
    RevocationSignatureInvalid,
    /// A revocation targets an activation absent from the presented set.
    #[error("revocation target activation is absent")]
    RevocationTargetMissing,
    /// A revocation is not prospective relative to its target activation.
    #[error("revocation cut is not strictly later than its target activation")]
    RevocationNotProspective,

    /// Migration-receipt bytes were not decodable.
    #[error("migration receipt is malformed")]
    MigrationReceiptMalformed,
    /// A decoded migration receipt was not exact canonical JSON.
    #[error("migration receipt bytes are not exact canonical JSON")]
    MigrationReceiptNonCanonical,
    /// The migration receipt schema identifier is unknown.
    #[error("migration receipt schema is unsupported")]
    MigrationReceiptSchemaUnsupported,
    /// The migration receipt schema version is unknown.
    #[error("migration receipt schema version is unsupported")]
    MigrationReceiptVersionUnsupported,
    /// A migration receipt asserted digest did not match its framed payload.
    #[error("migration receipt digest does not match its canonical payload")]
    MigrationReceiptDigestMismatch,
    /// A migration receipt named an unsupported signature algorithm.
    #[error("migration receipt signature algorithm is unsupported")]
    MigrationReceiptSignatureAlgorithmUnsupported,
    /// A migration receipt signature was malformed.
    #[error("migration receipt signature is malformed")]
    MigrationReceiptSignatureMalformed,
    /// A migration receipt signature did not verify under its named A1.
    #[error("migration receipt signature is invalid")]
    MigrationReceiptSignatureInvalid,
    /// Migration evidence is required but absent.
    #[error("migration establishment requires an exact migration receipt")]
    MigrationReceiptRequired,
    /// A non-migration activation carried a migration receipt.
    #[error("migration receipt is present for a non-migration activation")]
    UnexpectedMigrationReceipt,
    /// A migration receipt does not name the exact chain-root activation.
    #[error("migration receipt names another chain-root activation")]
    MigrationActivationMismatch,
    /// The migration old-root state differs from the Store expectation.
    #[error("migration receipt old-root state differs from the expected Store state")]
    MigrationOldRootMismatch,
    /// The migration disposition is not accepted for establishment.
    #[error("migration disposition does not authorize establishment")]
    MigrationDispositionMismatch,
    /// A declared restore proof is absent or differs.
    #[error("migration restore-proof binding differs from the declared restore")]
    RestoreProofMismatch,

    /// Store-side establishment receipt transcript bytes were malformed.
    #[error("establishment receipt transcript is malformed")]
    EstablishmentReceiptMalformed,
    /// Store-side establishment receipt transcript bytes were not canonical.
    #[error("establishment receipt transcript is not exact canonical JSON")]
    EstablishmentReceiptNonCanonical,
    /// Store-side establishment receipt transcript named an unknown schema.
    #[error("establishment receipt transcript schema is unsupported")]
    EstablishmentReceiptSchemaUnsupported,
    /// Store-side establishment receipt transcript named an unknown version.
    #[error("establishment receipt transcript version is unsupported")]
    EstablishmentReceiptVersionUnsupported,
    /// Receipt arm and migration-receipt presence disagree.
    #[error("establishment receipt arm disagrees with migration-receipt binding")]
    EstablishmentReceiptArmMismatch,

    /// A record carried an empty or structurally invalid identity field.
    #[error("authority identity field is empty or exceeds its bounded length")]
    IdentityMalformed,
    /// A record used a policy version unknown to this implementation.
    #[error("authority policy version is unsupported")]
    PolicyVersionUnsupported,
    /// A record's policy is below the controlling floor.
    #[error("authority policy is below the controlling policy floor")]
    PolicyBelowFloor,
    /// A policy floor exceeds its containing policy version or rolls back.
    #[error("authority policy floor is inconsistent")]
    PolicyFloorMismatch,
    /// The authority domain differs from the bounded expectation.
    #[error("authority domain differs from the expected runtime/backend domain")]
    DomainMismatch,
    /// A record widened or changed the closed activation scope.
    #[error("authority scope is not exactly runtime_dependency_admission")]
    ScopeMismatch,
    /// The Store occurrence differs from the signed chain-root occurrence.
    #[error("authority Store occurrence differs")]
    OccurrenceMismatch,
    /// The custody A2 does not match the receipt-pinned activation chain root.
    #[error("authority chain root differs from the retained establishment receipt")]
    ChainRootMismatch,
    /// The receipt's historical establishment tip is absent from the chain.
    #[error("historical establishment-time tip is absent from the activation chain")]
    EstablishmentTipMismatch,
    /// Current external genesis custody differs from the receipt-bound custody.
    #[error("genesis authority custody differs from the retained receipt binding")]
    CustodyDigestMismatch,
    /// The immutable trust anchor differs within the occurrence.
    #[error("authority trust anchor differs within the Store occurrence")]
    AnchorMismatch,
    /// The resident identity differs from the bounded expectation.
    #[error("activation resident identity differs")]
    ResidentMismatch,
    /// The resident generation differs from the bounded expectation.
    #[error("activation resident generation differs")]
    ResidentGenerationMismatch,
    /// The host role differs from the bounded expectation.
    #[error("activation host role differs")]
    RoleMismatch,
    /// The role-manifest generation differs from the bounded expectation.
    #[error("activation role-manifest generation differs")]
    RoleManifestGenerationMismatch,
    /// A record names an A1 identity absent from the verified A1 chain.
    #[error("authority record names an unknown A1 identity")]
    A1IdentityMismatch,
    /// A record's named key generation differs from the named A1 record.
    #[error("authority record names the wrong A1 key generation")]
    A1GenerationMismatch,
    /// A record was signed by an A1 that was not yet established at its cut.
    #[error("authority record names a future A1 generation")]
    A1NotYetEffective,

    /// An authority-event digest was duplicated across native families.
    #[error("authority-event identity is duplicated")]
    AuthorityEventDuplicateIdentity,
    /// Two authority events carry the same authority cut.
    #[error("authority-event cut collision")]
    AuthorityCutCollision,
    /// An authority-event predecessor is absent.
    #[error("authority-event chain has a gap")]
    AuthorityEventGap,
    /// More than one authority event names the same predecessor.
    #[error("authority-event chain forks")]
    AuthorityEventFork,
    /// The authority-event graph contains a cycle.
    #[error("authority-event chain contains a cycle")]
    AuthorityEventCycle,
    /// An authority-event cut did not increase over its exact predecessor.
    #[error("authority-event cut is not strictly increasing")]
    AuthorityCutNotLater,
}
