//! Strict native authority record carriers.

use nq_protocol::{Sha256Digest, canonical_json_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{AuthorityError, framing::framed_bytes, framing::framed_digest};

/// The only authority scope recognized by C1 Gen4.
pub const RUNTIME_DEPENDENCY_ADMISSION_SCOPE: &str = "runtime_dependency_admission";
/// Canonical Ed25519 algorithm identifier used by every signed native record.
pub const ED25519_SIGNATURE_ALGORITHM: &str = "ed25519";
/// Native operator-authority record schema.
pub const OPERATOR_AUTHORITY_SCHEMA: &str = "nq.runtime_dependency_operator_authority.v1";
/// Native resident-activation record schema.
pub const RESIDENT_ACTIVATION_SCHEMA: &str = "nq.runtime_dependency_resident_activation.v1";
/// Native activation-revocation record schema.
pub const ACTIVATION_REVOCATION_SCHEMA: &str = "nq.runtime_dependency_activation_revocation.v1";
/// Native migration-receipt schema.
pub const MIGRATION_RECEIPT_SCHEMA: &str = "nq.runtime_dependency_migration_receipt.v1";
/// The sole native schema version supported by this implementation.
pub const AUTHORITY_SCHEMA_VERSION: u16 = 1;
/// The sole governing policy version supported by this implementation.
pub const AUTHORITY_POLICY_VERSION: u64 = 1;

const MAX_RECORD_BYTES: usize = 1_048_576;
pub(crate) const MAX_IDENTITY_BYTES: usize = 1_024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

const A1_ID_DOMAIN: &str = "nq.runtime_dependency_authority.a1.identity.v1";
const A1_SIGNATURE_DOMAIN: &str = "nq.runtime_dependency_authority.a1.rotation_signature.v1";
const A2_ID_DOMAIN: &str = "nq.runtime_dependency_authority.a2.identity.v1";
const A2_SIGNATURE_DOMAIN: &str = "nq.runtime_dependency_authority.a2.signature.v1";
const REVOCATION_ID_DOMAIN: &str = "nq.runtime_dependency_authority.revocation.identity.v1";
const REVOCATION_SIGNATURE_DOMAIN: &str = "nq.runtime_dependency_authority.revocation.signature.v1";
const MIGRATION_ID_DOMAIN: &str = "nq.runtime_dependency_authority.migration.identity.v1";
const MIGRATION_SIGNATURE_DOMAIN: &str = "nq.runtime_dependency_authority.migration.signature.v1";
const PRESENTED_SET_DOMAIN: &str = "nq.runtime_dependency_authority.presented_set.v1";
const PRESENTED_ITEM_DOMAIN: &str = "nq.runtime_dependency_authority.presented_item.v1";
const CUSTODY_DIGEST_DOMAIN: &str = "nq.runtime_dependency_authority.genesis_custody.v1";
const ESTABLISHMENT_RECEIPT_ID_DOMAIN: &str =
    "nq.runtime_dependency_authority.establishment_receipt.identity.v1";
/// Canonical Store-side establishment receipt transcript schema.
pub const ESTABLISHMENT_RECEIPT_SCHEMA: &str =
    "nq.runtime_dependency_authority.establishment_receipt.v1";

/// One operator-signed, content-chained authority ordering value.
///
/// `sequence` is an authority ordinal, not a timestamp.  Its predecessor is
/// an exact native record digest and therefore makes ordering part of the
/// signed record content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCut {
    sequence: u64,
    predecessor_event_digest: Option<Sha256Digest>,
}

impl AuthorityCut {
    /// Returns the signed authority ordinal.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact preceding native authority-event digest.
    #[must_use]
    pub const fn predecessor_event_digest(&self) -> Option<&Sha256Digest> {
        self.predecessor_event_digest.as_ref()
    }

    pub(crate) fn validate_integer(&self) -> Result<(), AuthorityError> {
        if self.sequence > MAX_SAFE_JSON_INTEGER {
            return Err(AuthorityError::AuthorityCutNotLater);
        }
        Ok(())
    }
}

/// Position and establishment context of an A2 activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationContext {
    /// Chain root for a newly created Store occurrence.
    FreshGenesis,
    /// Chain root attributed through an accepted migration receipt.
    MigrationGenesis,
    /// Store-ledger-resident replacement on the same immutable anchor.
    Successor,
}

/// Closed migration disposition enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDisposition {
    /// Exact state retained and evidence-frozen without a validity claim.
    Observed,
    /// Exact state accepted for the bounded migration transaction.
    Accepted,
    /// Predecessor evidence-frozen in favor of a separate occurrence.
    Superseded,
    /// Exact state evidence-frozen with no in-occurrence reactivation.
    Refused,
}

/// Store-side establishment arm recorded in the immutable receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstablishmentArm {
    /// Fresh occurrence whose sole genesis is the signed A2 occurrence.
    Genesis,
    /// Existing occurrence admitted by an exact accepted migration receipt.
    Migration,
}

/// Exact prior trust-root state named by a migration receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OldRootState {
    /// The Store already has this exact immutable root digest.
    Rooted {
        /// Exact existing trust-anchor identity.
        trust_anchor_id: Sha256Digest,
    },
    /// The Store has no prior root; this is an absence marker, not a digest.
    Rootless,
}

/// Exact custody bytes for the exogenous genesis A1 and chain-root A2.
#[derive(Debug)]
pub struct GenesisAuthorityCustody {
    genesis_a1: Vec<u8>,
    genesis_a2: Vec<u8>,
}

impl GenesisAuthorityCustody {
    /// Creates an unverified exact-byte custody input.
    #[must_use]
    pub fn new(genesis_a1: Vec<u8>, genesis_a2: Vec<u8>) -> Self {
        Self {
            genesis_a1,
            genesis_a2,
        }
    }

    /// Returns the exact custody-carried A1 bytes.
    #[must_use]
    pub fn genesis_a1_bytes(&self) -> &[u8] {
        &self.genesis_a1
    }

    /// Returns the exact custody-carried A2 bytes.
    #[must_use]
    pub fn genesis_a2_bytes(&self) -> &[u8] {
        &self.genesis_a2
    }
}

/// One unverified Store-enumerated post-genesis authority record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentedAuthorityRecord {
    /// Store-ledger A1 key rotation bytes.
    OperatorAuthorityRotation(Vec<u8>),
    /// Store-ledger A2 successor bytes.
    ResidentActivationSuccessor(Vec<u8>),
    /// Store-ledger activation-revocation bytes.
    ActivationRevocation(Vec<u8>),
}

impl PresentedAuthorityRecord {
    /// Returns the exact presented canonical carrier bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::OperatorAuthorityRotation(bytes)
            | Self::ResidentActivationSuccessor(bytes)
            | Self::ActivationRevocation(bytes) => bytes,
        }
    }

    pub(crate) const fn kind_label(&self) -> &'static str {
        match self {
            Self::OperatorAuthorityRotation(_) => "a1_rotation",
            Self::ResidentActivationSuccessor(_) => "a2_successor",
            Self::ActivationRevocation(_) => "revocation",
        }
    }
}

/// Complete, order-independent authority records presented by Store enumeration.
#[derive(Debug, Default)]
pub struct PresentedAuthoritySet {
    records: Vec<PresentedAuthorityRecord>,
}

impl PresentedAuthoritySet {
    /// Creates an unverified complete presented set.
    #[must_use]
    pub fn new(records: Vec<PresentedAuthorityRecord>) -> Self {
        Self { records }
    }

    /// Returns the presented post-genesis records. Input order carries no
    /// authority meaning; digesting and resolution canonicalize independently.
    #[must_use]
    pub fn records(&self) -> &[PresentedAuthorityRecord] {
        &self.records
    }
}

/// Unverified exact migration-receipt bytes.
#[derive(Debug)]
pub struct MigrationReceiptBytes(Vec<u8>);

impl MigrationReceiptBytes {
    /// Wraps exact migration-receipt bytes without claiming validity.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the exact receipt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Store-derived expectations for a migration-genesis verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationExpectations {
    /// Exact old rooted/rootless state observed by the Store.
    pub old_root_state: OldRootState,
    /// Exact restore-proof digest for a declared restore, otherwise absent.
    pub restore_proof_digest: Option<Sha256Digest>,
}

/// Non-authority correspondence inputs supplied by the Store/runtime layer.
///
/// These fields constrain verification; they do not mint standing.  Fresh
/// initialization leaves `expected_occurrence_id` absent because the signed
/// genesis A2 is the sole source of that identity.  Migration and restart
/// provide the exact existing occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationExpectations {
    /// Required chain-root context.
    pub genesis_context: ActivationContext,
    /// Store-derived occurrence when one already exists.
    pub expected_occurrence_id: Option<String>,
    /// Exact enrolled resident identity.
    pub resident_identity: String,
    /// Exact enrolled resident generation.
    pub resident_generation: u64,
    /// Exact host role.
    pub host_role: String,
    /// Exact host-role manifest generation.
    pub role_manifest_generation: u64,
    /// Exact immutable runtime dependency trust anchor.
    pub trust_anchor_id: Sha256Digest,
    /// Exact runtime/backend authority domain.
    pub domain: String,
    /// Minimum governing policy version accepted by the caller.
    pub policy_floor: u64,
    /// Store-derived migration correspondence, only for migration genesis.
    pub migration: Option<MigrationExpectations>,
}

/// Store-retained correspondence inputs for ordinary read-only restart.
///
/// Historical old-root and restore-proof facts are deliberately absent: they
/// are validated from the retained signed migration receipt rather than
/// restated by a caller after migration. The expected receipt digest comes
/// from the immutable Store establishment receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartExpectations {
    /// Historical chain-root context retained by the establishment receipt.
    pub genesis_context: ActivationContext,
    /// Exact Store occurrence retained by Store genesis and receipt.
    pub expected_occurrence_id: String,
    /// Exact receipt-pinned chain-root A2 digest.
    pub expected_chain_root_activation_digest: Sha256Digest,
    /// Historical controlling tip recorded at establishment.
    pub expected_establishment_tip_digest: Sha256Digest,
    /// Exact enrolled resident identity.
    pub resident_identity: String,
    /// Exact enrolled resident generation.
    pub resident_generation: u64,
    /// Exact host role.
    pub host_role: String,
    /// Exact host-role manifest generation.
    pub role_manifest_generation: u64,
    /// Exact immutable trust anchor from Store root and receipt.
    pub trust_anchor_id: Sha256Digest,
    /// Exact runtime/backend authority domain.
    pub domain: String,
    /// Minimum supported governing policy.
    pub policy_floor: u64,
    /// Exact external genesis custody binding retained by the receipt.
    pub expected_custody_digest: Sha256Digest,
    /// Retained migration receipt identity for migration, absent for genesis.
    pub expected_migration_receipt_digest: Option<Sha256Digest>,
}

/// Canonical, digest-checked A1 carrier.  Signature and chain standing are
/// established only by the resolver.
#[derive(Debug)]
pub struct OperatorAuthorityRecord {
    wire: OperatorAuthorityWire,
    canonical_bytes: Vec<u8>,
}

impl OperatorAuthorityRecord {
    /// Decodes exact canonical bytes and verifies the asserted record digest.
    ///
    /// # Errors
    ///
    /// Refuses malformed, noncanonical, unknown-version, or digest-mismatched
    /// A1 bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let wire: OperatorAuthorityWire = parse_exact(
            bytes,
            AuthorityError::A1Malformed,
            AuthorityError::A1NonCanonical,
        )?;
        if wire.schema != OPERATOR_AUTHORITY_SCHEMA {
            return Err(AuthorityError::A1SchemaUnsupported);
        }
        if wire.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(AuthorityError::A1VersionUnsupported);
        }
        let expected = a1_digest(&wire.unsigned())?;
        if wire.record_digest != expected {
            return Err(AuthorityError::A1DigestMismatch);
        }
        Ok(Self {
            wire,
            canonical_bytes: bytes.to_vec(),
        })
    }

    /// Returns the exact A1 record identity.
    #[must_use]
    pub const fn record_digest(&self) -> &Sha256Digest {
        &self.wire.record_digest
    }

    /// Returns the named operator principal.
    #[must_use]
    pub fn operator_principal(&self) -> &str {
        &self.wire.operator_principal
    }

    /// Returns the operator key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u64 {
        self.wire.key_generation
    }

    /// Returns the policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.wire.policy_version
    }

    /// Returns the policy floor asserted by this A1.
    #[must_use]
    pub const fn policy_floor(&self) -> u64 {
        self.wire.policy_floor
    }

    /// Returns the authority domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.wire.domain
    }

    /// Returns the closed permitted scope.
    #[must_use]
    pub fn permitted_scope(&self) -> &str {
        &self.wire.permitted_scope
    }

    /// Returns this A1's authority cut.
    #[must_use]
    pub const fn cut(&self) -> &AuthorityCut {
        &self.wire.cut
    }

    /// Returns the predecessor A1 digest, absent only for genesis.
    #[must_use]
    pub const fn predecessor_a1_digest(&self) -> Option<&Sha256Digest> {
        self.wire.predecessor_a1_digest.as_ref()
    }

    /// Returns the exact canonical carrier bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn verification_key_hex(&self) -> &str {
        &self.wire.ed25519_verification_key
    }

    pub(crate) fn signature_algorithm(&self) -> &str {
        &self.wire.signature_algorithm
    }

    pub(crate) fn predecessor_signature_hex(&self) -> Option<&str> {
        self.wire.predecessor_signature.as_deref()
    }

    pub(crate) fn rotation_signature_preimage(&self) -> Result<Vec<u8>, AuthorityError> {
        signature_preimage(
            A1_SIGNATURE_DOMAIN,
            self.record_digest(),
            &self.wire.unsigned(),
        )
    }
}

/// Canonical, digest-checked A2 carrier.  Signature and standing are
/// established only by the resolver.
#[derive(Debug)]
pub struct ResidentActivationRecord {
    wire: ResidentActivationWire,
    canonical_bytes: Vec<u8>,
}

impl ResidentActivationRecord {
    /// Decodes exact canonical bytes and verifies the asserted activation digest.
    ///
    /// # Errors
    ///
    /// Refuses malformed, noncanonical, unknown-version, or digest-mismatched
    /// A2 bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let wire: ResidentActivationWire = parse_exact(
            bytes,
            AuthorityError::A2Malformed,
            AuthorityError::A2NonCanonical,
        )?;
        if wire.schema != RESIDENT_ACTIVATION_SCHEMA {
            return Err(AuthorityError::A2SchemaUnsupported);
        }
        if wire.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(AuthorityError::A2VersionUnsupported);
        }
        let expected = a2_digest(&wire.unsigned())?;
        if wire.activation_digest != expected {
            return Err(AuthorityError::A2DigestMismatch);
        }
        Ok(Self {
            wire,
            canonical_bytes: bytes.to_vec(),
        })
    }

    /// Returns the exact activation identity.
    #[must_use]
    pub const fn activation_digest(&self) -> &Sha256Digest {
        &self.wire.activation_digest
    }

    /// Returns the signed chain position and establishment context.
    #[must_use]
    pub const fn context(&self) -> ActivationContext {
        self.wire.context
    }

    /// Returns the signed Store-occurrence identity.
    #[must_use]
    pub fn occurrence_id(&self) -> &str {
        &self.wire.occurrence_id
    }

    /// Returns the enrolled resident identity.
    #[must_use]
    pub fn resident_identity(&self) -> &str {
        &self.wire.resident_identity
    }

    /// Returns the enrolled resident generation.
    #[must_use]
    pub const fn resident_generation(&self) -> u64 {
        self.wire.resident_generation
    }

    /// Returns the exact host role.
    #[must_use]
    pub fn host_role(&self) -> &str {
        &self.wire.host_role
    }

    /// Returns the role-manifest generation.
    #[must_use]
    pub const fn role_manifest_generation(&self) -> u64 {
        self.wire.role_manifest_generation
    }

    /// Returns the exact immutable trust-anchor identity.
    #[must_use]
    pub const fn trust_anchor_id(&self) -> &Sha256Digest {
        &self.wire.trust_anchor_id
    }

    /// Returns the closed authority scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.wire.scope
    }

    /// Returns the runtime/backend domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.wire.domain
    }

    /// Returns the activation authority cut.
    #[must_use]
    pub const fn cut(&self) -> &AuthorityCut {
        &self.wire.cut
    }

    /// Returns the exact predecessor activation, absent only at chain root.
    #[must_use]
    pub const fn predecessor_activation_digest(&self) -> Option<&Sha256Digest> {
        self.wire.predecessor_activation_digest.as_ref()
    }

    /// Returns the optional authority-cut expiry boundary.
    #[must_use]
    pub const fn expiry_cut(&self) -> Option<u64> {
        self.wire.expiry_cut
    }

    /// Returns the governing policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.wire.policy_version
    }

    /// Returns the exact A1 record named by this activation.
    #[must_use]
    pub const fn operator_authority_digest(&self) -> &Sha256Digest {
        &self.wire.operator_authority_digest
    }

    /// Returns the named A1 key generation.
    #[must_use]
    pub const fn operator_key_generation(&self) -> u64 {
        self.wire.operator_key_generation
    }

    /// Returns the exact canonical carrier bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn signature_algorithm(&self) -> &str {
        &self.wire.signature_algorithm
    }

    pub(crate) fn operator_signature_hex(&self) -> &str {
        &self.wire.operator_signature
    }

    pub(crate) fn signature_preimage(&self) -> Result<Vec<u8>, AuthorityError> {
        signature_preimage(
            A2_SIGNATURE_DOMAIN,
            self.activation_digest(),
            &self.wire.unsigned(),
        )
    }
}

/// Canonical, digest-checked prospective revocation carrier.
#[derive(Debug)]
pub struct ActivationRevocationRecord {
    wire: ActivationRevocationWire,
    canonical_bytes: Vec<u8>,
}

impl ActivationRevocationRecord {
    /// Decodes exact canonical bytes and verifies the asserted revocation digest.
    ///
    /// # Errors
    ///
    /// Refuses malformed, noncanonical, unknown-version, or digest-mismatched
    /// revocation bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let wire: ActivationRevocationWire = parse_exact(
            bytes,
            AuthorityError::RevocationMalformed,
            AuthorityError::RevocationNonCanonical,
        )?;
        if wire.schema != ACTIVATION_REVOCATION_SCHEMA {
            return Err(AuthorityError::RevocationSchemaUnsupported);
        }
        if wire.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(AuthorityError::RevocationVersionUnsupported);
        }
        let expected = revocation_digest(&wire.unsigned())?;
        if wire.record_digest != expected {
            return Err(AuthorityError::RevocationDigestMismatch);
        }
        Ok(Self {
            wire,
            canonical_bytes: bytes.to_vec(),
        })
    }

    /// Returns the exact revocation identity.
    #[must_use]
    pub const fn record_digest(&self) -> &Sha256Digest {
        &self.wire.record_digest
    }

    /// Returns the exact target A2 identity.
    #[must_use]
    pub const fn target_activation_digest(&self) -> &Sha256Digest {
        &self.wire.target_activation_digest
    }

    /// Returns the signed Store occurrence.
    #[must_use]
    pub fn occurrence_id(&self) -> &str {
        &self.wire.occurrence_id
    }

    /// Returns the authority domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.wire.domain
    }

    /// Returns the immutable anchor identity.
    #[must_use]
    pub const fn trust_anchor_id(&self) -> &Sha256Digest {
        &self.wire.trust_anchor_id
    }

    /// Returns the closed authority scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.wire.scope
    }

    /// Returns the revocation authority cut.
    #[must_use]
    pub const fn cut(&self) -> &AuthorityCut {
        &self.wire.cut
    }

    /// Returns the exact A1 identity named by the revocation.
    #[must_use]
    pub const fn operator_authority_digest(&self) -> &Sha256Digest {
        &self.wire.operator_authority_digest
    }

    /// Returns the named A1 key generation.
    #[must_use]
    pub const fn operator_key_generation(&self) -> u64 {
        self.wire.operator_key_generation
    }

    /// Returns the governing policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.wire.policy_version
    }

    /// Returns the exact canonical carrier bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn signature_algorithm(&self) -> &str {
        &self.wire.signature_algorithm
    }

    pub(crate) fn operator_signature_hex(&self) -> &str {
        &self.wire.operator_signature
    }

    pub(crate) fn signature_preimage(&self) -> Result<Vec<u8>, AuthorityError> {
        signature_preimage(
            REVOCATION_SIGNATURE_DOMAIN,
            self.record_digest(),
            &self.wire.unsigned(),
        )
    }
}

/// Canonical, digest-checked migration receipt carrier.
#[derive(Debug)]
pub struct MigrationReceipt {
    wire: MigrationReceiptWire,
    canonical_bytes: Vec<u8>,
}

impl MigrationReceipt {
    /// Decodes exact canonical bytes and verifies the asserted receipt digest.
    ///
    /// # Errors
    ///
    /// Refuses malformed, noncanonical, unknown-version, or digest-mismatched
    /// migration receipt bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let wire: MigrationReceiptWire = parse_exact(
            bytes,
            AuthorityError::MigrationReceiptMalformed,
            AuthorityError::MigrationReceiptNonCanonical,
        )?;
        if wire.schema != MIGRATION_RECEIPT_SCHEMA {
            return Err(AuthorityError::MigrationReceiptSchemaUnsupported);
        }
        if wire.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(AuthorityError::MigrationReceiptVersionUnsupported);
        }
        let expected = migration_digest(&wire.unsigned())?;
        if wire.receipt_digest != expected {
            return Err(AuthorityError::MigrationReceiptDigestMismatch);
        }
        Ok(Self {
            wire,
            canonical_bytes: bytes.to_vec(),
        })
    }

    /// Returns the exact migration-receipt identity.
    #[must_use]
    pub const fn receipt_digest(&self) -> &Sha256Digest {
        &self.wire.receipt_digest
    }

    /// Returns the existing Store occurrence named by this receipt.
    #[must_use]
    pub fn occurrence_id(&self) -> &str {
        &self.wire.occurrence_id
    }

    /// Returns the authority domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.wire.domain
    }

    /// Returns the exact prior root state.
    #[must_use]
    pub const fn old_root_state(&self) -> &OldRootState {
        &self.wire.old_root_state
    }

    /// Returns the new chain-root A2 digest.
    #[must_use]
    pub const fn new_chain_root_activation_digest(&self) -> &Sha256Digest {
        &self.wire.new_chain_root_activation_digest
    }

    /// Returns the new chain root's immutable anchor.
    #[must_use]
    pub const fn new_trust_anchor_id(&self) -> &Sha256Digest {
        &self.wire.new_trust_anchor_id
    }

    /// Returns the explicit migration disposition.
    #[must_use]
    pub const fn disposition(&self) -> MigrationDisposition {
        self.wire.disposition
    }

    /// Returns the migration cut.
    #[must_use]
    pub const fn cut(&self) -> &AuthorityCut {
        &self.wire.cut
    }

    /// Returns the governing policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.wire.policy_version
    }

    /// Returns the named A1 identity.
    #[must_use]
    pub const fn operator_authority_digest(&self) -> &Sha256Digest {
        &self.wire.operator_authority_digest
    }

    /// Returns the named A1 key generation.
    #[must_use]
    pub const fn operator_key_generation(&self) -> u64 {
        self.wire.operator_key_generation
    }

    /// Returns the exact declared restore-proof digest, when applicable.
    #[must_use]
    pub const fn restore_proof_digest(&self) -> Option<&Sha256Digest> {
        self.wire.restore_proof_digest.as_ref()
    }

    /// Returns the exact canonical receipt bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn signature_algorithm(&self) -> &str {
        &self.wire.signature_algorithm
    }

    pub(crate) fn operator_signature_hex(&self) -> &str {
        &self.wire.operator_signature
    }

    pub(crate) fn signature_preimage(&self) -> Result<Vec<u8>, AuthorityError> {
        signature_preimage(
            MIGRATION_SIGNATURE_DOMAIN,
            self.receipt_digest(),
            &self.wire.unsigned(),
        )
    }
}

/// Computes the exact order-independent candidate-set binding over Store-resident
/// post-genesis records only.
///
/// This function deliberately makes no validity or completeness claim.  The
/// bounded verifier calls it only after every carrier and structural law has
/// passed; the Store later compares the resulting digest against its own
/// enumeration.
///
/// # Errors
///
/// Refuses only if transcript length framing overflows.
pub fn digest_presented_authority_set(
    presented: &PresentedAuthoritySet,
) -> Result<Sha256Digest, AuthorityError> {
    let mut canonical_items = Vec::new();
    for record in presented.records() {
        let item = framed_bytes(
            PRESENTED_ITEM_DOMAIN,
            AUTHORITY_SCHEMA_VERSION,
            &[
                ("record_family", record.kind_label().as_bytes()),
                ("canonical_bytes", record.bytes()),
            ],
        )?;
        canonical_items.push(item);
    }
    canonical_items.sort_unstable();
    let mut framed_items = Vec::new();
    for item in canonical_items {
        let length = u64::try_from(item.len()).map_err(|_| AuthorityError::FramingOverflow)?;
        framed_items.extend_from_slice(&length.to_be_bytes());
        framed_items.extend_from_slice(&item);
    }
    framed_digest(
        PRESENTED_SET_DOMAIN,
        AUTHORITY_SCHEMA_VERSION,
        &[("canonical_post_genesis_record_set", &framed_items)],
    )
}

/// Computes the independent exact-byte binding over the custody-carried
/// genesis A1 and A2.
///
/// # Errors
///
/// Refuses only if transcript length framing overflows.
pub fn digest_genesis_authority_custody(
    custody: &GenesisAuthorityCustody,
) -> Result<Sha256Digest, AuthorityError> {
    framed_digest(
        CUSTODY_DIGEST_DOMAIN,
        AUTHORITY_SCHEMA_VERSION,
        &[
            ("genesis_a1", custody.genesis_a1_bytes()),
            ("genesis_a2", custody.genesis_a2_bytes()),
        ],
    )
}

/// Canonical immutable establishment-receipt transcript.
///
/// The complete transcript binds all chartered historical establishment
/// facts plus the independent custody and Store-resident candidate bindings.
/// Its receipt identity is intentionally computed over only
/// `{chain_root_activation_digest, occurrence_id, establishment_cut, arm}` as
/// required by the charter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstablishmentReceiptTranscript {
    schema: String,
    schema_version: u16,
    occurrence_id: String,
    chain_root_activation_digest: Sha256Digest,
    controlling_tip_digest_at_establishment: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    genesis_operator_authority_digest: Sha256Digest,
    genesis_operator_key_generation: u64,
    domain: String,
    establishment_cut: AuthorityCut,
    policy_version: u64,
    arm: EstablishmentArm,
    migration_receipt_digest: Option<Sha256Digest>,
    custody_digest: Sha256Digest,
    candidate_set_digest: Sha256Digest,
}

impl EstablishmentReceiptTranscript {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        occurrence_id: String,
        chain_root_activation_digest: Sha256Digest,
        controlling_tip_digest_at_establishment: Sha256Digest,
        trust_anchor_id: Sha256Digest,
        genesis_operator_authority_digest: Sha256Digest,
        genesis_operator_key_generation: u64,
        domain: String,
        establishment_cut: AuthorityCut,
        policy_version: u64,
        arm: EstablishmentArm,
        migration_receipt_digest: Option<Sha256Digest>,
        custody_digest: Sha256Digest,
        candidate_set_digest: Sha256Digest,
    ) -> Self {
        Self {
            schema: ESTABLISHMENT_RECEIPT_SCHEMA.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            occurrence_id,
            chain_root_activation_digest,
            controlling_tip_digest_at_establishment,
            trust_anchor_id,
            genesis_operator_authority_digest,
            genesis_operator_key_generation,
            domain,
            establishment_cut,
            policy_version,
            arm,
            migration_receipt_digest,
            custody_digest,
            candidate_set_digest,
        }
    }

    /// Parses an exact canonical receipt transcript for ordinary Store
    /// validation.
    ///
    /// The returned value retains the full authority-cut predecessor binding;
    /// callers can recompute [`Self::receipt_id`] and compare every indexed
    /// Store column against the typed accessors.
    ///
    /// # Errors
    ///
    /// Refuses malformed, noncanonical, unknown-version, or arm-inconsistent
    /// receipt transcripts.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let transcript: Self = parse_exact(
            bytes,
            AuthorityError::EstablishmentReceiptMalformed,
            AuthorityError::EstablishmentReceiptNonCanonical,
        )?;
        if transcript.schema != ESTABLISHMENT_RECEIPT_SCHEMA {
            return Err(AuthorityError::EstablishmentReceiptSchemaUnsupported);
        }
        if transcript.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(AuthorityError::EstablishmentReceiptVersionUnsupported);
        }
        let arm_matches = matches!(
            (transcript.arm, &transcript.migration_receipt_digest),
            (EstablishmentArm::Genesis, None) | (EstablishmentArm::Migration, Some(_))
        );
        if !arm_matches {
            return Err(AuthorityError::EstablishmentReceiptArmMismatch);
        }
        transcript.establishment_cut.validate_integer()?;
        if transcript.occurrence_id.is_empty()
            || transcript.occurrence_id.len() > MAX_IDENTITY_BYTES
            || transcript.domain.is_empty()
            || transcript.domain.len() > MAX_IDENTITY_BYTES
            || transcript
                .occurrence_id
                .chars()
                .chain(transcript.domain.chars())
                .any(char::is_control)
            || transcript.genesis_operator_key_generation == 0
            || transcript.genesis_operator_key_generation > MAX_SAFE_JSON_INTEGER
            || transcript
                .establishment_cut
                .predecessor_event_digest()
                .is_none()
        {
            return Err(AuthorityError::EstablishmentReceiptMalformed);
        }
        if transcript.policy_version != AUTHORITY_POLICY_VERSION {
            return Err(AuthorityError::PolicyVersionUnsupported);
        }
        Ok(transcript)
    }

    /// Returns the exact canonical, versioned receipt transcript bytes.
    ///
    /// # Errors
    ///
    /// Refuses if canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_json_bytes(self).map_err(|_| AuthorityError::FramingOverflow)
    }

    /// Computes the chartered domain-separated four-field receipt identity.
    ///
    /// # Errors
    ///
    /// Refuses if cut canonicalization or framing overflows.
    pub fn receipt_id(&self) -> Result<Sha256Digest, AuthorityError> {
        let cut = canonical_json_bytes(&self.establishment_cut)
            .map_err(|_| AuthorityError::FramingOverflow)?;
        let arm = match self.arm {
            EstablishmentArm::Genesis => b"genesis".as_slice(),
            EstablishmentArm::Migration => b"migration".as_slice(),
        };
        framed_digest(
            ESTABLISHMENT_RECEIPT_ID_DOMAIN,
            AUTHORITY_SCHEMA_VERSION,
            &[
                (
                    "activation_digest",
                    self.chain_root_activation_digest.as_str().as_bytes(),
                ),
                ("occurrence", self.occurrence_id.as_bytes()),
                ("cut", &cut),
                ("arm", arm),
            ],
        )
    }

    /// Returns the exact Store occurrence.
    #[must_use]
    pub fn occurrence_id(&self) -> &str {
        &self.occurrence_id
    }
    /// Returns the immutable A2 chain root.
    #[must_use]
    pub const fn chain_root_activation_digest(&self) -> &Sha256Digest {
        &self.chain_root_activation_digest
    }
    /// Returns the historical establishment-time controlling tip.
    #[must_use]
    pub const fn controlling_tip_digest_at_establishment(&self) -> &Sha256Digest {
        &self.controlling_tip_digest_at_establishment
    }
    /// Returns the immutable anchor.
    #[must_use]
    pub const fn trust_anchor_id(&self) -> &Sha256Digest {
        &self.trust_anchor_id
    }
    /// Returns the custody genesis A1 identity.
    #[must_use]
    pub const fn genesis_operator_authority_digest(&self) -> &Sha256Digest {
        &self.genesis_operator_authority_digest
    }
    /// Returns the genesis A1 key generation.
    #[must_use]
    pub const fn genesis_operator_key_generation(&self) -> u64 {
        self.genesis_operator_key_generation
    }
    /// Returns the authority domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }
    /// Returns the establishment authority cut.
    #[must_use]
    pub const fn establishment_cut(&self) -> &AuthorityCut {
        &self.establishment_cut
    }
    /// Returns the policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }
    /// Returns the establishment arm.
    #[must_use]
    pub const fn arm(&self) -> EstablishmentArm {
        self.arm
    }
    /// Returns the migration receipt binding, explicitly absent for genesis.
    #[must_use]
    pub const fn migration_receipt_digest(&self) -> Option<&Sha256Digest> {
        self.migration_receipt_digest.as_ref()
    }
    /// Returns the exact external-custody binding.
    #[must_use]
    pub const fn custody_digest(&self) -> &Sha256Digest {
        &self.custody_digest
    }
    /// Returns the exact Store-resident candidate-set binding.
    #[must_use]
    pub const fn candidate_set_digest(&self) -> &Sha256Digest {
        &self.candidate_set_digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorAuthorityWire {
    schema: String,
    schema_version: u16,
    record_digest: Sha256Digest,
    operator_principal: String,
    signature_algorithm: String,
    ed25519_verification_key: String,
    key_generation: u64,
    policy_version: u64,
    policy_floor: u64,
    domain: String,
    permitted_scope: String,
    cut: AuthorityCut,
    predecessor_a1_digest: Option<Sha256Digest>,
    predecessor_signature: Option<String>,
}

#[derive(Serialize)]
struct OperatorAuthorityUnsigned<'a> {
    schema: &'a str,
    schema_version: u16,
    operator_principal: &'a str,
    signature_algorithm: &'a str,
    ed25519_verification_key: &'a str,
    key_generation: u64,
    policy_version: u64,
    policy_floor: u64,
    domain: &'a str,
    permitted_scope: &'a str,
    cut: &'a AuthorityCut,
    predecessor_a1_digest: Option<&'a Sha256Digest>,
}

impl OperatorAuthorityWire {
    fn unsigned(&self) -> OperatorAuthorityUnsigned<'_> {
        OperatorAuthorityUnsigned {
            schema: &self.schema,
            schema_version: self.schema_version,
            operator_principal: &self.operator_principal,
            signature_algorithm: &self.signature_algorithm,
            ed25519_verification_key: &self.ed25519_verification_key,
            key_generation: self.key_generation,
            policy_version: self.policy_version,
            policy_floor: self.policy_floor,
            domain: &self.domain,
            permitted_scope: &self.permitted_scope,
            cut: &self.cut,
            predecessor_a1_digest: self.predecessor_a1_digest.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentActivationWire {
    schema: String,
    schema_version: u16,
    activation_digest: Sha256Digest,
    context: ActivationContext,
    occurrence_id: String,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    trust_anchor_id: Sha256Digest,
    scope: String,
    domain: String,
    cut: AuthorityCut,
    predecessor_activation_digest: Option<Sha256Digest>,
    expiry_cut: Option<u64>,
    policy_version: u64,
    operator_authority_digest: Sha256Digest,
    operator_key_generation: u64,
    signature_algorithm: String,
    operator_signature: String,
}

#[derive(Serialize)]
struct ResidentActivationUnsigned<'a> {
    schema: &'a str,
    schema_version: u16,
    context: ActivationContext,
    occurrence_id: &'a str,
    resident_identity: &'a str,
    resident_generation: u64,
    host_role: &'a str,
    role_manifest_generation: u64,
    trust_anchor_id: &'a Sha256Digest,
    scope: &'a str,
    domain: &'a str,
    cut: &'a AuthorityCut,
    predecessor_activation_digest: Option<&'a Sha256Digest>,
    expiry_cut: Option<u64>,
    policy_version: u64,
    operator_authority_digest: &'a Sha256Digest,
    operator_key_generation: u64,
    signature_algorithm: &'a str,
}

impl ResidentActivationWire {
    fn unsigned(&self) -> ResidentActivationUnsigned<'_> {
        ResidentActivationUnsigned {
            schema: &self.schema,
            schema_version: self.schema_version,
            context: self.context,
            occurrence_id: &self.occurrence_id,
            resident_identity: &self.resident_identity,
            resident_generation: self.resident_generation,
            host_role: &self.host_role,
            role_manifest_generation: self.role_manifest_generation,
            trust_anchor_id: &self.trust_anchor_id,
            scope: &self.scope,
            domain: &self.domain,
            cut: &self.cut,
            predecessor_activation_digest: self.predecessor_activation_digest.as_ref(),
            expiry_cut: self.expiry_cut,
            policy_version: self.policy_version,
            operator_authority_digest: &self.operator_authority_digest,
            operator_key_generation: self.operator_key_generation,
            signature_algorithm: &self.signature_algorithm,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationRevocationWire {
    schema: String,
    schema_version: u16,
    record_digest: Sha256Digest,
    target_activation_digest: Sha256Digest,
    occurrence_id: String,
    domain: String,
    trust_anchor_id: Sha256Digest,
    scope: String,
    cut: AuthorityCut,
    policy_version: u64,
    operator_authority_digest: Sha256Digest,
    operator_key_generation: u64,
    signature_algorithm: String,
    operator_signature: String,
}

#[derive(Serialize)]
struct ActivationRevocationUnsigned<'a> {
    schema: &'a str,
    schema_version: u16,
    target_activation_digest: &'a Sha256Digest,
    occurrence_id: &'a str,
    domain: &'a str,
    trust_anchor_id: &'a Sha256Digest,
    scope: &'a str,
    cut: &'a AuthorityCut,
    policy_version: u64,
    operator_authority_digest: &'a Sha256Digest,
    operator_key_generation: u64,
    signature_algorithm: &'a str,
}

impl ActivationRevocationWire {
    fn unsigned(&self) -> ActivationRevocationUnsigned<'_> {
        ActivationRevocationUnsigned {
            schema: &self.schema,
            schema_version: self.schema_version,
            target_activation_digest: &self.target_activation_digest,
            occurrence_id: &self.occurrence_id,
            domain: &self.domain,
            trust_anchor_id: &self.trust_anchor_id,
            scope: &self.scope,
            cut: &self.cut,
            policy_version: self.policy_version,
            operator_authority_digest: &self.operator_authority_digest,
            operator_key_generation: self.operator_key_generation,
            signature_algorithm: &self.signature_algorithm,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationReceiptWire {
    schema: String,
    schema_version: u16,
    receipt_digest: Sha256Digest,
    occurrence_id: String,
    domain: String,
    old_root_state: OldRootState,
    new_chain_root_activation_digest: Sha256Digest,
    new_trust_anchor_id: Sha256Digest,
    disposition: MigrationDisposition,
    cut: AuthorityCut,
    policy_version: u64,
    operator_authority_digest: Sha256Digest,
    operator_key_generation: u64,
    restore_proof_digest: Option<Sha256Digest>,
    signature_algorithm: String,
    operator_signature: String,
}

#[derive(Serialize)]
struct MigrationReceiptUnsigned<'a> {
    schema: &'a str,
    schema_version: u16,
    occurrence_id: &'a str,
    domain: &'a str,
    old_root_state: &'a OldRootState,
    new_chain_root_activation_digest: &'a Sha256Digest,
    new_trust_anchor_id: &'a Sha256Digest,
    disposition: MigrationDisposition,
    cut: &'a AuthorityCut,
    policy_version: u64,
    operator_authority_digest: &'a Sha256Digest,
    operator_key_generation: u64,
    restore_proof_digest: Option<&'a Sha256Digest>,
    signature_algorithm: &'a str,
}

impl MigrationReceiptWire {
    fn unsigned(&self) -> MigrationReceiptUnsigned<'_> {
        MigrationReceiptUnsigned {
            schema: &self.schema,
            schema_version: self.schema_version,
            occurrence_id: &self.occurrence_id,
            domain: &self.domain,
            old_root_state: &self.old_root_state,
            new_chain_root_activation_digest: &self.new_chain_root_activation_digest,
            new_trust_anchor_id: &self.new_trust_anchor_id,
            disposition: self.disposition,
            cut: &self.cut,
            policy_version: self.policy_version,
            operator_authority_digest: &self.operator_authority_digest,
            operator_key_generation: self.operator_key_generation,
            restore_proof_digest: self.restore_proof_digest.as_ref(),
            signature_algorithm: &self.signature_algorithm,
        }
    }
}

fn parse_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    malformed: AuthorityError,
    noncanonical: AuthorityError,
) -> Result<T, AuthorityError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(malformed);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| malformed)?;
    let canonical = canonical_json_bytes(&value).map_err(|_| noncanonical.clone())?;
    if canonical != bytes {
        return Err(noncanonical);
    }
    Ok(value)
}

fn a1_digest(unsigned: &OperatorAuthorityUnsigned<'_>) -> Result<Sha256Digest, AuthorityError> {
    canonical_unsigned_digest(A1_ID_DOMAIN, unsigned)
}

fn a2_digest(unsigned: &ResidentActivationUnsigned<'_>) -> Result<Sha256Digest, AuthorityError> {
    canonical_unsigned_digest(A2_ID_DOMAIN, unsigned)
}

fn revocation_digest(
    unsigned: &ActivationRevocationUnsigned<'_>,
) -> Result<Sha256Digest, AuthorityError> {
    canonical_unsigned_digest(REVOCATION_ID_DOMAIN, unsigned)
}

fn migration_digest(
    unsigned: &MigrationReceiptUnsigned<'_>,
) -> Result<Sha256Digest, AuthorityError> {
    canonical_unsigned_digest(MIGRATION_ID_DOMAIN, unsigned)
}

fn canonical_unsigned_digest<T: Serialize>(
    domain: &str,
    unsigned: &T,
) -> Result<Sha256Digest, AuthorityError> {
    let canonical = canonical_json_bytes(unsigned).map_err(|_| AuthorityError::FramingOverflow)?;
    framed_digest(
        domain,
        AUTHORITY_SCHEMA_VERSION,
        &[("canonical_unsigned_record", &canonical)],
    )
}

fn signature_preimage<T: Serialize>(
    domain: &str,
    digest: &Sha256Digest,
    unsigned: &T,
) -> Result<Vec<u8>, AuthorityError> {
    let canonical = canonical_json_bytes(unsigned).map_err(|_| AuthorityError::FramingOverflow)?;
    framed_bytes(
        domain,
        AUTHORITY_SCHEMA_VERSION,
        &[
            ("record_digest", digest.as_str().as_bytes()),
            ("canonical_unsigned_record", &canonical),
        ],
    )
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)] // Some hostile mutation helpers are used only by this crate's cfg(test) suite.
pub(crate) mod fixture_access {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    pub(crate) fn a1_bytes(mut wire: OperatorAuthorityWire) -> Vec<u8> {
        wire.record_digest = a1_digest(&wire.unsigned()).unwrap();
        canonical_json_bytes(&wire).unwrap()
    }

    pub(crate) fn a1_digest_for(wire: &OperatorAuthorityWire) -> Sha256Digest {
        a1_digest(&wire.unsigned()).unwrap()
    }

    pub(crate) fn a1_signature_preimage_for(wire: &OperatorAuthorityWire) -> Vec<u8> {
        let digest = a1_digest_for(wire);
        signature_preimage(A1_SIGNATURE_DOMAIN, &digest, &wire.unsigned()).unwrap()
    }

    pub(crate) fn a2_bytes(mut wire: ResidentActivationWire) -> Vec<u8> {
        wire.activation_digest = a2_digest(&wire.unsigned()).unwrap();
        canonical_json_bytes(&wire).unwrap()
    }

    pub(crate) fn a2_digest_for(wire: &ResidentActivationWire) -> Sha256Digest {
        a2_digest(&wire.unsigned()).unwrap()
    }

    pub(crate) fn a2_signature_preimage_for(wire: &ResidentActivationWire) -> Vec<u8> {
        let digest = a2_digest_for(wire);
        signature_preimage(A2_SIGNATURE_DOMAIN, &digest, &wire.unsigned()).unwrap()
    }

    pub(crate) fn revocation_bytes(mut wire: ActivationRevocationWire) -> Vec<u8> {
        wire.record_digest = revocation_digest(&wire.unsigned()).unwrap();
        canonical_json_bytes(&wire).unwrap()
    }

    pub(crate) fn revocation_digest_for(wire: &ActivationRevocationWire) -> Sha256Digest {
        revocation_digest(&wire.unsigned()).unwrap()
    }

    pub(crate) fn revocation_signature_preimage_for(wire: &ActivationRevocationWire) -> Vec<u8> {
        let digest = revocation_digest_for(wire);
        signature_preimage(REVOCATION_SIGNATURE_DOMAIN, &digest, &wire.unsigned()).unwrap()
    }

    pub(crate) fn migration_bytes(mut wire: MigrationReceiptWire) -> Vec<u8> {
        wire.receipt_digest = migration_digest(&wire.unsigned()).unwrap();
        canonical_json_bytes(&wire).unwrap()
    }

    pub(crate) fn migration_digest_for(wire: &MigrationReceiptWire) -> Sha256Digest {
        migration_digest(&wire.unsigned()).unwrap()
    }

    pub(crate) fn migration_signature_preimage_for(wire: &MigrationReceiptWire) -> Vec<u8> {
        let digest = migration_digest_for(wire);
        signature_preimage(MIGRATION_SIGNATURE_DOMAIN, &digest, &wire.unsigned()).unwrap()
    }

    pub(crate) fn placeholder_digest() -> Sha256Digest {
        nq_protocol::sha256_bytes(b"fixture placeholder")
    }

    pub(crate) fn a1_wire(
        operator_principal: String,
        verification_key: String,
        key_generation: u64,
        cut: AuthorityCut,
        predecessor_a1_digest: Option<Sha256Digest>,
        predecessor_signature: Option<String>,
    ) -> OperatorAuthorityWire {
        OperatorAuthorityWire {
            schema: OPERATOR_AUTHORITY_SCHEMA.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            record_digest: placeholder_digest(),
            operator_principal,
            signature_algorithm: ED25519_SIGNATURE_ALGORITHM.to_owned(),
            ed25519_verification_key: verification_key,
            key_generation,
            policy_version: AUTHORITY_POLICY_VERSION,
            policy_floor: AUTHORITY_POLICY_VERSION,
            domain: "runtime/backend".to_owned(),
            permitted_scope: RUNTIME_DEPENDENCY_ADMISSION_SCOPE.to_owned(),
            cut,
            predecessor_a1_digest,
            predecessor_signature,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn a2_wire(
        context: ActivationContext,
        cut: AuthorityCut,
        predecessor_activation_digest: Option<Sha256Digest>,
        operator_authority_digest: Sha256Digest,
        operator_key_generation: u64,
        operator_signature: String,
        expiry_cut: Option<u64>,
    ) -> ResidentActivationWire {
        ResidentActivationWire {
            schema: RESIDENT_ACTIVATION_SCHEMA.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            activation_digest: placeholder_digest(),
            context,
            occurrence_id: "store-occurrence/operator-minted".to_owned(),
            resident_identity: "resident/node-a".to_owned(),
            resident_generation: 7,
            host_role: "host-role/runtime".to_owned(),
            role_manifest_generation: 11,
            trust_anchor_id: nq_protocol::sha256_bytes(b"fixture trust anchor"),
            scope: RUNTIME_DEPENDENCY_ADMISSION_SCOPE.to_owned(),
            domain: "runtime/backend".to_owned(),
            cut,
            predecessor_activation_digest,
            expiry_cut,
            policy_version: AUTHORITY_POLICY_VERSION,
            operator_authority_digest,
            operator_key_generation,
            signature_algorithm: ED25519_SIGNATURE_ALGORITHM.to_owned(),
            operator_signature,
        }
    }

    pub(crate) fn revocation_wire(
        target_activation_digest: Sha256Digest,
        cut: AuthorityCut,
        operator_authority_digest: Sha256Digest,
        operator_key_generation: u64,
        operator_signature: String,
    ) -> ActivationRevocationWire {
        ActivationRevocationWire {
            schema: ACTIVATION_REVOCATION_SCHEMA.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            record_digest: placeholder_digest(),
            target_activation_digest,
            occurrence_id: "store-occurrence/operator-minted".to_owned(),
            domain: "runtime/backend".to_owned(),
            trust_anchor_id: nq_protocol::sha256_bytes(b"fixture trust anchor"),
            scope: RUNTIME_DEPENDENCY_ADMISSION_SCOPE.to_owned(),
            cut,
            policy_version: AUTHORITY_POLICY_VERSION,
            operator_authority_digest,
            operator_key_generation,
            signature_algorithm: ED25519_SIGNATURE_ALGORITHM.to_owned(),
            operator_signature,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn migration_wire(
        old_root_state: OldRootState,
        new_chain_root_activation_digest: Sha256Digest,
        new_trust_anchor_id: Sha256Digest,
        cut: AuthorityCut,
        operator_authority_digest: Sha256Digest,
        operator_key_generation: u64,
        restore_proof_digest: Option<Sha256Digest>,
        operator_signature: String,
    ) -> MigrationReceiptWire {
        MigrationReceiptWire {
            schema: MIGRATION_RECEIPT_SCHEMA.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            receipt_digest: placeholder_digest(),
            occurrence_id: "store-occurrence/operator-minted".to_owned(),
            domain: "runtime/backend".to_owned(),
            old_root_state,
            new_chain_root_activation_digest,
            new_trust_anchor_id,
            disposition: MigrationDisposition::Accepted,
            cut,
            policy_version: AUTHORITY_POLICY_VERSION,
            operator_authority_digest,
            operator_key_generation,
            restore_proof_digest,
            signature_algorithm: ED25519_SIGNATURE_ALGORITHM.to_owned(),
            operator_signature,
        }
    }

    pub(crate) fn cut(
        sequence: u64,
        predecessor_event_digest: Option<Sha256Digest>,
    ) -> AuthorityCut {
        AuthorityCut {
            sequence,
            predecessor_event_digest,
        }
    }

    pub(crate) fn set_a1_signature(wire: &mut OperatorAuthorityWire, signature: String) {
        wire.predecessor_signature = Some(signature);
    }

    pub(crate) fn set_a2_signature(wire: &mut ResidentActivationWire, signature: String) {
        wire.operator_signature = signature;
    }

    pub(crate) fn set_revocation_signature(wire: &mut ActivationRevocationWire, signature: String) {
        wire.operator_signature = signature;
    }

    pub(crate) fn set_revocation_anchor(wire: &mut ActivationRevocationWire, anchor: Sha256Digest) {
        wire.trust_anchor_id = anchor;
    }

    pub(crate) fn set_migration_signature(wire: &mut MigrationReceiptWire, signature: String) {
        wire.operator_signature = signature;
    }

    pub(crate) fn set_a2_scope(wire: &mut ResidentActivationWire, scope: String) {
        wire.scope = scope;
    }

    pub(crate) fn set_a2_domain(wire: &mut ResidentActivationWire, domain: String) {
        wire.domain = domain;
    }

    pub(crate) fn set_a2_anchor(wire: &mut ResidentActivationWire, anchor: Sha256Digest) {
        wire.trust_anchor_id = anchor;
    }

    pub(crate) fn set_a2_resident(wire: &mut ResidentActivationWire, resident: String) {
        wire.resident_identity = resident;
    }

    pub(crate) fn set_a2_resident_generation(wire: &mut ResidentActivationWire, generation: u64) {
        wire.resident_generation = generation;
    }

    pub(crate) fn set_a2_role(wire: &mut ResidentActivationWire, role: String) {
        wire.host_role = role;
    }

    pub(crate) fn set_a2_role_manifest_generation(
        wire: &mut ResidentActivationWire,
        generation: u64,
    ) {
        wire.role_manifest_generation = generation;
    }

    pub(crate) fn set_a2_occurrence(wire: &mut ResidentActivationWire, occurrence: String) {
        wire.occurrence_id = occurrence;
    }

    pub(crate) fn set_a2_operator_authority(
        wire: &mut ResidentActivationWire,
        authority_digest: Sha256Digest,
        key_generation: u64,
    ) {
        wire.operator_authority_digest = authority_digest;
        wire.operator_key_generation = key_generation;
    }

    pub(crate) fn set_a2_signature_algorithm(wire: &mut ResidentActivationWire, algorithm: String) {
        wire.signature_algorithm = algorithm;
    }

    pub(crate) fn set_a2_policy(wire: &mut ResidentActivationWire, policy: u64) {
        wire.policy_version = policy;
    }

    pub(crate) fn set_migration_disposition(
        wire: &mut MigrationReceiptWire,
        disposition: MigrationDisposition,
    ) {
        wire.disposition = disposition;
    }
}
