//! Explicit evidence-freeze classification for non-migratable schema-v7
//! genesis-cardinality states.
//!
//! This carrier is deliberately not a migration receipt, Store occurrence,
//! activation, or authority event. It authenticates an operator disposition
//! over exact Store-derived facts. Only the Store can testify that those facts
//! are complete.

use std::marker::PhantomData;

use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{Sha256Digest, canonical_json_bytes};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityError, ED25519_SIGNATURE_ALGORITHM, MigrationDisposition, OldRootState,
    OperatorAuthorityRecord, RUNTIME_DEPENDENCY_ADMISSION_SCOPE, VerificationBrand,
    framing::{framed_bytes, framed_digest},
    records::{AUTHORITY_POLICY_VERSION, AUTHORITY_SCHEMA_VERSION, MAX_IDENTITY_BYTES},
};

/// Canonical schema for explicit non-migratable schema-v7 dispositions.
pub const V7_CARDINALITY_DISPOSITION_SCHEMA: &str =
    "nq.runtime_dependency_v7_cardinality_disposition.v1";
/// The only Store schema version this carrier may classify.
pub const CARDINALITY_DISPOSITION_SOURCE_SCHEMA_VERSION: u32 = 7;

const CARDINALITY_DISPOSITION_ID_DOMAIN: &str =
    "nq.runtime_dependency_authority.v7_cardinality_disposition.identity.v1";
const CARDINALITY_DISPOSITION_SIGNATURE_DOMAIN: &str =
    "nq.runtime_dependency_authority.v7_cardinality_disposition.signature.v1";
const MAX_RECORD_BYTES: usize = 1_048_576;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Exact unverified canonical carrier bytes.
#[derive(Debug)]
pub struct V7CardinalityDispositionBytes(Vec<u8>);

impl V7CardinalityDispositionBytes {
    /// Wraps unverified bytes without making a validity or completeness claim.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the exact unverified carrier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Store-derived facts that an operator-signed cardinality disposition must
/// match exactly.
///
/// The verifier checks correspondence only. It cannot prove that the caller
/// enumerated the Store completely or computed its logical digest correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V7CardinalityDispositionExpectations {
    /// Exact byte-lexicographically sorted genesis census: zero rows, one
    /// empty identity, or at least two rows.
    pub genesis_identities: Vec<String>,
    /// Exact logical digest of the locked schema-v7 source.
    pub source_logical_digest: Sha256Digest,
    /// Exact old rooted/rootless state of that source.
    pub old_root_state: OldRootState,
    /// Exact bounded runtime/backend authority domain.
    pub domain: String,
    /// Minimum supported policy version.
    pub policy_floor: u64,
    /// Exact exogenous official-restore declaration, otherwise absent.
    pub restore_declaration_digest: Option<Sha256Digest>,
}

#[derive(PartialEq, Eq)]
struct VerifiedFields {
    canonical_bytes: Vec<u8>,
    disposition_digest: Sha256Digest,
    disposition: MigrationDisposition,
    genesis_identities: Vec<String>,
    source_logical_digest: Sha256Digest,
    old_root_state: OldRootState,
    domain: String,
    policy_version: u64,
    operator_authority_digest: Sha256Digest,
    operator_key_generation: u64,
    restore_declaration_digest: Option<Sha256Digest>,
}

struct ReverificationContext {
    genesis_operator_authority_bytes: Vec<u8>,
    disposition_bytes: Vec<u8>,
}

/// Sealed proof of an authentic non-migratable schema-v7 evidence-freeze
/// disposition over exact presented expectations.
///
/// This type has private fields, no public constructor, no cloning or
/// serialization path, and no conversion to establishment evidence. It does
/// not establish an occurrence, activation, root, or migration eligibility.
pub struct VerifiedV7CardinalityDisposition<'id> {
    fields: VerifiedFields,
    reverification: ReverificationContext,
    _invariant: PhantomData<fn(&'id mut ()) -> &'id mut ()>,
}

impl<'id> VerifiedV7CardinalityDisposition<'id> {
    fn new(
        fields: VerifiedFields,
        reverification: ReverificationContext,
        _brand: &VerificationBrand<'id>,
    ) -> Self {
        Self {
            fields,
            reverification,
            _invariant: PhantomData,
        }
    }

    /// Reauthenticates this exact signed carrier against newly supplied exact
    /// Store-derived expectations.
    ///
    /// The caller remains responsible for deriving a complete genesis census,
    /// logical digest, root state, and restore declaration from one locked
    /// Store snapshot.
    ///
    /// # Errors
    ///
    /// Refuses any signature, digest, cardinality, disposition, A1, policy,
    /// domain, root, source, declaration, or sealed-result mismatch.
    pub fn reverify_exact_expectations(
        &self,
        expectations: &V7CardinalityDispositionExpectations,
    ) -> Result<(), AuthorityError> {
        let raw = V7CardinalityDispositionBytes::new(self.reverification.disposition_bytes.clone());
        let fields = resolve_fields(
            &self.reverification.genesis_operator_authority_bytes,
            &raw,
            expectations,
        )?;
        if fields != self.fields {
            return Err(AuthorityError::V7CardinalityCorrespondenceMismatch);
        }
        Ok(())
    }

    /// Returns the exact canonical signed carrier bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.fields.canonical_bytes
    }

    /// Returns the domain-separated disposition identity.
    #[must_use]
    pub const fn disposition_digest(&self) -> &Sha256Digest {
        &self.fields.disposition_digest
    }

    /// Returns the exact signed evidence-freeze disposition.
    #[must_use]
    pub const fn disposition(&self) -> MigrationDisposition {
        self.fields.disposition
    }

    /// Returns the exact sorted absent, singleton-empty, or multiple genesis census.
    #[must_use]
    pub fn genesis_identities(&self) -> &[String] {
        &self.fields.genesis_identities
    }

    /// Returns the exact locked schema-v7 source logical digest.
    #[must_use]
    pub const fn source_logical_digest(&self) -> &Sha256Digest {
        &self.fields.source_logical_digest
    }

    /// Returns the exact historical rooted/rootless state.
    #[must_use]
    pub const fn old_root_state(&self) -> &OldRootState {
        &self.fields.old_root_state
    }

    /// Returns the exact authority domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.fields.domain
    }

    /// Returns the governing policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.fields.policy_version
    }

    /// Returns the exact exogenous genesis A1 identity.
    #[must_use]
    pub const fn operator_authority_digest(&self) -> &Sha256Digest {
        &self.fields.operator_authority_digest
    }

    /// Returns the exact exogenous genesis A1 key generation.
    #[must_use]
    pub const fn operator_key_generation(&self) -> u64 {
        self.fields.operator_key_generation
    }

    /// Returns the official-restore declaration binding, when present.
    #[must_use]
    pub const fn restore_declaration_digest(&self) -> Option<&Sha256Digest> {
        self.fields.restore_declaration_digest.as_ref()
    }
}

/// Verifies an explicit operator-signed disposition for a schema-v7 source
/// that has zero rows, one empty genesis identity, or multiple genesis rows.
///
/// The exogenous genesis A1 authenticates the classification act. Its A2, if
/// any, is deliberately not accepted or inspected by this path. Successful
/// verification proves correspondence over the presented expectations only;
/// it does not prove Store completeness and cannot establish or migrate.
///
/// # Errors
///
/// Refuses malformed/noncanonical bytes, invalid digests or signatures, a
/// non-genesis A1, one nonempty/unsorted/duplicate genesis identities,
/// `accepted`, an unsupported policy or source version, and every expectation
/// mismatch.
pub fn verify_v7_cardinality_disposition<'id>(
    brand: &VerificationBrand<'id>,
    genesis_operator_authority_bytes: &[u8],
    raw: &V7CardinalityDispositionBytes,
    expectations: &V7CardinalityDispositionExpectations,
) -> Result<VerifiedV7CardinalityDisposition<'id>, AuthorityError> {
    let fields = resolve_fields(genesis_operator_authority_bytes, raw, expectations)?;
    Ok(VerifiedV7CardinalityDisposition::new(
        fields,
        ReverificationContext {
            genesis_operator_authority_bytes: genesis_operator_authority_bytes.to_vec(),
            disposition_bytes: raw.as_bytes().to_vec(),
        },
        brand,
    ))
}

fn resolve_fields(
    genesis_operator_authority_bytes: &[u8],
    raw: &V7CardinalityDispositionBytes,
    expectations: &V7CardinalityDispositionExpectations,
) -> Result<VerifiedFields, AuthorityError> {
    validate_expectations(expectations)?;
    let wire = parse_exact(raw.as_bytes())?;
    if wire.schema != V7_CARDINALITY_DISPOSITION_SCHEMA {
        return Err(AuthorityError::V7CardinalityDispositionSchemaUnsupported);
    }
    if wire.schema_version != AUTHORITY_SCHEMA_VERSION {
        return Err(AuthorityError::V7CardinalityDispositionVersionUnsupported);
    }
    if wire.source_schema_version != CARDINALITY_DISPOSITION_SOURCE_SCHEMA_VERSION {
        return Err(AuthorityError::V7CardinalitySourceVersionMismatch);
    }
    let expected_digest = disposition_digest(&wire.unsigned())?;
    if wire.disposition_digest != expected_digest {
        return Err(AuthorityError::V7CardinalityDispositionDigestMismatch);
    }
    validate_genesis_identities(&wire.genesis_identities)?;
    if wire.disposition == MigrationDisposition::Accepted {
        return Err(AuthorityError::V7CardinalityAcceptedForbidden);
    }
    if wire.genesis_identities != expectations.genesis_identities {
        return Err(AuthorityError::V7CardinalitySetMismatch);
    }
    if wire.source_logical_digest != expectations.source_logical_digest {
        return Err(AuthorityError::V7CardinalitySourceDigestMismatch);
    }
    if wire.old_root_state != expectations.old_root_state {
        return Err(AuthorityError::V7CardinalityOldRootMismatch);
    }
    validate_identity(&wire.domain)?;
    if wire.domain != expectations.domain {
        return Err(AuthorityError::DomainMismatch);
    }
    validate_policy(wire.policy_version, expectations.policy_floor)?;
    if wire.restore_declaration_digest != expectations.restore_declaration_digest {
        return Err(AuthorityError::RestoreDeclarationMismatch);
    }
    if wire.signature_algorithm != ED25519_SIGNATURE_ALGORITHM {
        return Err(AuthorityError::V7CardinalityDispositionSignatureAlgorithmUnsupported);
    }

    let genesis_a1 =
        OperatorAuthorityRecord::from_canonical_bytes(genesis_operator_authority_bytes)?;
    validate_genesis_a1(&genesis_a1, expectations)?;
    if wire.operator_authority_digest != *genesis_a1.record_digest() {
        return Err(AuthorityError::A1IdentityMismatch);
    }
    if wire.operator_key_generation != genesis_a1.key_generation() {
        return Err(AuthorityError::A1GenerationMismatch);
    }
    let key = decode_verifying_key(genesis_a1.verification_key_hex())?;
    verify_signature(
        &key,
        &wire.operator_signature,
        &disposition_signature_preimage(&wire)?,
    )?;

    Ok(VerifiedFields {
        canonical_bytes: raw.as_bytes().to_vec(),
        disposition_digest: wire.disposition_digest,
        disposition: wire.disposition,
        genesis_identities: wire.genesis_identities,
        source_logical_digest: wire.source_logical_digest,
        old_root_state: wire.old_root_state,
        domain: wire.domain,
        policy_version: wire.policy_version,
        operator_authority_digest: wire.operator_authority_digest,
        operator_key_generation: wire.operator_key_generation,
        restore_declaration_digest: wire.restore_declaration_digest,
    })
}

fn validate_expectations(
    expectations: &V7CardinalityDispositionExpectations,
) -> Result<(), AuthorityError> {
    validate_genesis_identities(&expectations.genesis_identities)?;
    validate_identity(&expectations.domain)?;
    validate_policy(expectations.policy_floor, expectations.policy_floor)
}

fn validate_genesis_a1(
    record: &OperatorAuthorityRecord,
    expectations: &V7CardinalityDispositionExpectations,
) -> Result<(), AuthorityError> {
    validate_identity(record.operator_principal())?;
    if record.predecessor_a1_digest().is_some()
        || record.predecessor_signature_hex().is_some()
        || record.cut().predecessor_event_digest().is_some()
    {
        return Err(AuthorityError::A1GenesisShapeMismatch);
    }
    if record.signature_algorithm() != ED25519_SIGNATURE_ALGORITHM {
        return Err(AuthorityError::A1SignatureAlgorithmUnsupported);
    }
    if record.domain() != expectations.domain {
        return Err(AuthorityError::DomainMismatch);
    }
    if record.permitted_scope() != RUNTIME_DEPENDENCY_ADMISSION_SCOPE {
        return Err(AuthorityError::ScopeMismatch);
    }
    if record.key_generation() == 0 || record.key_generation() > MAX_SAFE_JSON_INTEGER {
        return Err(AuthorityError::IdentityMalformed);
    }
    validate_policy(record.policy_version(), expectations.policy_floor)?;
    if record.policy_floor() > record.policy_version() {
        return Err(AuthorityError::PolicyFloorMismatch);
    }
    if record.policy_floor() < expectations.policy_floor {
        return Err(AuthorityError::PolicyBelowFloor);
    }
    Ok(())
}

fn validate_genesis_identities(identities: &[String]) -> Result<(), AuthorityError> {
    if matches!(identities, [identity] if !identity.is_empty()) {
        return Err(AuthorityError::V7CardinalityInvalid);
    }
    for identity in identities {
        if identity.len() > MAX_IDENTITY_BYTES || identity.chars().any(char::is_control) {
            return Err(AuthorityError::IdentityMalformed);
        }
    }
    if identities.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AuthorityError::V7CardinalityInvalid);
    }
    Ok(())
}

fn validate_identity(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
        return Err(AuthorityError::IdentityMalformed);
    }
    Ok(())
}

fn validate_policy(version: u64, required_floor: u64) -> Result<(), AuthorityError> {
    if version != AUTHORITY_POLICY_VERSION || required_floor != AUTHORITY_POLICY_VERSION {
        return Err(AuthorityError::PolicyVersionUnsupported);
    }
    if version < required_floor {
        return Err(AuthorityError::PolicyBelowFloor);
    }
    Ok(())
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, AuthorityError> {
    let bytes =
        decode_exact_hex::<32>(encoded).ok_or(AuthorityError::A1VerificationKeyMalformed)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| AuthorityError::A1VerificationKeyMalformed)
}

fn verify_signature(
    key: &VerifyingKey,
    encoded_signature: &str,
    preimage: &[u8],
) -> Result<(), AuthorityError> {
    let signature_bytes = decode_exact_hex::<64>(encoded_signature)
        .ok_or(AuthorityError::V7CardinalityDispositionSignatureMalformed)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(preimage, &signature)
        .map_err(|_| AuthorityError::V7CardinalityDispositionSignatureInvalid)
}

fn decode_exact_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    if encoded.len() != N * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut decoded = [0_u8; N];
    hex::decode_to_slice(encoded, &mut decoded).ok()?;
    Some(decoded)
}

fn parse_exact(bytes: &[u8]) -> Result<V7CardinalityDispositionWire, AuthorityError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(AuthorityError::V7CardinalityDispositionMalformed);
    }
    let wire: V7CardinalityDispositionWire = serde_json::from_slice(bytes)
        .map_err(|_| AuthorityError::V7CardinalityDispositionMalformed)?;
    let canonical = canonical_json_bytes(&wire)
        .map_err(|_| AuthorityError::V7CardinalityDispositionNonCanonical)?;
    if canonical != bytes {
        return Err(AuthorityError::V7CardinalityDispositionNonCanonical);
    }
    Ok(wire)
}

fn disposition_digest(
    unsigned: &V7CardinalityDispositionUnsigned<'_>,
) -> Result<Sha256Digest, AuthorityError> {
    let canonical = canonical_json_bytes(unsigned).map_err(|_| AuthorityError::FramingOverflow)?;
    framed_digest(
        CARDINALITY_DISPOSITION_ID_DOMAIN,
        AUTHORITY_SCHEMA_VERSION,
        &[("canonical_unsigned_disposition", &canonical)],
    )
}

fn disposition_signature_preimage(
    wire: &V7CardinalityDispositionWire,
) -> Result<Vec<u8>, AuthorityError> {
    let canonical =
        canonical_json_bytes(&wire.unsigned()).map_err(|_| AuthorityError::FramingOverflow)?;
    framed_bytes(
        CARDINALITY_DISPOSITION_SIGNATURE_DOMAIN,
        AUTHORITY_SCHEMA_VERSION,
        &[
            (
                "disposition_digest",
                wire.disposition_digest.as_str().as_bytes(),
            ),
            ("canonical_unsigned_disposition", &canonical),
        ],
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct V7CardinalityDispositionWire {
    schema: String,
    schema_version: u16,
    source_schema_version: u32,
    disposition_digest: Sha256Digest,
    disposition: MigrationDisposition,
    genesis_identities: Vec<String>,
    source_logical_digest: Sha256Digest,
    old_root_state: OldRootState,
    domain: String,
    policy_version: u64,
    operator_authority_digest: Sha256Digest,
    operator_key_generation: u64,
    restore_declaration_digest: Option<Sha256Digest>,
    signature_algorithm: String,
    operator_signature: String,
}

#[derive(Serialize)]
struct V7CardinalityDispositionUnsigned<'a> {
    schema: &'a str,
    schema_version: u16,
    source_schema_version: u32,
    disposition: MigrationDisposition,
    genesis_identities: &'a [String],
    source_logical_digest: &'a Sha256Digest,
    old_root_state: &'a OldRootState,
    domain: &'a str,
    policy_version: u64,
    operator_authority_digest: &'a Sha256Digest,
    operator_key_generation: u64,
    restore_declaration_digest: Option<&'a Sha256Digest>,
    signature_algorithm: &'a str,
}

impl V7CardinalityDispositionWire {
    fn unsigned(&self) -> V7CardinalityDispositionUnsigned<'_> {
        V7CardinalityDispositionUnsigned {
            schema: &self.schema,
            schema_version: self.schema_version,
            source_schema_version: self.source_schema_version,
            disposition: self.disposition,
            genesis_identities: &self.genesis_identities,
            source_logical_digest: &self.source_logical_digest,
            old_root_state: &self.old_root_state,
            domain: &self.domain,
            policy_version: self.policy_version,
            operator_authority_digest: &self.operator_authority_digest,
            operator_key_generation: self.operator_key_generation,
            restore_declaration_digest: self.restore_declaration_digest.as_ref(),
            signature_algorithm: &self.signature_algorithm,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod fixture_access {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn wire(
        disposition: MigrationDisposition,
        genesis_identities: Vec<String>,
        source_logical_digest: Sha256Digest,
        old_root_state: OldRootState,
        domain: String,
        policy_version: u64,
        operator_authority_digest: Sha256Digest,
        operator_key_generation: u64,
        restore_declaration_digest: Option<Sha256Digest>,
        operator_signature: String,
    ) -> V7CardinalityDispositionWire {
        V7CardinalityDispositionWire {
            schema: V7_CARDINALITY_DISPOSITION_SCHEMA.to_owned(),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            source_schema_version: CARDINALITY_DISPOSITION_SOURCE_SCHEMA_VERSION,
            disposition_digest: nq_protocol::sha256_bytes(b"fixture placeholder"),
            disposition,
            genesis_identities,
            source_logical_digest,
            old_root_state,
            domain,
            policy_version,
            operator_authority_digest,
            operator_key_generation,
            restore_declaration_digest,
            signature_algorithm: ED25519_SIGNATURE_ALGORITHM.to_owned(),
            operator_signature,
        }
    }

    pub(crate) fn bytes(mut wire: V7CardinalityDispositionWire) -> Vec<u8> {
        wire.disposition_digest = disposition_digest(&wire.unsigned()).unwrap();
        canonical_json_bytes(&wire).unwrap()
    }

    pub(crate) fn signature_preimage(wire: &V7CardinalityDispositionWire) -> Vec<u8> {
        let mut wire = wire.clone();
        wire.disposition_digest = disposition_digest(&wire.unsigned()).unwrap();
        disposition_signature_preimage(&wire).unwrap()
    }

    pub(crate) fn set_signature(wire: &mut V7CardinalityDispositionWire, signature: String) {
        wire.operator_signature = signature;
    }
}
