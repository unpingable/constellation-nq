//! Refusal-total native authority-chain verification and resolution.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::Sha256Digest;

use crate::{
    ActivationContext, ActivationExpectations, ActivationRevocationRecord, AuthorityCut,
    AuthorityError, ControllingActivationSnapshot, ED25519_SIGNATURE_ALGORITHM,
    GenesisAuthorityCustody, MigrationDisposition, MigrationReceipt, MigrationReceiptBytes,
    OldRootState, OperatorAuthorityRecord, PresentedAuthorityRecord, PresentedAuthoritySet,
    RUNTIME_DEPENDENCY_ADMISSION_SCOPE, ResidentActivationRecord, ResolvedControllingActivation,
    RestartExpectations, VerificationBrand, VerifiedActivationRevocation,
    VerifiedOperatorAuthorityRotation, VerifiedResidentActivationSuccessor,
    brand::{ResolutionFields, VerifiedEventFields},
    digest_genesis_authority_custody, digest_presented_authority_set,
    records::{AUTHORITY_POLICY_VERSION, MAX_IDENTITY_BYTES},
};

/// Verifies an exact presented set and mints sealed establishment evidence
/// under the supplied fresh brand.
///
/// This proves validity over the presented set only.  Store-owned enumeration
/// and an in-transaction comparison with [`ResolvedControllingActivation::candidate_set_digest`]
/// remain mandatory.
///
/// # Errors
///
/// Refuses every malformed, cryptographically invalid, mismatched, incomplete,
/// forked, cyclic, revoked, expired, or non-unique presented chain.
pub fn verify_for_establishment<'id>(
    brand: &VerificationBrand<'id>,
    custody: &GenesisAuthorityCustody,
    presented: &PresentedAuthoritySet,
    migration_receipt: Option<&MigrationReceiptBytes>,
    expectations: &ActivationExpectations,
) -> Result<ResolvedControllingActivation<'id>, AuthorityError> {
    let fields = resolve_fields(
        custody,
        presented,
        migration_receipt,
        expectations,
        TipRequirement::UniqueLive,
    )?;
    Ok(ResolvedControllingActivation::new(fields, brand))
}

/// Resolves the exact Store-enumerated authority set for read-only restart.
///
/// The result is deliberately not establishment evidence and cannot be
/// converted into [`ResolvedControllingActivation`].
///
/// # Errors
///
/// Refuses every condition described by [`verify_for_establishment`].
pub fn resolve_for_restart(
    custody: &GenesisAuthorityCustody,
    presented: &PresentedAuthoritySet,
    migration_receipt: Option<&MigrationReceiptBytes>,
    expectations: &RestartExpectations,
) -> Result<ControllingActivationSnapshot, AuthorityError> {
    let effective = restart_expectations(expectations, migration_receipt)?;
    let fields = resolve_fields(
        custody,
        presented,
        migration_receipt,
        &effective,
        TipRequirement::UniqueLive,
    )?;
    if fields.chain_root_activation_digest != expectations.expected_chain_root_activation_digest {
        return Err(AuthorityError::ChainRootMismatch);
    }
    if fields.custody_digest != expectations.expected_custody_digest {
        return Err(AuthorityError::CustodyDigestMismatch);
    }
    let parsed = parse_authority(custody, presented)?;
    if !parsed
        .a2
        .contains_key(&expectations.expected_establishment_tip_digest)
    {
        return Err(AuthorityError::EstablishmentTipMismatch);
    }
    Ok(ControllingActivationSnapshot::new(fields))
}

fn restart_expectations(
    restart: &RestartExpectations,
    migration_receipt: Option<&MigrationReceiptBytes>,
) -> Result<ActivationExpectations, AuthorityError> {
    let migration = match restart.genesis_context {
        ActivationContext::FreshGenesis => {
            if restart.expected_migration_receipt_digest.is_some() || migration_receipt.is_some() {
                return Err(AuthorityError::UnexpectedMigrationReceipt);
            }
            None
        }
        ActivationContext::MigrationGenesis => {
            let expected_digest = restart
                .expected_migration_receipt_digest
                .as_ref()
                .ok_or(AuthorityError::MigrationReceiptRequired)?;
            let raw = migration_receipt.ok_or(AuthorityError::MigrationReceiptRequired)?;
            let retained = MigrationReceipt::from_canonical_bytes(raw.as_bytes())?;
            if retained.receipt_digest() != expected_digest {
                return Err(AuthorityError::MigrationReceiptDigestMismatch);
            }
            Some(crate::MigrationExpectations {
                old_root_state: retained.old_root_state().clone(),
                restore_proof_digest: retained.restore_proof_digest().cloned(),
            })
        }
        ActivationContext::Successor => return Err(AuthorityError::A2GenesisShapeMismatch),
    };
    Ok(ActivationExpectations {
        genesis_context: restart.genesis_context,
        expected_occurrence_id: Some(restart.expected_occurrence_id.clone()),
        resident_identity: restart.resident_identity.clone(),
        resident_generation: restart.resident_generation,
        host_role: restart.host_role.clone(),
        role_manifest_generation: restart.role_manifest_generation,
        trust_anchor_id: restart.trust_anchor_id.clone(),
        domain: restart.domain.clone(),
        policy_floor: restart.policy_floor,
        migration,
    })
}

/// Verifies one proposed Store-ledger A1 rotation against the complete current
/// presented set and returns a sealed, brand-bound append value.
///
/// # Errors
///
/// Refuses unless both the current and resulting chains pass every applicable
/// law and the proposed record is the one newly added record.
#[allow(clippy::too_many_arguments)]
pub fn verify_operator_authority_rotation<'id>(
    brand: &VerificationBrand<'id>,
    custody: &GenesisAuthorityCustody,
    current: &PresentedAuthoritySet,
    canonical_rotation: &[u8],
    migration_receipt: Option<&MigrationReceiptBytes>,
    expectations: &ActivationExpectations,
) -> Result<VerifiedOperatorAuthorityRotation<'id>, AuthorityError> {
    resolve_fields(
        custody,
        current,
        migration_receipt,
        expectations,
        TipRequirement::UniqueLive,
    )?;
    let parsed = OperatorAuthorityRecord::from_canonical_bytes(canonical_rotation)?;
    let digest = parsed.record_digest().clone();
    let resulting = with_added_record(
        current,
        PresentedAuthorityRecord::OperatorAuthorityRotation(canonical_rotation.to_vec()),
    );
    let fields = resolve_fields(
        custody,
        &resulting,
        migration_receipt,
        expectations,
        TipRequirement::UniqueLive,
    )?;
    Ok(VerifiedOperatorAuthorityRotation::new(
        VerifiedEventFields {
            canonical_bytes: canonical_rotation.to_vec(),
            record_digest: digest,
            resulting_candidate_set_digest: fields.candidate_set_digest,
        },
        brand,
    ))
}

/// Verifies one proposed Store-ledger A2 successor and returns a sealed,
/// brand-bound append value.
///
/// A successor is allowed to restore standing after a lawfully revoked or
/// cut-expired prior tip, but the resulting set must have one unique live tip.
///
/// # Errors
///
/// Refuses any invalid current structure, proposed successor, or resulting
/// authority state.
#[allow(clippy::too_many_arguments)]
pub fn verify_resident_activation_successor<'id>(
    brand: &VerificationBrand<'id>,
    custody: &GenesisAuthorityCustody,
    current: &PresentedAuthoritySet,
    canonical_successor: &[u8],
    migration_receipt: Option<&MigrationReceiptBytes>,
    expectations: &ActivationExpectations,
) -> Result<VerifiedResidentActivationSuccessor<'id>, AuthorityError> {
    resolve_fields(
        custody,
        current,
        migration_receipt,
        expectations,
        TipRequirement::AllowTerminalNonLive,
    )?;
    let parsed = ResidentActivationRecord::from_canonical_bytes(canonical_successor)?;
    let digest = parsed.activation_digest().clone();
    let resulting = with_added_record(
        current,
        PresentedAuthorityRecord::ResidentActivationSuccessor(canonical_successor.to_vec()),
    );
    let fields = resolve_fields(
        custody,
        &resulting,
        migration_receipt,
        expectations,
        TipRequirement::UniqueLive,
    )?;
    Ok(VerifiedResidentActivationSuccessor::new(
        VerifiedEventFields {
            canonical_bytes: canonical_successor.to_vec(),
            record_digest: digest,
            resulting_candidate_set_digest: fields.candidate_set_digest,
        },
        brand,
    ))
}

/// Verifies one proposed prospective revocation and returns a sealed,
/// brand-bound append value.
///
/// A lawful revocation may intentionally leave no live activation.  The
/// current state must resolve live; the resulting structure and revocation
/// must verify completely, but only restart/establishment require a live tip.
///
/// # Errors
///
/// Refuses any invalid current structure, revocation, or resulting chain.
#[allow(clippy::too_many_arguments)]
pub fn verify_activation_revocation<'id>(
    brand: &VerificationBrand<'id>,
    custody: &GenesisAuthorityCustody,
    current: &PresentedAuthoritySet,
    canonical_revocation: &[u8],
    migration_receipt: Option<&MigrationReceiptBytes>,
    expectations: &ActivationExpectations,
) -> Result<VerifiedActivationRevocation<'id>, AuthorityError> {
    resolve_fields(
        custody,
        current,
        migration_receipt,
        expectations,
        TipRequirement::UniqueLive,
    )?;
    let parsed = ActivationRevocationRecord::from_canonical_bytes(canonical_revocation)?;
    let digest = parsed.record_digest().clone();
    let resulting = with_added_record(
        current,
        PresentedAuthorityRecord::ActivationRevocation(canonical_revocation.to_vec()),
    );
    let fields = resolve_fields(
        custody,
        &resulting,
        migration_receipt,
        expectations,
        TipRequirement::AllowTerminalNonLive,
    )?;
    Ok(VerifiedActivationRevocation::new(
        VerifiedEventFields {
            canonical_bytes: canonical_revocation.to_vec(),
            record_digest: digest,
            resulting_candidate_set_digest: fields.candidate_set_digest,
        },
        brand,
    ))
}

fn with_added_record(
    current: &PresentedAuthoritySet,
    record: PresentedAuthorityRecord,
) -> PresentedAuthoritySet {
    let mut records = current.records().to_vec();
    records.push(record);
    PresentedAuthoritySet::new(records)
}

#[derive(Clone, Copy)]
enum TipRequirement {
    UniqueLive,
    AllowTerminalNonLive,
}

struct ParsedAuthority {
    genesis_a1_digest: Sha256Digest,
    genesis_a2_digest: Sha256Digest,
    a1: BTreeMap<Sha256Digest, OperatorAuthorityRecord>,
    a2: BTreeMap<Sha256Digest, ResidentActivationRecord>,
    revocations: BTreeMap<Sha256Digest, ActivationRevocationRecord>,
}

fn resolve_fields(
    custody: &GenesisAuthorityCustody,
    presented: &PresentedAuthoritySet,
    migration_receipt_bytes: Option<&MigrationReceiptBytes>,
    expectations: &ActivationExpectations,
    tip_requirement: TipRequirement,
) -> Result<ResolutionFields, AuthorityError> {
    validate_expectations(expectations, migration_receipt_bytes)?;
    let parsed = parse_authority(custody, presented)?;
    let genesis_a1 = parsed
        .a1
        .get(&parsed.genesis_a1_digest)
        .ok_or(AuthorityError::A1Gap)?;
    let genesis_a2 = parsed
        .a2
        .get(&parsed.genesis_a2_digest)
        .ok_or(AuthorityError::ActivationGap)?;

    let verifying_keys = verify_a1_chain(&parsed, expectations)?;
    verify_activations(&parsed, expectations, &verifying_keys)?;
    verify_revocations(&parsed, expectations, &verifying_keys)?;
    let event_order = verify_global_event_chain(&parsed)?;
    let event_positions: BTreeMap<_, _> = event_order
        .iter()
        .enumerate()
        .map(|(position, digest)| (digest.clone(), position))
        .collect();
    verify_event_temporal_correspondence(&parsed, &event_positions)?;
    let activation_order = verify_activation_chain(&parsed)?;

    let migration_receipt = verify_migration(
        migration_receipt_bytes,
        expectations,
        genesis_a2,
        &parsed,
        &verifying_keys,
        &event_positions,
    )?;

    let terminal_event_digest = event_order
        .last()
        .ok_or(AuthorityError::AuthorityEventGap)?;
    let terminal_cut = event_cut(&parsed, terminal_event_digest)?.clone();
    let tip_digest = select_structural_tip(&activation_order)?;
    let tip = parsed
        .a2
        .get(tip_digest)
        .ok_or(AuthorityError::NoLiveActivation)?;
    let revoked = parsed
        .revocations
        .values()
        .any(|record| record.target_activation_digest() == tip.activation_digest());
    let expired = tip
        .expiry_cut()
        .is_some_and(|expiry| terminal_cut.sequence() >= expiry);
    match (tip_requirement, revoked, expired) {
        (TipRequirement::UniqueLive, true, _) => {
            return Err(AuthorityError::ControllingActivationRevoked);
        }
        (TipRequirement::UniqueLive, false, true) => {
            return Err(AuthorityError::ControllingActivationExpired);
        }
        (TipRequirement::AllowTerminalNonLive, _, _)
        | (TipRequirement::UniqueLive, false, false) => {}
    }

    let candidate_set_digest = digest_presented_authority_set(presented)?;
    let custody_digest = digest_genesis_authority_custody(custody)?;
    let (migration_receipt_digest, migration_receipt_canonical_bytes) =
        migration_receipt.map_or((None, None), |receipt| {
            (
                Some(receipt.receipt_digest().clone()),
                Some(receipt.canonical_bytes().to_vec()),
            )
        });

    Ok(ResolutionFields {
        occurrence_id: genesis_a2.occurrence_id().to_owned(),
        domain: genesis_a2.domain().to_owned(),
        chain_root_activation_digest: genesis_a2.activation_digest().clone(),
        controlling_tip_activation_digest: tip.activation_digest().clone(),
        trust_anchor_id: genesis_a2.trust_anchor_id().clone(),
        genesis_operator_authority_digest: genesis_a1.record_digest().clone(),
        genesis_operator_key_generation: genesis_a1.key_generation(),
        resident_identity: tip.resident_identity().to_owned(),
        resident_generation: tip.resident_generation(),
        host_role: tip.host_role().to_owned(),
        role_manifest_generation: tip.role_manifest_generation(),
        policy_version: tip.policy_version(),
        verification_cut: terminal_cut,
        custody_digest,
        candidate_set_digest,
        genesis_context: genesis_a2.context(),
        migration_receipt_digest,
        migration_receipt_canonical_bytes,
    })
}

fn validate_expectations(
    expectations: &ActivationExpectations,
    migration_receipt: Option<&MigrationReceiptBytes>,
) -> Result<(), AuthorityError> {
    validate_identity(&expectations.resident_identity)?;
    validate_identity(&expectations.host_role)?;
    validate_identity(&expectations.domain)?;
    validate_generation(expectations.resident_generation)?;
    validate_generation(expectations.role_manifest_generation)?;
    validate_policy(expectations.policy_floor, expectations.policy_floor)?;
    if let Some(occurrence) = &expectations.expected_occurrence_id {
        validate_identity(occurrence)?;
    }
    match expectations.genesis_context {
        ActivationContext::FreshGenesis => {
            if expectations.migration.is_some() || migration_receipt.is_some() {
                return Err(AuthorityError::UnexpectedMigrationReceipt);
            }
        }
        ActivationContext::MigrationGenesis => {
            if expectations.expected_occurrence_id.is_none()
                || expectations.migration.is_none()
                || migration_receipt.is_none()
            {
                return Err(AuthorityError::MigrationReceiptRequired);
            }
        }
        ActivationContext::Successor => return Err(AuthorityError::A2GenesisShapeMismatch),
    }
    Ok(())
}

fn parse_authority(
    custody: &GenesisAuthorityCustody,
    presented: &PresentedAuthoritySet,
) -> Result<ParsedAuthority, AuthorityError> {
    let genesis_a1 = OperatorAuthorityRecord::from_canonical_bytes(custody.genesis_a1_bytes())?;
    let genesis_a1_digest = genesis_a1.record_digest().clone();
    let genesis_a2 = ResidentActivationRecord::from_canonical_bytes(custody.genesis_a2_bytes())?;
    let genesis_a2_digest = genesis_a2.activation_digest().clone();
    let mut a1 = BTreeMap::from([(genesis_a1_digest.clone(), genesis_a1)]);
    let mut a2 = BTreeMap::from([(genesis_a2_digest.clone(), genesis_a2)]);
    let mut revocations = BTreeMap::new();

    for candidate in presented.records() {
        match candidate {
            PresentedAuthorityRecord::OperatorAuthorityRotation(bytes) => {
                let record = OperatorAuthorityRecord::from_canonical_bytes(bytes)?;
                if a1.insert(record.record_digest().clone(), record).is_some() {
                    return Err(AuthorityError::A1DuplicateIdentity);
                }
            }
            PresentedAuthorityRecord::ResidentActivationSuccessor(bytes) => {
                let record = ResidentActivationRecord::from_canonical_bytes(bytes)?;
                if a2
                    .insert(record.activation_digest().clone(), record)
                    .is_some()
                {
                    return Err(AuthorityError::A2DuplicateIdentity);
                }
            }
            PresentedAuthorityRecord::ActivationRevocation(bytes) => {
                let record = ActivationRevocationRecord::from_canonical_bytes(bytes)?;
                if revocations
                    .insert(record.record_digest().clone(), record)
                    .is_some()
                {
                    return Err(AuthorityError::AuthorityEventDuplicateIdentity);
                }
            }
        }
    }
    Ok(ParsedAuthority {
        genesis_a1_digest,
        genesis_a2_digest,
        a1,
        a2,
        revocations,
    })
}

fn verify_a1_chain(
    parsed: &ParsedAuthority,
    expectations: &ActivationExpectations,
) -> Result<BTreeMap<Sha256Digest, VerifyingKey>, AuthorityError> {
    let genesis = parsed
        .a1
        .get(&parsed.genesis_a1_digest)
        .ok_or(AuthorityError::A1Gap)?;
    if genesis.predecessor_a1_digest().is_some()
        || genesis.predecessor_signature_hex().is_some()
        || genesis.cut().predecessor_event_digest().is_some()
    {
        return Err(AuthorityError::A1GenesisShapeMismatch);
    }
    let mut keys = BTreeMap::new();
    for record in parsed.a1.values() {
        validate_a1_common(record, expectations)?;
        let key = decode_verifying_key(record.verification_key_hex())?;
        keys.insert(record.record_digest().clone(), key);
    }

    for record in parsed.a1.values() {
        if record.record_digest() == &parsed.genesis_a1_digest {
            continue;
        }
        let predecessor_digest = record
            .predecessor_a1_digest()
            .ok_or(AuthorityError::A1RotationShapeMismatch)?;
        let signature = record
            .predecessor_signature_hex()
            .ok_or(AuthorityError::A1RotationShapeMismatch)?;
        let predecessor = parsed
            .a1
            .get(predecessor_digest)
            .ok_or(AuthorityError::A1Gap)?;
        if record.operator_principal() != predecessor.operator_principal() {
            return Err(AuthorityError::A1PrincipalMismatch);
        }
        if record.domain() != predecessor.domain()
            || record.permitted_scope() != predecessor.permitted_scope()
        {
            return Err(AuthorityError::DomainMismatch);
        }
        if predecessor.key_generation().checked_add(1) != Some(record.key_generation()) {
            return Err(AuthorityError::A1KeyGenerationMismatch);
        }
        if record.cut().sequence() <= predecessor.cut().sequence() {
            return Err(AuthorityError::A1CutNotLater);
        }
        if record.policy_floor() < predecessor.policy_floor() {
            return Err(AuthorityError::PolicyFloorMismatch);
        }
        let predecessor_key = keys.get(predecessor_digest).ok_or(AuthorityError::A1Gap)?;
        verify_signature(
            predecessor_key,
            signature,
            &record.rotation_signature_preimage()?,
            AuthorityError::A1SignatureMalformed,
            AuthorityError::A1SignatureInvalid,
        )?;
    }

    let nodes: BTreeMap<_, _> = parsed
        .a1
        .values()
        .map(|record| {
            (
                record.record_digest().clone(),
                LinkNode {
                    predecessor: record.predecessor_a1_digest().cloned(),
                    sequence: record.cut().sequence(),
                },
            )
        })
        .collect();
    walk_linked_chain(&nodes, &parsed.genesis_a1_digest, ChainKind::A1)?;
    Ok(keys)
}

fn validate_a1_common(
    record: &OperatorAuthorityRecord,
    expectations: &ActivationExpectations,
) -> Result<(), AuthorityError> {
    validate_identity(record.operator_principal())?;
    validate_generation(record.key_generation())?;
    record.cut().validate_integer()?;
    if record.signature_algorithm() != ED25519_SIGNATURE_ALGORITHM {
        return Err(AuthorityError::A1SignatureAlgorithmUnsupported);
    }
    if record.domain() != expectations.domain {
        return Err(AuthorityError::DomainMismatch);
    }
    if record.permitted_scope() != RUNTIME_DEPENDENCY_ADMISSION_SCOPE {
        return Err(AuthorityError::ScopeMismatch);
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

fn verify_global_event_chain(
    parsed: &ParsedAuthority,
) -> Result<Vec<Sha256Digest>, AuthorityError> {
    let mut nodes = BTreeMap::new();
    for record in parsed.a1.values() {
        insert_event_node(&mut nodes, record.record_digest(), record.cut())?;
    }
    for record in parsed.a2.values() {
        insert_event_node(&mut nodes, record.activation_digest(), record.cut())?;
    }
    for record in parsed.revocations.values() {
        insert_event_node(&mut nodes, record.record_digest(), record.cut())?;
    }
    let order = walk_linked_chain(&nodes, &parsed.genesis_a1_digest, ChainKind::AuthorityEvent)?;
    if order.get(1) != Some(&parsed.genesis_a2_digest) {
        return Err(AuthorityError::A2GenesisShapeMismatch);
    }
    Ok(order)
}

fn insert_event_node(
    nodes: &mut BTreeMap<Sha256Digest, LinkNode>,
    digest: &Sha256Digest,
    cut: &AuthorityCut,
) -> Result<(), AuthorityError> {
    cut.validate_integer()?;
    if nodes
        .insert(
            digest.clone(),
            LinkNode {
                predecessor: cut.predecessor_event_digest().cloned(),
                sequence: cut.sequence(),
            },
        )
        .is_some()
    {
        return Err(AuthorityError::AuthorityEventDuplicateIdentity);
    }
    Ok(())
}

fn verify_activations(
    parsed: &ParsedAuthority,
    expectations: &ActivationExpectations,
    keys: &BTreeMap<Sha256Digest, VerifyingKey>,
) -> Result<(), AuthorityError> {
    let genesis = parsed
        .a2
        .get(&parsed.genesis_a2_digest)
        .ok_or(AuthorityError::ActivationGap)?;
    if genesis.context() != expectations.genesis_context
        || genesis.context() == ActivationContext::Successor
        || genesis.predecessor_activation_digest().is_some()
        || genesis.cut().predecessor_event_digest() != Some(&parsed.genesis_a1_digest)
    {
        return Err(AuthorityError::A2GenesisShapeMismatch);
    }
    if let Some(expected_occurrence) = &expectations.expected_occurrence_id
        && genesis.occurrence_id() != expected_occurrence
    {
        return Err(AuthorityError::OccurrenceMismatch);
    }
    for record in parsed.a2.values() {
        if record.activation_digest() != &parsed.genesis_a2_digest
            && (record.context() != ActivationContext::Successor
                || record.predecessor_activation_digest().is_none())
        {
            return Err(AuthorityError::A2SuccessorShapeMismatch);
        }
        validate_activation_tuple(record, genesis, expectations)?;
        let named_a1 = parsed
            .a1
            .get(record.operator_authority_digest())
            .ok_or(AuthorityError::A1IdentityMismatch)?;
        if named_a1.key_generation() != record.operator_key_generation() {
            return Err(AuthorityError::A1GenerationMismatch);
        }
        let key = keys
            .get(record.operator_authority_digest())
            .ok_or(AuthorityError::A1IdentityMismatch)?;
        verify_signature(
            key,
            record.operator_signature_hex(),
            &record.signature_preimage()?,
            AuthorityError::A2SignatureMalformed,
            AuthorityError::A2SignatureInvalid,
        )?;
    }
    Ok(())
}

fn validate_activation_tuple(
    record: &ResidentActivationRecord,
    genesis: &ResidentActivationRecord,
    expectations: &ActivationExpectations,
) -> Result<(), AuthorityError> {
    validate_identity(record.occurrence_id())?;
    validate_identity(record.resident_identity())?;
    validate_identity(record.host_role())?;
    validate_generation(record.resident_generation())?;
    validate_generation(record.role_manifest_generation())?;
    record.cut().validate_integer()?;
    if record.signature_algorithm() != ED25519_SIGNATURE_ALGORITHM {
        return Err(AuthorityError::A2SignatureAlgorithmUnsupported);
    }
    if record.scope() != RUNTIME_DEPENDENCY_ADMISSION_SCOPE {
        return Err(AuthorityError::ScopeMismatch);
    }
    if record.occurrence_id() != genesis.occurrence_id() {
        return Err(AuthorityError::OccurrenceMismatch);
    }
    if record.domain() != genesis.domain() || record.domain() != expectations.domain {
        return Err(AuthorityError::DomainMismatch);
    }
    if record.trust_anchor_id() != genesis.trust_anchor_id()
        || record.trust_anchor_id() != &expectations.trust_anchor_id
    {
        return Err(AuthorityError::AnchorMismatch);
    }
    if record.resident_identity() != expectations.resident_identity {
        return Err(AuthorityError::ResidentMismatch);
    }
    if record.resident_generation() != expectations.resident_generation {
        return Err(AuthorityError::ResidentGenerationMismatch);
    }
    if record.host_role() != expectations.host_role {
        return Err(AuthorityError::RoleMismatch);
    }
    if record.role_manifest_generation() != expectations.role_manifest_generation {
        return Err(AuthorityError::RoleManifestGenerationMismatch);
    }
    validate_policy(record.policy_version(), expectations.policy_floor)?;
    if let Some(expiry) = record.expiry_cut()
        && (expiry > 9_007_199_254_740_991 || expiry <= record.cut().sequence())
    {
        return Err(AuthorityError::ExpiryCutInvalid);
    }
    Ok(())
}

fn verify_revocations(
    parsed: &ParsedAuthority,
    expectations: &ActivationExpectations,
    keys: &BTreeMap<Sha256Digest, VerifyingKey>,
) -> Result<(), AuthorityError> {
    let genesis = parsed
        .a2
        .get(&parsed.genesis_a2_digest)
        .ok_or(AuthorityError::ActivationGap)?;
    for record in parsed.revocations.values() {
        let target = parsed
            .a2
            .get(record.target_activation_digest())
            .ok_or(AuthorityError::RevocationTargetMissing)?;
        validate_identity(record.occurrence_id())?;
        record.cut().validate_integer()?;
        if record.signature_algorithm() != ED25519_SIGNATURE_ALGORITHM {
            return Err(AuthorityError::RevocationSignatureAlgorithmUnsupported);
        }
        if record.scope() != RUNTIME_DEPENDENCY_ADMISSION_SCOPE {
            return Err(AuthorityError::ScopeMismatch);
        }
        if record.occurrence_id() != genesis.occurrence_id() {
            return Err(AuthorityError::OccurrenceMismatch);
        }
        if record.domain() != genesis.domain() || record.domain() != expectations.domain {
            return Err(AuthorityError::DomainMismatch);
        }
        if record.trust_anchor_id() != genesis.trust_anchor_id()
            || record.trust_anchor_id() != &expectations.trust_anchor_id
        {
            return Err(AuthorityError::AnchorMismatch);
        }
        validate_policy(record.policy_version(), expectations.policy_floor)?;
        if record.cut().sequence() <= target.cut().sequence() {
            return Err(AuthorityError::RevocationNotProspective);
        }
        let named_a1 = parsed
            .a1
            .get(record.operator_authority_digest())
            .ok_or(AuthorityError::A1IdentityMismatch)?;
        if named_a1.key_generation() != record.operator_key_generation() {
            return Err(AuthorityError::A1GenerationMismatch);
        }
        let key = keys
            .get(record.operator_authority_digest())
            .ok_or(AuthorityError::A1IdentityMismatch)?;
        verify_signature(
            key,
            record.operator_signature_hex(),
            &record.signature_preimage()?,
            AuthorityError::RevocationSignatureMalformed,
            AuthorityError::RevocationSignatureInvalid,
        )?;
    }
    Ok(())
}

fn verify_event_temporal_correspondence(
    parsed: &ParsedAuthority,
    event_positions: &BTreeMap<Sha256Digest, usize>,
) -> Result<(), AuthorityError> {
    for record in parsed.a2.values() {
        ensure_a1_precedes_event(
            event_positions,
            record.operator_authority_digest(),
            record.activation_digest(),
        )?;
    }
    for record in parsed.revocations.values() {
        ensure_a1_precedes_event(
            event_positions,
            record.operator_authority_digest(),
            record.record_digest(),
        )?;
        let target_position = event_positions
            .get(record.target_activation_digest())
            .ok_or(AuthorityError::AuthorityEventGap)?;
        let revocation_position = event_positions
            .get(record.record_digest())
            .ok_or(AuthorityError::AuthorityEventGap)?;
        if revocation_position <= target_position {
            return Err(AuthorityError::RevocationNotProspective);
        }
    }
    Ok(())
}

fn verify_activation_chain(parsed: &ParsedAuthority) -> Result<Vec<Sha256Digest>, AuthorityError> {
    let nodes: BTreeMap<_, _> = parsed
        .a2
        .values()
        .map(|record| {
            (
                record.activation_digest().clone(),
                LinkNode {
                    predecessor: record.predecessor_activation_digest().cloned(),
                    sequence: record.cut().sequence(),
                },
            )
        })
        .collect();
    walk_linked_chain(&nodes, &parsed.genesis_a2_digest, ChainKind::Activation)
}

fn verify_migration(
    receipt_bytes: Option<&MigrationReceiptBytes>,
    expectations: &ActivationExpectations,
    genesis_a2: &ResidentActivationRecord,
    parsed: &ParsedAuthority,
    keys: &BTreeMap<Sha256Digest, VerifyingKey>,
    event_positions: &BTreeMap<Sha256Digest, usize>,
) -> Result<Option<MigrationReceipt>, AuthorityError> {
    match expectations.genesis_context {
        ActivationContext::FreshGenesis => {
            if receipt_bytes.is_some() {
                return Err(AuthorityError::UnexpectedMigrationReceipt);
            }
            Ok(None)
        }
        ActivationContext::Successor => Err(AuthorityError::A2GenesisShapeMismatch),
        ActivationContext::MigrationGenesis => {
            let raw = receipt_bytes.ok_or(AuthorityError::MigrationReceiptRequired)?;
            let expected = expectations
                .migration
                .as_ref()
                .ok_or(AuthorityError::MigrationReceiptRequired)?;
            let receipt = MigrationReceipt::from_canonical_bytes(raw.as_bytes())?;
            if receipt.signature_algorithm() != ED25519_SIGNATURE_ALGORITHM {
                return Err(AuthorityError::MigrationReceiptSignatureAlgorithmUnsupported);
            }
            if receipt.disposition() != MigrationDisposition::Accepted {
                return Err(AuthorityError::MigrationDispositionMismatch);
            }
            if receipt.occurrence_id() != genesis_a2.occurrence_id() {
                return Err(AuthorityError::OccurrenceMismatch);
            }
            if receipt.domain() != genesis_a2.domain() || receipt.domain() != expectations.domain {
                return Err(AuthorityError::DomainMismatch);
            }
            if receipt.new_chain_root_activation_digest() != genesis_a2.activation_digest() {
                return Err(AuthorityError::MigrationActivationMismatch);
            }
            if receipt.new_trust_anchor_id() != genesis_a2.trust_anchor_id()
                || receipt.new_trust_anchor_id() != &expectations.trust_anchor_id
            {
                return Err(AuthorityError::AnchorMismatch);
            }
            if receipt.old_root_state() != &expected.old_root_state {
                return Err(AuthorityError::MigrationOldRootMismatch);
            }
            if let OldRootState::Rooted { trust_anchor_id } = receipt.old_root_state()
                && trust_anchor_id != genesis_a2.trust_anchor_id()
            {
                return Err(AuthorityError::MigrationOldRootMismatch);
            }
            if receipt.restore_proof_digest() != expected.restore_proof_digest.as_ref() {
                return Err(AuthorityError::RestoreProofMismatch);
            }
            validate_policy(receipt.policy_version(), expectations.policy_floor)?;
            receipt.cut().validate_integer()?;
            if receipt.cut().sequence() <= genesis_a2.cut().sequence()
                || receipt.cut().predecessor_event_digest() != Some(genesis_a2.activation_digest())
            {
                return Err(AuthorityError::AuthorityCutNotLater);
            }
            let named_a1 = parsed
                .a1
                .get(receipt.operator_authority_digest())
                .ok_or(AuthorityError::A1IdentityMismatch)?;
            if named_a1.key_generation() != receipt.operator_key_generation() {
                return Err(AuthorityError::A1GenerationMismatch);
            }
            let a1_position = event_positions
                .get(named_a1.record_digest())
                .ok_or(AuthorityError::A1IdentityMismatch)?;
            let root_position = event_positions
                .get(genesis_a2.activation_digest())
                .ok_or(AuthorityError::AuthorityEventGap)?;
            if a1_position >= root_position {
                return Err(AuthorityError::A1NotYetEffective);
            }
            let key = keys
                .get(receipt.operator_authority_digest())
                .ok_or(AuthorityError::A1IdentityMismatch)?;
            verify_signature(
                key,
                receipt.operator_signature_hex(),
                &receipt.signature_preimage()?,
                AuthorityError::MigrationReceiptSignatureMalformed,
                AuthorityError::MigrationReceiptSignatureInvalid,
            )?;
            Ok(Some(receipt))
        }
    }
}

fn ensure_a1_precedes_event(
    positions: &BTreeMap<Sha256Digest, usize>,
    a1: &Sha256Digest,
    event: &Sha256Digest,
) -> Result<(), AuthorityError> {
    let a1_position = positions
        .get(a1)
        .ok_or(AuthorityError::A1IdentityMismatch)?;
    let event_position = positions
        .get(event)
        .ok_or(AuthorityError::AuthorityEventGap)?;
    if a1_position >= event_position {
        return Err(AuthorityError::A1NotYetEffective);
    }
    Ok(())
}

fn event_cut<'a>(
    parsed: &'a ParsedAuthority,
    digest: &Sha256Digest,
) -> Result<&'a AuthorityCut, AuthorityError> {
    if let Some(record) = parsed.a1.get(digest) {
        return Ok(record.cut());
    }
    if let Some(record) = parsed.a2.get(digest) {
        return Ok(record.cut());
    }
    parsed
        .revocations
        .get(digest)
        .map(ActivationRevocationRecord::cut)
        .ok_or(AuthorityError::AuthorityEventGap)
}

#[derive(Clone)]
struct LinkNode {
    predecessor: Option<Sha256Digest>,
    sequence: u64,
}

#[derive(Clone, Copy)]
enum ChainKind {
    A1,
    Activation,
    AuthorityEvent,
}

fn walk_linked_chain(
    nodes: &BTreeMap<Sha256Digest, LinkNode>,
    root: &Sha256Digest,
    kind: ChainKind,
) -> Result<Vec<Sha256Digest>, AuthorityError> {
    let root_node = nodes.get(root).ok_or_else(|| chain_gap(kind))?;
    if root_node.predecessor.is_some() {
        return Err(chain_gap(kind));
    }
    // A cryptographic digest cycle is not practically constructible, but the
    // structural resolver must still have an explicit refusal branch rather
    // than relying on a coincident cut-order failure.
    if graph_has_cycle(nodes) {
        return Err(chain_cycle(kind));
    }
    let mut cuts = BTreeMap::new();
    let mut successors = BTreeMap::new();
    for (digest, node) in nodes {
        if cuts.insert(node.sequence, digest).is_some() {
            return Err(match kind {
                ChainKind::A1 => AuthorityError::A1CutNotLater,
                ChainKind::Activation | ChainKind::AuthorityEvent => {
                    AuthorityError::AuthorityCutCollision
                }
            });
        }
        if digest == root {
            continue;
        }
        let predecessor = node.predecessor.as_ref().ok_or_else(|| chain_gap(kind))?;
        let predecessor_node = nodes.get(predecessor).ok_or_else(|| chain_gap(kind))?;
        if node.sequence <= predecessor_node.sequence {
            return Err(chain_not_later(kind));
        }
        if successors
            .insert(predecessor.clone(), digest.clone())
            .is_some()
        {
            return Err(chain_fork(kind));
        }
    }
    let mut order = Vec::with_capacity(nodes.len());
    let mut visited = BTreeSet::new();
    let mut current = root.clone();
    loop {
        if !visited.insert(current.clone()) {
            return Err(chain_cycle(kind));
        }
        order.push(current.clone());
        let Some(next) = successors.get(&current) else {
            break;
        };
        current = next.clone();
    }
    if visited.len() != nodes.len() {
        return Err(chain_gap(kind));
    }
    Ok(order)
}

fn graph_has_cycle(nodes: &BTreeMap<Sha256Digest, LinkNode>) -> bool {
    for start in nodes.keys() {
        let mut path = BTreeSet::new();
        let mut current = Some(start);
        while let Some(digest) = current {
            if !path.insert(digest) {
                return true;
            }
            current = nodes.get(digest).and_then(|node| node.predecessor.as_ref());
        }
    }
    false
}

const fn chain_gap(kind: ChainKind) -> AuthorityError {
    match kind {
        ChainKind::A1 => AuthorityError::A1Gap,
        ChainKind::Activation => AuthorityError::ActivationGap,
        ChainKind::AuthorityEvent => AuthorityError::AuthorityEventGap,
    }
}

const fn chain_fork(kind: ChainKind) -> AuthorityError {
    match kind {
        ChainKind::A1 => AuthorityError::A1Fork,
        ChainKind::Activation => AuthorityError::ActivationFork,
        ChainKind::AuthorityEvent => AuthorityError::AuthorityEventFork,
    }
}

const fn chain_cycle(kind: ChainKind) -> AuthorityError {
    match kind {
        ChainKind::A1 => AuthorityError::A1Cycle,
        ChainKind::Activation => AuthorityError::ActivationCycle,
        ChainKind::AuthorityEvent => AuthorityError::AuthorityEventCycle,
    }
}

const fn chain_not_later(kind: ChainKind) -> AuthorityError {
    match kind {
        ChainKind::A1 => AuthorityError::A1CutNotLater,
        ChainKind::Activation | ChainKind::AuthorityEvent => AuthorityError::AuthorityCutNotLater,
    }
}

fn select_structural_tip(order: &[Sha256Digest]) -> Result<&Sha256Digest, AuthorityError> {
    let tips: Vec<_> = order.last().into_iter().collect();
    select_unique_tip(&tips)
}

fn select_unique_tip<'a>(tips: &[&'a Sha256Digest]) -> Result<&'a Sha256Digest, AuthorityError> {
    match tips {
        [] => Err(AuthorityError::NoLiveActivation),
        [tip] => Ok(*tip),
        _ => Err(AuthorityError::MultipleLiveActivations),
    }
}

fn validate_identity(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
        return Err(AuthorityError::IdentityMalformed);
    }
    Ok(())
}

fn validate_generation(value: u64) -> Result<(), AuthorityError> {
    if value == 0 || value > 9_007_199_254_740_991 {
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
    malformed: AuthorityError,
    invalid: AuthorityError,
) -> Result<(), AuthorityError> {
    let signature_bytes = decode_exact_hex::<64>(encoded_signature).ok_or(malformed)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(preimage, &signature).map_err(|_| invalid)
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

#[cfg(test)]
mod structural_tests {
    use nq_protocol::sha256_bytes;

    use super::*;

    fn id(label: &str) -> Sha256Digest {
        sha256_bytes(label.as_bytes())
    }

    #[test]
    fn private_cycle_branch_refuses_even_without_constructible_signed_cycle() {
        let root = id("root");
        let left = id("left");
        let right = id("right");
        let nodes = BTreeMap::from([
            (
                root.clone(),
                LinkNode {
                    predecessor: None,
                    sequence: 1,
                },
            ),
            (
                left.clone(),
                LinkNode {
                    predecessor: Some(right.clone()),
                    sequence: 2,
                },
            ),
            (
                right,
                LinkNode {
                    predecessor: Some(left),
                    sequence: 3,
                },
            ),
        ]);
        assert_eq!(
            walk_linked_chain(&nodes, &root, ChainKind::Activation),
            Err(AuthorityError::ActivationCycle)
        );
    }

    #[test]
    fn private_multiple_tip_branch_refuses_without_tie_breaking() {
        let left = id("left");
        let right = id("right");
        assert_eq!(
            select_unique_tip(&[&left, &right]),
            Err(AuthorityError::MultipleLiveActivations)
        );
    }

    #[test]
    fn private_fork_branch_refuses_without_arrival_order_selection() {
        let root = id("root");
        let left = id("left");
        let right = id("right");
        let nodes = BTreeMap::from([
            (
                root.clone(),
                LinkNode {
                    predecessor: None,
                    sequence: 1,
                },
            ),
            (
                left,
                LinkNode {
                    predecessor: Some(root.clone()),
                    sequence: 2,
                },
            ),
            (
                right,
                LinkNode {
                    predecessor: Some(root.clone()),
                    sequence: 3,
                },
            ),
        ]);
        assert_eq!(
            walk_linked_chain(&nodes, &root, ChainKind::AuthorityEvent),
            Err(AuthorityError::AuthorityEventFork)
        );
    }
}
