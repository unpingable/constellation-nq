//! Deterministic raw authority carriers for tests and qualification.
//!
//! This module is absent from the default production surface.  It can create
//! and sign raw native records only; it exposes no verification brand, sealed
//! establishment evidence, verified event, writer session, or unchecked
//! authority constructor.

use ed25519_dalek::{Signer as _, SigningKey};
use nq_protocol::{Sha256Digest, sha256_bytes};

use crate::{
    ActivationContext, ActivationExpectations, GenesisAuthorityCustody, MigrationExpectations,
    MigrationReceipt, MigrationReceiptBytes, OldRootState, PresentedAuthorityRecord,
    PresentedAuthoritySet, ResidentActivationRecord, RestartExpectations,
    V7CardinalityDispositionBytes,
    cardinality::fixture_access::{
        bytes as cardinality_bytes, set_signature as set_cardinality_signature,
        signature_preimage as cardinality_signature_preimage, wire as cardinality_wire,
    },
    records::fixture_access::{
        a1_bytes, a1_digest_for, a1_signature_preimage_for, a1_wire, a2_bytes, a2_digest_for,
        a2_signature_preimage_for, a2_wire, cut, migration_bytes, migration_digest_for,
        migration_signature_preimage_for, migration_wire, revocation_bytes, revocation_digest_for,
        revocation_signature_preimage_for, revocation_wire, set_a1_signature, set_a2_signature,
        set_migration_disposition, set_migration_signature, set_revocation_anchor,
        set_revocation_signature,
    },
};

/// Deterministic fixture occurrence identity.
pub const FIXTURE_OCCURRENCE_ID: &str = "store-occurrence/operator-minted";
/// Deterministic fixture authority domain.
pub const FIXTURE_DOMAIN: &str = "runtime/backend";
/// Deterministic fixture resident identity.
pub const FIXTURE_RESIDENT_ID: &str = "resident/node-a";
/// Deterministic fixture host role.
pub const FIXTURE_HOST_ROLE: &str = "host-role/runtime";
/// Deterministic fixture resident generation.
pub const FIXTURE_RESIDENT_GENERATION: u64 = 7;
/// Deterministic fixture role-manifest generation.
pub const FIXTURE_ROLE_MANIFEST_GENERATION: u64 = 11;

/// A deterministic, cryptographically valid raw authority history.
///
/// Methods returning records update only this in-memory fixture.  No method
/// can construct sealed verification output.
pub struct RawAuthorityFixture {
    genesis_a1: Vec<u8>,
    genesis_a2: Vec<u8>,
    presented: Vec<PresentedAuthorityRecord>,
    migration_receipt: Option<Vec<u8>>,
    genesis_context: ActivationContext,
    anchor: Sha256Digest,
    current_a1_digest: Sha256Digest,
    current_a1_generation: u64,
    current_signing_key: SigningKey,
    genesis_a2_digest: Sha256Digest,
    current_a2_digest: Sha256Digest,
    last_event_digest: Sha256Digest,
    next_sequence: u64,
    next_key_seed: u8,
    migration_expectations: Option<MigrationExpectations>,
}

impl RawAuthorityFixture {
    /// Builds a fresh-genesis authority history with no post-genesis records.
    #[must_use]
    pub fn fresh_genesis() -> Self {
        Self::fresh_genesis_with_anchor(fixture_trust_anchor_id())
    }

    /// Builds a fresh-genesis history for one exact authenticated dependency
    /// anchor supplied by an integration test.
    #[must_use]
    pub fn fresh_genesis_with_anchor(trust_anchor_id: Sha256Digest) -> Self {
        Self::build(ActivationContext::FreshGenesis, trust_anchor_id, None)
    }

    /// Builds an accepted migration-genesis history.
    ///
    /// A rooted prior state should normally use [`Self::trust_anchor_id`] from
    /// a fresh fixture or [`fixture_trust_anchor_id`].  Passing another rooted
    /// digest deliberately constructs a signed but semantically mismatched
    /// hostile receipt.
    #[must_use]
    pub fn accepted_migration(
        old_root_state: OldRootState,
        restore_proof_digest: Option<Sha256Digest>,
    ) -> Self {
        Self::accepted_migration_with_anchor(
            fixture_trust_anchor_id(),
            old_root_state,
            restore_proof_digest,
        )
    }

    /// Builds an accepted migration-genesis history for one exact authenticated
    /// dependency anchor supplied by an integration test.
    #[must_use]
    pub fn accepted_migration_with_anchor(
        trust_anchor_id: Sha256Digest,
        old_root_state: OldRootState,
        restore_proof_digest: Option<Sha256Digest>,
    ) -> Self {
        let restore_declaration_digest = restore_proof_digest
            .as_ref()
            .map(|_| sha256_bytes(b"fixture restore declaration"));
        Self::accepted_migration_with_anchor_and_restore_bindings(
            trust_anchor_id,
            old_root_state,
            restore_declaration_digest,
            restore_proof_digest,
        )
    }

    /// Builds an accepted migration fixture with independently supplied exact
    /// official-restore declaration and proof bindings.
    ///
    /// # Panics
    ///
    /// Panics when exactly one binding is present, because a declared restore
    /// requires the declaration and proof as one complete pair.
    #[must_use]
    pub fn accepted_migration_with_restore_bindings(
        old_root_state: OldRootState,
        restore_declaration_digest: Option<Sha256Digest>,
        restore_proof_digest: Option<Sha256Digest>,
    ) -> Self {
        Self::accepted_migration_with_anchor_and_restore_bindings(
            fixture_trust_anchor_id(),
            old_root_state,
            restore_declaration_digest,
            restore_proof_digest,
        )
    }

    /// Anchor-parameterized form of
    /// [`Self::accepted_migration_with_restore_bindings`].
    ///
    /// # Panics
    ///
    /// Panics when exactly one restore binding is present.
    #[must_use]
    pub fn accepted_migration_with_anchor_and_restore_bindings(
        trust_anchor_id: Sha256Digest,
        old_root_state: OldRootState,
        restore_declaration_digest: Option<Sha256Digest>,
        restore_proof_digest: Option<Sha256Digest>,
    ) -> Self {
        assert_eq!(
            restore_declaration_digest.is_some(),
            restore_proof_digest.is_some(),
            "restore declaration and proof must be supplied together"
        );
        Self::build(
            ActivationContext::MigrationGenesis,
            trust_anchor_id,
            Some(MigrationExpectations {
                old_root_state,
                restore_declaration_digest,
                restore_proof_digest,
            }),
        )
    }

    fn build(
        context: ActivationContext,
        anchor: Sha256Digest,
        migration_expectations: Option<MigrationExpectations>,
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let a1_wire = a1_wire(
            "operator/principal-a".to_owned(),
            hex::encode(signing_key.verifying_key().as_bytes()),
            1,
            cut(1, None),
            None,
            None,
        );
        let a1_digest = a1_digest_for(&a1_wire);
        let genesis_a1 = a1_bytes(a1_wire);

        let mut a2_wire = a2_wire(
            context,
            cut(2, Some(a1_digest.clone())),
            None,
            a1_digest.clone(),
            1,
            empty_signature(),
            None,
        );
        crate::records::fixture_access::set_a2_anchor(&mut a2_wire, anchor.clone());
        let a2_signature = signing_key.sign(&a2_signature_preimage_for(&a2_wire));
        set_a2_signature(&mut a2_wire, hex::encode(a2_signature.to_bytes()));
        let a2_digest = a2_digest_for(&a2_wire);
        let genesis_a2 = a2_bytes(a2_wire);
        let mut fixture = Self {
            genesis_a1,
            genesis_a2,
            presented: Vec::new(),
            migration_receipt: None,
            genesis_context: context,
            anchor,
            current_a1_digest: a1_digest,
            current_a1_generation: 1,
            current_signing_key: signing_key,
            genesis_a2_digest: a2_digest.clone(),
            current_a2_digest: a2_digest.clone(),
            last_event_digest: a2_digest,
            next_sequence: 3,
            next_key_seed: 2,
            migration_expectations,
        };
        if context == ActivationContext::MigrationGenesis {
            fixture.build_migration_receipt();
        }
        fixture
    }

    fn build_migration_receipt(&mut self) {
        let expected = self
            .migration_expectations
            .as_ref()
            .expect("migration expectations");
        let mut wire = migration_wire(
            expected.old_root_state.clone(),
            self.current_a2_digest.clone(),
            self.anchor.clone(),
            cut(3, Some(self.current_a2_digest.clone())),
            self.current_a1_digest.clone(),
            self.current_a1_generation,
            expected.restore_declaration_digest.clone(),
            expected.restore_proof_digest.clone(),
            empty_signature(),
        );
        let signature = self
            .current_signing_key
            .sign(&migration_signature_preimage_for(&wire));
        set_migration_signature(&mut wire, hex::encode(signature.to_bytes()));
        self.last_event_digest = migration_digest_for(&wire);
        self.migration_receipt = Some(migration_bytes(wire));
        // The retained migration receipt is the migration establishment event
        // in the global authority-cut topology. Every later Store-ledger event
        // must name it as its exact authority-event predecessor.
        self.next_sequence = 4;
    }

    /// Returns a fresh owned copy of the exact genesis custody bundle.
    #[must_use]
    pub fn custody(&self) -> GenesisAuthorityCustody {
        GenesisAuthorityCustody::new(self.genesis_a1.clone(), self.genesis_a2.clone())
    }

    /// Returns a fresh owned copy of every post-genesis record.
    #[must_use]
    pub fn presented_set(&self) -> PresentedAuthoritySet {
        PresentedAuthoritySet::new(self.presented.clone())
    }

    fn append_presented_record(&mut self, record: PresentedAuthorityRecord) {
        let current = PresentedAuthoritySet::new(std::mem::take(&mut self.presented));
        self.presented = current
            .with_record_in_store_enumeration_order(record)
            .records()
            .to_vec();
    }

    /// Returns establishment expectations matching the fixture.
    #[must_use]
    pub fn activation_expectations(&self) -> ActivationExpectations {
        ActivationExpectations {
            genesis_context: self.genesis_context,
            expected_occurrence_id: (self.genesis_context == ActivationContext::MigrationGenesis)
                .then(|| FIXTURE_OCCURRENCE_ID.to_owned()),
            resident_identity: FIXTURE_RESIDENT_ID.to_owned(),
            resident_generation: FIXTURE_RESIDENT_GENERATION,
            host_role: FIXTURE_HOST_ROLE.to_owned(),
            role_manifest_generation: FIXTURE_ROLE_MANIFEST_GENERATION,
            trust_anchor_id: self.anchor.clone(),
            domain: FIXTURE_DOMAIN.to_owned(),
            policy_floor: 1,
            migration: self.migration_expectations.clone(),
        }
    }

    /// Returns Store-retained restart expectations matching the fixture.
    ///
    /// # Panics
    ///
    /// Panics only if this fixture's internally generated migration receipt no
    /// longer decodes, which indicates a defect in test-support construction.
    #[must_use]
    pub fn restart_expectations(&self) -> RestartExpectations {
        let migration = self.migration_receipt.as_ref().map(|bytes| {
            MigrationReceipt::from_canonical_bytes(bytes).expect("fixture migration receipt")
        });
        let migration_digest = migration
            .as_ref()
            .map(|receipt| receipt.receipt_digest().clone());
        let genesis_a1 = crate::OperatorAuthorityRecord::from_canonical_bytes(&self.genesis_a1)
            .expect("fixture genesis A1");
        let genesis_a2 = ResidentActivationRecord::from_canonical_bytes(&self.genesis_a2)
            .expect("fixture genesis A2");
        let expected_establishment_cut = migration
            .as_ref()
            .map_or_else(|| genesis_a2.cut().clone(), |receipt| receipt.cut().clone());
        RestartExpectations {
            genesis_context: self.genesis_context,
            expected_occurrence_id: FIXTURE_OCCURRENCE_ID.to_owned(),
            expected_chain_root_activation_digest: self.genesis_a2_digest.clone(),
            expected_establishment_tip_digest: self.genesis_a2_digest.clone(),
            expected_genesis_operator_authority_digest: genesis_a1.record_digest().clone(),
            expected_genesis_operator_key_generation: genesis_a1.key_generation(),
            expected_establishment_cut,
            expected_establishment_policy_version: 1,
            expected_establishment_candidate_set_digest: crate::digest_presented_authority_set(
                &PresentedAuthoritySet::new(Vec::new()),
            )
            .expect("empty fixture candidate set"),
            resident_identity: FIXTURE_RESIDENT_ID.to_owned(),
            resident_generation: FIXTURE_RESIDENT_GENERATION,
            host_role: FIXTURE_HOST_ROLE.to_owned(),
            role_manifest_generation: FIXTURE_ROLE_MANIFEST_GENERATION,
            trust_anchor_id: self.anchor.clone(),
            domain: FIXTURE_DOMAIN.to_owned(),
            policy_floor: 1,
            expected_custody_digest: crate::digest_genesis_authority_custody(&self.custody())
                .expect("fixture custody framing"),
            expected_migration_receipt_digest: migration_digest,
        }
    }

    /// Returns an owned exact migration receipt, if this is a migration fixture.
    #[must_use]
    pub fn migration_receipt(&self) -> Option<MigrationReceiptBytes> {
        self.migration_receipt
            .as_ref()
            .map(|bytes| MigrationReceiptBytes::new(bytes.clone()))
    }

    /// Returns a freshly signed receipt over this migration fixture with the
    /// requested explicit disposition.
    ///
    /// This emits only unverified raw input and is unavailable for a fresh
    /// genesis fixture.
    ///
    /// # Panics
    ///
    /// Panics only if this fixture's internally generated genesis A1 no longer
    /// decodes, which indicates a defect in test-support construction.
    #[must_use]
    pub fn migration_receipt_with_disposition(
        &self,
        disposition: crate::MigrationDisposition,
    ) -> Option<MigrationReceiptBytes> {
        let expected = self.migration_expectations.as_ref()?;
        let genesis_a1 = crate::OperatorAuthorityRecord::from_canonical_bytes(&self.genesis_a1)
            .expect("fixture genesis A1");
        let genesis_signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let mut wire = migration_wire(
            expected.old_root_state.clone(),
            self.genesis_a2_digest.clone(),
            self.anchor.clone(),
            cut(3, Some(self.genesis_a2_digest.clone())),
            genesis_a1.record_digest().clone(),
            genesis_a1.key_generation(),
            expected.restore_declaration_digest.clone(),
            expected.restore_proof_digest.clone(),
            empty_signature(),
        );
        set_migration_disposition(&mut wire, disposition);
        let signature = genesis_signing_key.sign(&migration_signature_preimage_for(&wire));
        set_migration_signature(&mut wire, hex::encode(signature.to_bytes()));
        Some(MigrationReceiptBytes::new(migration_bytes(wire)))
    }

    /// Builds an unverified operator-signed schema-v7 cardinality disposition
    /// over an exact absent, singleton-empty, or multiple sorted genesis census.
    ///
    /// The constructor deliberately performs no cardinality, sorting, or
    /// disposition validation so hostile tests can emit invalid raw inputs.
    ///
    /// # Panics
    ///
    /// Panics only if this fixture's internally generated genesis A1 no longer
    /// decodes, which indicates a test-support construction defect.
    #[must_use]
    pub fn v7_cardinality_disposition(
        &self,
        disposition: crate::MigrationDisposition,
        genesis_identities: Vec<String>,
        source_logical_digest: Sha256Digest,
        old_root_state: OldRootState,
        restore_declaration_digest: Option<Sha256Digest>,
    ) -> V7CardinalityDispositionBytes {
        let genesis_a1 = crate::OperatorAuthorityRecord::from_canonical_bytes(&self.genesis_a1)
            .expect("fixture genesis A1");
        let genesis_signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let mut wire = cardinality_wire(
            disposition,
            genesis_identities,
            source_logical_digest,
            old_root_state,
            FIXTURE_DOMAIN.to_owned(),
            1,
            genesis_a1.record_digest().clone(),
            genesis_a1.key_generation(),
            restore_declaration_digest,
            empty_signature(),
        );
        let signature = genesis_signing_key.sign(&cardinality_signature_preimage(&wire));
        set_cardinality_signature(&mut wire, hex::encode(signature.to_bytes()));
        V7CardinalityDispositionBytes::new(cardinality_bytes(wire))
    }

    /// Returns the fixture's immutable trust anchor.
    #[must_use]
    pub const fn trust_anchor_id(&self) -> &Sha256Digest {
        &self.anchor
    }

    /// Returns the current A2 tip digest.
    #[must_use]
    pub const fn current_activation_digest(&self) -> &Sha256Digest {
        &self.current_a2_digest
    }

    /// Appends and returns one valid A1 rotation.
    ///
    /// # Panics
    ///
    /// Panics after exhausting all deterministic one-byte fixture key seeds or
    /// overflowing the fixture-only key-generation counter.
    pub fn append_operator_rotation(&mut self) -> Vec<u8> {
        let new_key = SigningKey::from_bytes(&[self.next_key_seed; 32]);
        self.next_key_seed = self.next_key_seed.checked_add(1).expect("fixture key seed");
        let generation = self
            .current_a1_generation
            .checked_add(1)
            .expect("fixture key generation");
        let mut wire = a1_wire(
            "operator/principal-a".to_owned(),
            hex::encode(new_key.verifying_key().as_bytes()),
            generation,
            cut(self.next_sequence, Some(self.last_event_digest.clone())),
            Some(self.current_a1_digest.clone()),
            Some(empty_signature()),
        );
        let signature = self
            .current_signing_key
            .sign(&a1_signature_preimage_for(&wire));
        set_a1_signature(&mut wire, hex::encode(signature.to_bytes()));
        let digest = a1_digest_for(&wire);
        let bytes = a1_bytes(wire);
        self.append_presented_record(PresentedAuthorityRecord::OperatorAuthorityRotation(
            bytes.clone(),
        ));
        self.current_signing_key = new_key;
        self.current_a1_digest = digest.clone();
        self.current_a1_generation = generation;
        self.last_event_digest = digest;
        self.next_sequence += 1;
        bytes
    }

    /// Appends and returns one valid A2 successor.
    pub fn append_activation_successor(&mut self) -> Vec<u8> {
        self.append_activation_successor_with_expiry(None)
    }

    /// Appends and returns one valid A2 successor with an optional cut expiry.
    pub fn append_activation_successor_with_expiry(&mut self, expiry_cut: Option<u64>) -> Vec<u8> {
        let mut wire = a2_wire(
            ActivationContext::Successor,
            cut(self.next_sequence, Some(self.last_event_digest.clone())),
            Some(self.current_a2_digest.clone()),
            self.current_a1_digest.clone(),
            self.current_a1_generation,
            empty_signature(),
            expiry_cut,
        );
        crate::records::fixture_access::set_a2_anchor(&mut wire, self.anchor.clone());
        let signature = self
            .current_signing_key
            .sign(&a2_signature_preimage_for(&wire));
        set_a2_signature(&mut wire, hex::encode(signature.to_bytes()));
        let digest = a2_digest_for(&wire);
        let bytes = a2_bytes(wire);
        self.append_presented_record(PresentedAuthorityRecord::ResidentActivationSuccessor(
            bytes.clone(),
        ));
        self.current_a2_digest = digest.clone();
        self.last_event_digest = digest;
        self.next_sequence += 1;
        bytes
    }

    /// Appends and returns one valid prospective revocation of the current tip.
    pub fn append_current_activation_revocation(&mut self) -> Vec<u8> {
        let mut wire = revocation_wire(
            self.current_a2_digest.clone(),
            cut(self.next_sequence, Some(self.last_event_digest.clone())),
            self.current_a1_digest.clone(),
            self.current_a1_generation,
            empty_signature(),
        );
        set_revocation_anchor(&mut wire, self.anchor.clone());
        let signature = self
            .current_signing_key
            .sign(&revocation_signature_preimage_for(&wire));
        set_revocation_signature(&mut wire, hex::encode(signature.to_bytes()));
        let digest = revocation_digest_for(&wire);
        let bytes = revocation_bytes(wire);
        self.append_presented_record(PresentedAuthorityRecord::ActivationRevocation(
            bytes.clone(),
        ));
        self.last_event_digest = digest;
        self.next_sequence += 1;
        bytes
    }
}

/// Returns the deterministic fixture trust-anchor identity.
#[must_use]
pub fn fixture_trust_anchor_id() -> Sha256Digest {
    sha256_bytes(b"fixture trust anchor")
}

fn empty_signature() -> String {
    "00".repeat(64)
}

#[cfg(test)]
mod tests {
    use nq_protocol::{canonical_json_bytes, sha256_bytes};
    use serde_json::Value;

    use super::*;
    use crate::records::fixture_access::{
        set_a2_anchor, set_a2_domain, set_a2_occurrence, set_a2_operator_authority, set_a2_policy,
        set_a2_resident, set_a2_resident_generation, set_a2_role, set_a2_role_manifest_generation,
        set_a2_scope, set_a2_signature_algorithm, set_migration_disposition,
    };
    use crate::{
        AuthorityError, EstablishmentArm, EstablishmentReceiptTranscript,
        RUNTIME_DEPENDENCY_ADMISSION_SCOPE, ResidentActivationRecord,
        V7CardinalityDispositionExpectations, digest_presented_authority_set, resolve_for_restart,
        verify_activation_revocation, verify_for_establishment,
        verify_nonaccepted_migration_classification, verify_operator_authority_rotation,
        verify_resident_activation_successor, verify_v7_cardinality_disposition,
        with_verification_brand,
    };

    #[derive(Clone, Copy)]
    enum SuccessorMutation {
        None,
        WrongScope,
        WrongDomain,
        WrongAnchor,
        WrongResident,
        WrongResidentGeneration,
        WrongRole,
        WrongRoleManifestGeneration,
        WrongOccurrence,
        UnknownOperatorAuthority,
        UnsupportedPolicy,
        UnsupportedSignatureAlgorithm,
        WrongSignature,
    }

    #[derive(Clone, Copy, Debug)]
    enum NativeEventFamily {
        OperatorRotation,
        ActivationSuccessor,
        Revocation,
    }

    fn successor_candidate(
        fixture: &RawAuthorityFixture,
        sequence: u64,
        event_predecessor: Sha256Digest,
        activation_predecessor: Sha256Digest,
        mutation: SuccessorMutation,
    ) -> Vec<u8> {
        let mut wire = a2_wire(
            ActivationContext::Successor,
            cut(sequence, Some(event_predecessor)),
            Some(activation_predecessor),
            fixture.current_a1_digest.clone(),
            fixture.current_a1_generation,
            empty_signature(),
            None,
        );
        set_a2_anchor(&mut wire, fixture.anchor.clone());
        match mutation {
            SuccessorMutation::None | SuccessorMutation::WrongSignature => {}
            SuccessorMutation::WrongScope => set_a2_scope(&mut wire, "diagnostic_warrant".into()),
            SuccessorMutation::WrongDomain => set_a2_domain(&mut wire, "other/backend".into()),
            SuccessorMutation::WrongAnchor => {
                set_a2_anchor(&mut wire, sha256_bytes(b"other anchor"));
            }
            SuccessorMutation::WrongResident => {
                set_a2_resident(&mut wire, "resident/attacker".into());
            }
            SuccessorMutation::WrongResidentGeneration => {
                set_a2_resident_generation(&mut wire, FIXTURE_RESIDENT_GENERATION + 1);
            }
            SuccessorMutation::WrongRole => {
                set_a2_role(&mut wire, "host-role/other".into());
            }
            SuccessorMutation::WrongRoleManifestGeneration => {
                set_a2_role_manifest_generation(&mut wire, FIXTURE_ROLE_MANIFEST_GENERATION + 1);
            }
            SuccessorMutation::WrongOccurrence => {
                set_a2_occurrence(&mut wire, "store-occurrence/other".into());
            }
            SuccessorMutation::UnknownOperatorAuthority => {
                set_a2_operator_authority(&mut wire, sha256_bytes(b"absent A1"), 1);
            }
            SuccessorMutation::UnsupportedPolicy => set_a2_policy(&mut wire, 2),
            SuccessorMutation::UnsupportedSignatureAlgorithm => {
                set_a2_signature_algorithm(&mut wire, "ed448".into());
            }
        }
        let signer = if matches!(mutation, SuccessorMutation::WrongSignature) {
            SigningKey::from_bytes(&[99_u8; 32])
        } else {
            fixture.current_signing_key.clone()
        };
        let signature = signer.sign(&a2_signature_preimage_for(&wire));
        set_a2_signature(&mut wire, hex::encode(signature.to_bytes()));
        a2_bytes(wire)
    }

    fn set_with_candidate(
        fixture: &RawAuthorityFixture,
        candidate: PresentedAuthorityRecord,
    ) -> PresentedAuthoritySet {
        fixture
            .presented_set()
            .with_record_in_store_enumeration_order(candidate)
    }

    fn migration_competing_event(
        fixture: &RawAuthorityFixture,
        family: NativeEventFamily,
        sequence: u64,
    ) -> PresentedAuthorityRecord {
        let event_predecessor = fixture.genesis_a2_digest.clone();
        match family {
            NativeEventFamily::OperatorRotation => {
                let new_key = SigningKey::from_bytes(&[2_u8; 32]);
                let mut wire = a1_wire(
                    "operator/principal-a".to_owned(),
                    hex::encode(new_key.verifying_key().as_bytes()),
                    2,
                    cut(sequence, Some(event_predecessor)),
                    Some(fixture.current_a1_digest.clone()),
                    Some(empty_signature()),
                );
                let signature = fixture
                    .current_signing_key
                    .sign(&a1_signature_preimage_for(&wire));
                set_a1_signature(&mut wire, hex::encode(signature.to_bytes()));
                PresentedAuthorityRecord::OperatorAuthorityRotation(a1_bytes(wire))
            }
            NativeEventFamily::ActivationSuccessor => {
                PresentedAuthorityRecord::ResidentActivationSuccessor(successor_candidate(
                    fixture,
                    sequence,
                    event_predecessor,
                    fixture.current_a2_digest.clone(),
                    SuccessorMutation::None,
                ))
            }
            NativeEventFamily::Revocation => {
                let mut wire = revocation_wire(
                    fixture.current_a2_digest.clone(),
                    cut(sequence, Some(event_predecessor)),
                    fixture.current_a1_digest.clone(),
                    fixture.current_a1_generation,
                    empty_signature(),
                );
                set_revocation_anchor(&mut wire, fixture.anchor.clone());
                let signature = fixture
                    .current_signing_key
                    .sign(&revocation_signature_preimage_for(&wire));
                set_revocation_signature(&mut wire, hex::encode(signature.to_bytes()));
                PresentedAuthorityRecord::ActivationRevocation(revocation_bytes(wire))
            }
        }
    }

    fn restart(
        fixture: &RawAuthorityFixture,
    ) -> Result<crate::ControllingActivationSnapshot, AuthorityError> {
        let custody = fixture.custody();
        let presented = fixture.presented_set();
        let receipt = fixture.migration_receipt();
        resolve_for_restart(
            &custody,
            &presented,
            receipt.as_ref(),
            &fixture.restart_expectations(),
        )
    }

    fn cardinality_expectations(
        genesis_identities: Vec<String>,
        source_logical_digest: Sha256Digest,
        old_root_state: OldRootState,
        restore_declaration_digest: Option<Sha256Digest>,
    ) -> V7CardinalityDispositionExpectations {
        V7CardinalityDispositionExpectations {
            genesis_identities,
            source_logical_digest,
            old_root_state,
            domain: FIXTURE_DOMAIN.to_owned(),
            policy_floor: 1,
            restore_declaration_digest,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_cardinality_disposition(
        fixture: &RawAuthorityFixture,
        disposition: crate::MigrationDisposition,
        genesis_identities: Vec<String>,
        source_logical_digest: Sha256Digest,
        old_root_state: OldRootState,
        domain: &str,
        policy_version: u64,
        restore_declaration_digest: Option<Sha256Digest>,
        signing_seed: u8,
    ) -> V7CardinalityDispositionBytes {
        let genesis_a1 =
            crate::OperatorAuthorityRecord::from_canonical_bytes(&fixture.genesis_a1).unwrap();
        let signing_key = SigningKey::from_bytes(&[signing_seed; 32]);
        let mut wire = cardinality_wire(
            disposition,
            genesis_identities,
            source_logical_digest,
            old_root_state,
            domain.to_owned(),
            policy_version,
            genesis_a1.record_digest().clone(),
            genesis_a1.key_generation(),
            restore_declaration_digest,
            empty_signature(),
        );
        let signature = signing_key.sign(&cardinality_signature_preimage(&wire));
        set_cardinality_signature(&mut wire, hex::encode(signature.to_bytes()));
        V7CardinalityDispositionBytes::new(cardinality_bytes(wire))
    }

    #[test]
    fn fresh_genesis_resolves_and_derives_round_trip_receipt() {
        // This deliberately proves cryptographic consistency and attribution
        // only. Authorization of the initialize act and prevention of an
        // arbitrary fresh-file initialization are exogenous nonclaims.
        let fixture = RawAuthorityFixture::fresh_genesis();
        let custody = fixture.custody();
        let presented = fixture.presented_set();
        let result = with_verification_brand(|brand| {
            let evidence = verify_for_establishment(
                &brand,
                &custody,
                &presented,
                None,
                &fixture.activation_expectations(),
            )?;
            assert_eq!(evidence.occurrence_id(), FIXTURE_OCCURRENCE_ID);
            assert_eq!(evidence.genesis_context(), ActivationContext::FreshGenesis);
            assert_eq!(evidence.trust_anchor_id(), fixture.trust_anchor_id());
            assert_eq!(
                evidence.candidate_set_digest(),
                &digest_presented_authority_set(&presented)?
            );
            let transcript = evidence.establishment_receipt_transcript()?;
            assert_eq!(transcript.arm(), EstablishmentArm::Genesis);
            assert_eq!(transcript.migration_receipt_digest(), None);
            let canonical = transcript.canonical_bytes()?;
            let decoded = EstablishmentReceiptTranscript::from_canonical_bytes(&canonical)?;
            assert_eq!(decoded, transcript);
            assert_eq!(decoded.receipt_id()?, transcript.receipt_id()?);
            Ok::<_, AuthorityError>(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(
            restart(&fixture)
                .unwrap()
                .controlling_tip_activation_digest(),
            ResidentActivationRecord::from_canonical_bytes(fixture.custody().genesis_a2_bytes())
                .unwrap()
                .activation_digest()
        );
    }

    #[test]
    fn anchor_parameterized_fixtures_sign_every_native_family_to_exact_anchor() {
        let anchor = sha256_bytes(b"authenticated dependency fixture anchor");
        let mut fresh = RawAuthorityFixture::fresh_genesis_with_anchor(anchor.clone());
        fresh.append_operator_rotation();
        fresh.append_activation_successor();
        fresh.append_current_activation_revocation();
        fresh.append_activation_successor();
        assert_eq!(fresh.trust_anchor_id(), &anchor);
        assert_eq!(restart(&fresh).unwrap().trust_anchor_id(), &anchor);

        let migrated = RawAuthorityFixture::accepted_migration_with_anchor(
            anchor.clone(),
            OldRootState::Rooted {
                trust_anchor_id: anchor.clone(),
            },
            None,
        );
        assert_eq!(restart(&migrated).unwrap().trust_anchor_id(), &anchor);
    }

    #[test]
    fn candidate_digest_preserves_cross_table_enumeration_order() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        fixture.append_operator_rotation();
        fixture.append_activation_successor();
        let forward = fixture.presented_set();
        let mut reversed = fixture.presented.clone();
        reversed.reverse();
        let reversed = PresentedAuthoritySet::new(reversed);
        assert_ne!(
            digest_presented_authority_set(&forward),
            digest_presented_authority_set(&reversed)
        );
    }

    #[test]
    fn prospective_records_use_store_family_order_without_changing_event_topology() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        fixture.append_activation_successor();
        fixture.append_operator_rotation();
        fixture.append_current_activation_revocation();
        fixture.append_activation_successor();

        let presented = fixture.presented_set();
        assert!(matches!(
            presented.records(),
            [
                PresentedAuthorityRecord::OperatorAuthorityRotation(_),
                PresentedAuthorityRecord::ResidentActivationSuccessor(_),
                PresentedAuthorityRecord::ResidentActivationSuccessor(_),
                PresentedAuthorityRecord::ActivationRevocation(_),
            ]
        ));
        assert_eq!(
            restart(&fixture)
                .expect("event-predecessor topology remains authoritative")
                .controlling_tip_activation_digest(),
            fixture.current_activation_digest()
        );
    }

    #[test]
    fn candidate_binding_detects_set_changes_but_does_not_testify_store_completeness() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        fixture.append_operator_rotation();
        fixture.append_activation_successor();
        fixture.append_current_activation_revocation();

        let complete = fixture.presented_set();
        let complete_digest = digest_presented_authority_set(&complete).unwrap();

        let mut omitted = fixture.presented.clone();
        omitted.pop();
        assert_ne!(
            digest_presented_authority_set(&PresentedAuthoritySet::new(omitted)).unwrap(),
            complete_digest
        );

        let mut duplicated = fixture.presented.clone();
        duplicated.push(fixture.presented[0].clone());
        assert_ne!(
            digest_presented_authority_set(&PresentedAuthoritySet::new(duplicated)).unwrap(),
            complete_digest
        );

        let mut byte_substitution = fixture.presented.clone();
        match &mut byte_substitution[0] {
            PresentedAuthorityRecord::OperatorAuthorityRotation(bytes)
            | PresentedAuthorityRecord::ResidentActivationSuccessor(bytes)
            | PresentedAuthorityRecord::ActivationRevocation(bytes) => bytes.push(b' '),
        }
        assert_ne!(
            digest_presented_authority_set(&PresentedAuthoritySet::new(byte_substitution)).unwrap(),
            complete_digest
        );

        // This sensitivity lets the Store compare an in-transaction census
        // with sealed evidence.  The evidence crate itself cannot testify
        // that `complete` is the Store's complete resident candidate set.
    }

    #[test]
    fn candidate_binding_changes_when_previously_verified_evidence_becomes_stale() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        let result = with_verification_brand(|brand| {
            let original_set = fixture.presented_set();
            let evidence = verify_for_establishment(
                &brand,
                &fixture.custody(),
                &original_set,
                None,
                &fixture.activation_expectations(),
            )?;
            evidence.reverify_store_owned_presented_set(&original_set)?;
            let before = evidence.candidate_set_digest().clone();

            fixture.append_operator_rotation();
            let changed = fixture.presented_set();
            let after = digest_presented_authority_set(&changed)?;
            assert_ne!(before, after);
            assert_eq!(
                evidence.reverify_store_owned_presented_set(&changed),
                Err(AuthorityError::PresentedSetCorrespondenceMismatch)
            );
            Ok::<_, AuthorityError>(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn identical_custody_bundles_remain_cryptographically_valid_without_duplicate_detection() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let verify = || {
            with_verification_brand(|brand| {
                verify_for_establishment(
                    &brand,
                    &fixture.custody(),
                    &fixture.presented_set(),
                    None,
                    &fixture.activation_expectations(),
                )
                .map(|evidence| {
                    (
                        evidence.occurrence_id().to_owned(),
                        evidence.chain_root_activation_digest().clone(),
                        evidence.custody_digest().clone(),
                    )
                })
            })
        };

        let first = verify().unwrap();
        let copied = verify().unwrap();
        assert_eq!(first, copied);

        // H-27 is intentionally a deployment/C2 nonclaim: exact copied bytes
        // carry the same operator-minted occurrence identity.  This bounded
        // verifier neither detects nor prevents another physical occurrence.
    }

    #[test]
    fn a1_rotation_and_a2_successor_verify_through_sealed_event_apis() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        let before_rotation = fixture.presented_set();
        let rotation = fixture.append_operator_rotation();
        let custody = fixture.custody();
        assert!(
            with_verification_brand(|brand| {
                let event = verify_operator_authority_rotation(
                    &brand,
                    &custody,
                    &before_rotation,
                    &rotation,
                    None,
                    &fixture.activation_expectations(),
                )?;
                event.reverify_store_owned_presented_set(&before_rotation)?;
                assert_eq!(
                    event.reverify_store_owned_presented_set(&fixture.presented_set()),
                    Err(AuthorityError::PresentedSetCorrespondenceMismatch)
                );
                Ok::<_, AuthorityError>(())
            })
            .is_ok()
        );

        let before_successor = fixture.presented_set();
        let successor = fixture.append_activation_successor();
        assert!(
            with_verification_brand(|brand| {
                let event = verify_resident_activation_successor(
                    &brand,
                    &custody,
                    &before_successor,
                    &successor,
                    None,
                    &fixture.activation_expectations(),
                )?;
                event.reverify_store_owned_presented_set(&before_successor)?;
                assert_eq!(
                    event.reverify_store_owned_presented_set(&fixture.presented_set()),
                    Err(AuthorityError::PresentedSetCorrespondenceMismatch)
                );
                Ok::<_, AuthorityError>(())
            })
            .is_ok()
        );
        assert_eq!(
            restart(&fixture)
                .unwrap()
                .controlling_tip_activation_digest(),
            fixture.current_activation_digest()
        );
    }

    #[test]
    fn prospective_revocation_is_appendable_but_restart_refuses_until_successor() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        let before = fixture.presented_set();
        let revocation = fixture.append_current_activation_revocation();
        let custody = fixture.custody();
        assert!(
            with_verification_brand(|brand| {
                let event = verify_activation_revocation(
                    &brand,
                    &custody,
                    &before,
                    &revocation,
                    None,
                    &fixture.activation_expectations(),
                )?;
                event.reverify_store_owned_presented_set(&before)?;
                assert_eq!(
                    event.reverify_store_owned_presented_set(&fixture.presented_set()),
                    Err(AuthorityError::PresentedSetCorrespondenceMismatch)
                );
                Ok::<_, AuthorityError>(())
            })
            .is_ok()
        );
        assert_eq!(
            restart(&fixture),
            Err(AuthorityError::ControllingActivationRevoked)
        );
        fixture.append_activation_successor();
        assert!(restart(&fixture).is_ok());
    }

    #[test]
    fn expiry_is_evaluated_only_at_later_authority_cut() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        fixture.append_activation_successor_with_expiry(Some(4));
        assert!(restart(&fixture).is_ok());
        fixture.append_operator_rotation();
        assert_eq!(
            restart(&fixture),
            Err(AuthorityError::ControllingActivationExpired)
        );
        assert_eq!(
            restart(&fixture),
            Err(AuthorityError::ControllingActivationExpired)
        );
    }

    #[test]
    fn signed_tuple_substitutions_refuse_with_distinct_errors() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let cases = [
            (SuccessorMutation::WrongScope, AuthorityError::ScopeMismatch),
            (
                SuccessorMutation::WrongDomain,
                AuthorityError::DomainMismatch,
            ),
            (
                SuccessorMutation::WrongAnchor,
                AuthorityError::AnchorMismatch,
            ),
            (
                SuccessorMutation::WrongResident,
                AuthorityError::ResidentMismatch,
            ),
            (
                SuccessorMutation::WrongResidentGeneration,
                AuthorityError::ResidentGenerationMismatch,
            ),
            (SuccessorMutation::WrongRole, AuthorityError::RoleMismatch),
            (
                SuccessorMutation::WrongRoleManifestGeneration,
                AuthorityError::RoleManifestGenerationMismatch,
            ),
            (
                SuccessorMutation::WrongOccurrence,
                AuthorityError::OccurrenceMismatch,
            ),
            (
                SuccessorMutation::UnknownOperatorAuthority,
                AuthorityError::A1IdentityMismatch,
            ),
            (
                SuccessorMutation::UnsupportedPolicy,
                AuthorityError::PolicyVersionUnsupported,
            ),
            (
                SuccessorMutation::UnsupportedSignatureAlgorithm,
                AuthorityError::A2SignatureAlgorithmUnsupported,
            ),
            (
                SuccessorMutation::WrongSignature,
                AuthorityError::A2SignatureInvalid,
            ),
        ];
        for (mutation, expected) in cases {
            let candidate = successor_candidate(
                &fixture,
                fixture.next_sequence,
                fixture.last_event_digest.clone(),
                fixture.current_a2_digest.clone(),
                mutation,
            );
            let presented = set_with_candidate(
                &fixture,
                PresentedAuthorityRecord::ResidentActivationSuccessor(candidate),
            );
            let custody = fixture.custody();
            let observed =
                resolve_for_restart(&custody, &presented, None, &fixture.restart_expectations());
            assert_eq!(observed, Err(expected));
        }
    }

    #[test]
    fn activation_scope_cannot_be_reinterpreted_as_downstream_authority() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        for prohibited_scope in [
            "c2_capacity_authority",
            "diagnostic_warrant",
            "docket_authority",
            "effect_authority",
        ] {
            let mut wire = a2_wire(
                ActivationContext::Successor,
                cut(
                    fixture.next_sequence,
                    Some(fixture.last_event_digest.clone()),
                ),
                Some(fixture.current_a2_digest.clone()),
                fixture.current_a1_digest.clone(),
                fixture.current_a1_generation,
                empty_signature(),
                None,
            );
            set_a2_anchor(&mut wire, fixture.anchor.clone());
            set_a2_scope(&mut wire, prohibited_scope.to_owned());
            let signature = fixture
                .current_signing_key
                .sign(&a2_signature_preimage_for(&wire));
            set_a2_signature(&mut wire, hex::encode(signature.to_bytes()));
            let presented = set_with_candidate(
                &fixture,
                PresentedAuthorityRecord::ResidentActivationSuccessor(a2_bytes(wire)),
            );
            assert_eq!(
                resolve_for_restart(
                    &fixture.custody(),
                    &presented,
                    None,
                    &fixture.restart_expectations(),
                ),
                Err(AuthorityError::ScopeMismatch),
                "scope {prohibited_scope} must not be accepted"
            );
        }
    }

    #[test]
    fn activation_gap_and_exact_predecessor_fork_refuse_without_selection() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let gap = successor_candidate(
            &fixture,
            fixture.next_sequence,
            fixture.last_event_digest.clone(),
            sha256_bytes(b"missing activation"),
            SuccessorMutation::None,
        );
        let gap_set = set_with_candidate(
            &fixture,
            PresentedAuthorityRecord::ResidentActivationSuccessor(gap),
        );
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &gap_set,
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::ActivationGap)
        );

        let left = successor_candidate(
            &fixture,
            3,
            fixture.last_event_digest.clone(),
            fixture.current_a2_digest.clone(),
            SuccessorMutation::None,
        );
        let right = successor_candidate(
            &fixture,
            4,
            fixture.last_event_digest.clone(),
            fixture.current_a2_digest.clone(),
            SuccessorMutation::None,
        );
        let fork = PresentedAuthoritySet::new(vec![
            PresentedAuthorityRecord::ResidentActivationSuccessor(left),
            PresentedAuthorityRecord::ResidentActivationSuccessor(right),
        ]);
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &fork,
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::ActivationFork)
        );
    }

    #[test]
    fn globally_linear_activation_branch_emits_multiple_live_activations() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let left = successor_candidate(
            &fixture,
            3,
            fixture.last_event_digest.clone(),
            fixture.current_a2_digest.clone(),
            SuccessorMutation::None,
        );
        let left_digest = ResidentActivationRecord::from_canonical_bytes(&left)
            .unwrap()
            .activation_digest()
            .clone();
        let right = successor_candidate(
            &fixture,
            4,
            left_digest,
            fixture.current_a2_digest.clone(),
            SuccessorMutation::None,
        );
        let presented = PresentedAuthoritySet::new(vec![
            PresentedAuthorityRecord::ResidentActivationSuccessor(left),
            PresentedAuthorityRecord::ResidentActivationSuccessor(right),
        ]);
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &presented,
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::MultipleLiveActivations)
        );
    }

    #[test]
    fn activation_and_operator_events_at_the_same_cut_refuse() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        fixture.append_operator_rotation();
        let colliding = successor_candidate(
            &fixture,
            3,
            fixture.last_event_digest.clone(),
            fixture.current_a2_digest.clone(),
            SuccessorMutation::None,
        );
        let presented = set_with_candidate(
            &fixture,
            PresentedAuthorityRecord::ResidentActivationSuccessor(colliding),
        );
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &presented,
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::AuthorityCutCollision)
        );
    }

    #[test]
    fn activation_and_revocation_at_the_same_cut_refuse() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let successor = successor_candidate(
            &fixture,
            3,
            fixture.last_event_digest.clone(),
            fixture.current_a2_digest.clone(),
            SuccessorMutation::None,
        );
        let mut revocation = revocation_wire(
            fixture.current_a2_digest.clone(),
            cut(3, Some(fixture.last_event_digest.clone())),
            fixture.current_a1_digest.clone(),
            fixture.current_a1_generation,
            empty_signature(),
        );
        set_revocation_anchor(&mut revocation, fixture.anchor.clone());
        let signature = fixture
            .current_signing_key
            .sign(&revocation_signature_preimage_for(&revocation));
        set_revocation_signature(&mut revocation, hex::encode(signature.to_bytes()));
        let presented = PresentedAuthoritySet::new(vec![
            PresentedAuthorityRecord::ResidentActivationSuccessor(successor),
            PresentedAuthorityRecord::ActivationRevocation(revocation_bytes(revocation)),
        ]);

        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &presented,
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::AuthorityCutCollision)
        );
    }

    #[test]
    fn canonical_and_digest_substitution_refuse_before_semantic_use() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let mut noncanonical = fixture.genesis_a1.clone();
        noncanonical.push(b'\n');
        assert_eq!(
            crate::OperatorAuthorityRecord::from_canonical_bytes(&noncanonical).unwrap_err(),
            AuthorityError::A1NonCanonical
        );

        let mut value: Value = serde_json::from_slice(&fixture.genesis_a1).unwrap();
        value["record_digest"] = Value::String(sha256_bytes(b"substitute").into_string());
        let digest_substitution = canonical_json_bytes(&value).unwrap();
        assert_eq!(
            crate::OperatorAuthorityRecord::from_canonical_bytes(&digest_substitution).unwrap_err(),
            AuthorityError::A1DigestMismatch
        );
    }

    #[test]
    fn receipt_pinning_refuses_same_anchor_activation_and_tip_substitution() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let genesis_a1_digest = fixture.current_a1_digest.clone();
        let mut alternate_wire = a2_wire(
            ActivationContext::FreshGenesis,
            cut(2, Some(genesis_a1_digest.clone())),
            None,
            genesis_a1_digest,
            1,
            empty_signature(),
            Some(99),
        );
        set_a2_anchor(&mut alternate_wire, fixture.anchor.clone());
        let signature = fixture
            .current_signing_key
            .sign(&a2_signature_preimage_for(&alternate_wire));
        set_a2_signature(&mut alternate_wire, hex::encode(signature.to_bytes()));
        let alternate_custody =
            GenesisAuthorityCustody::new(fixture.genesis_a1.clone(), a2_bytes(alternate_wire));

        assert_eq!(
            resolve_for_restart(
                &alternate_custody,
                &fixture.presented_set(),
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::ChainRootMismatch)
        );

        let mut wrong_tip = fixture.restart_expectations();
        wrong_tip.expected_establishment_tip_digest = sha256_bytes(b"substituted activation tip");
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &fixture.presented_set(),
                None,
                &wrong_tip,
            ),
            Err(AuthorityError::EstablishmentTipMismatch)
        );

        let mut successor_history = RawAuthorityFixture::fresh_genesis();
        successor_history.append_activation_successor();
        let mut substituted_valid_tip = successor_history.restart_expectations();
        substituted_valid_tip.expected_establishment_tip_digest =
            successor_history.current_activation_digest().clone();
        assert_eq!(
            resolve_for_restart(
                &successor_history.custody(),
                &successor_history.presented_set(),
                None,
                &substituted_valid_tip,
            ),
            Err(AuthorityError::EstablishmentTipMismatch)
        );
    }

    #[test]
    fn incomplete_or_receipt_mismatched_custody_refuses() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let missing_a1 = GenesisAuthorityCustody::new(Vec::new(), fixture.genesis_a2.clone());
        assert_eq!(
            resolve_for_restart(
                &missing_a1,
                &fixture.presented_set(),
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::A1Malformed)
        );

        let missing_a2 = GenesisAuthorityCustody::new(fixture.genesis_a1.clone(), Vec::new());
        assert_eq!(
            resolve_for_restart(
                &missing_a2,
                &fixture.presented_set(),
                None,
                &fixture.restart_expectations(),
            ),
            Err(AuthorityError::A2Malformed)
        );

        let mut mismatched_receipt = fixture.restart_expectations();
        mismatched_receipt.expected_custody_digest = sha256_bytes(b"other custody bundle");
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &fixture.presented_set(),
                None,
                &mismatched_receipt,
            ),
            Err(AuthorityError::CustodyDigestMismatch)
        );
    }

    #[test]
    fn rooted_and_rootless_accepted_migrations_resolve_and_restart() {
        for old_root in [
            OldRootState::Rooted {
                trust_anchor_id: fixture_trust_anchor_id(),
            },
            OldRootState::Rootless,
        ] {
            let fixture = RawAuthorityFixture::accepted_migration(old_root, None);
            let receipt = fixture.migration_receipt().unwrap();
            let custody = fixture.custody();
            let presented = fixture.presented_set();
            let result = with_verification_brand(|brand| {
                let evidence = verify_for_establishment(
                    &brand,
                    &custody,
                    &presented,
                    Some(&receipt),
                    &fixture.activation_expectations(),
                )?;
                assert_eq!(
                    evidence.genesis_context(),
                    ActivationContext::MigrationGenesis
                );
                assert_eq!(
                    evidence.migration_receipt_canonical_bytes(),
                    Some(receipt.as_bytes())
                );
                assert_eq!(
                    evidence.establishment_receipt_transcript()?.arm(),
                    EstablishmentArm::Migration
                );
                let parsed_receipt = MigrationReceipt::from_canonical_bytes(receipt.as_bytes())?;
                assert_eq!(
                    evidence
                        .establishment_receipt_transcript()?
                        .establishment_cut(),
                    parsed_receipt.cut()
                );
                Ok::<_, AuthorityError>(())
            });
            assert_eq!(result, Ok(()));
            assert!(restart(&fixture).is_ok());
        }
    }

    #[test]
    fn migration_receipt_participates_in_every_native_event_collision_and_fork() {
        for family in [
            NativeEventFamily::OperatorRotation,
            NativeEventFamily::ActivationSuccessor,
            NativeEventFamily::Revocation,
        ] {
            let fixture = RawAuthorityFixture::accepted_migration(OldRootState::Rootless, None);
            let collision =
                PresentedAuthoritySet::new(vec![migration_competing_event(&fixture, family, 3)]);
            assert_eq!(
                resolve_for_restart(
                    &fixture.custody(),
                    &collision,
                    fixture.migration_receipt().as_ref(),
                    &fixture.restart_expectations(),
                ),
                Err(AuthorityError::AuthorityCutCollision),
                "migration collision for {family:?} must refuse"
            );

            let fork =
                PresentedAuthoritySet::new(vec![migration_competing_event(&fixture, family, 4)]);
            assert_eq!(
                resolve_for_restart(
                    &fixture.custody(),
                    &fork,
                    fixture.migration_receipt().as_ref(),
                    &fixture.restart_expectations(),
                ),
                Err(AuthorityError::AuthorityEventFork),
                "migration fork for {family:?} must refuse"
            );
        }
    }

    #[test]
    fn first_post_migration_event_names_consumed_receipt_as_predecessor() {
        let mut fixture = RawAuthorityFixture::accepted_migration(OldRootState::Rootless, None);
        let receipt = fixture.migration_receipt().unwrap();
        let receipt = MigrationReceipt::from_canonical_bytes(receipt.as_bytes()).unwrap();
        let successor = fixture.append_activation_successor();
        let successor = ResidentActivationRecord::from_canonical_bytes(&successor).unwrap();
        assert_eq!(
            successor.cut().predecessor_event_digest(),
            Some(receipt.receipt_digest())
        );
        assert!(restart(&fixture).is_ok());
    }

    #[test]
    fn migration_and_genesis_arms_cannot_masquerade_as_each_other() {
        let fresh = RawAuthorityFixture::fresh_genesis();
        let migrated = RawAuthorityFixture::accepted_migration(OldRootState::Rootless, None);
        let migration_receipt = migrated.migration_receipt().unwrap();

        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &fresh.custody(),
                &fresh.presented_set(),
                Some(&migration_receipt),
                &fresh.activation_expectations(),
            )
            .map(|_| ())),
            Err(AuthorityError::UnexpectedMigrationReceipt)
        );

        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &migrated.custody(),
                &migrated.presented_set(),
                None,
                &migrated.activation_expectations(),
            )
            .map(|_| ())),
            Err(AuthorityError::MigrationReceiptRequired)
        );
    }

    #[test]
    fn migration_receipt_for_another_chain_root_refuses_replay() {
        let target = RawAuthorityFixture::accepted_migration(OldRootState::Rootless, None);
        let foreign = RawAuthorityFixture::accepted_migration_with_anchor(
            sha256_bytes(b"foreign occurrence anchor"),
            OldRootState::Rootless,
            None,
        );
        let foreign_receipt = foreign.migration_receipt().unwrap();

        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &target.custody(),
                &target.presented_set(),
                Some(&foreign_receipt),
                &target.activation_expectations(),
            )
            .map(|_| ())),
            Err(AuthorityError::MigrationActivationMismatch)
        );

        // Exact one-use consumption remains Store-owned.  This test proves
        // only the pure receipt bindings to chain root, anchor, occurrence,
        // domain, operator authority, disposition, cut, and restore proof.
    }

    #[test]
    fn rooted_accepted_migration_cannot_replace_anchor_in_occurrence() {
        let fixture = RawAuthorityFixture::accepted_migration(
            OldRootState::Rooted {
                trust_anchor_id: sha256_bytes(b"different old root"),
            },
            None,
        );
        let receipt = fixture.migration_receipt().unwrap();
        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                Some(&receipt),
                &fixture.activation_expectations(),
            )
            .map(|_| ())),
            Err(AuthorityError::MigrationOldRootMismatch)
        );
    }

    #[test]
    fn migration_restore_proof_and_disposition_are_exact() {
        let fixture = RawAuthorityFixture::accepted_migration(
            OldRootState::Rootless,
            Some(sha256_bytes(b"restore proof")),
        );
        let mut wrong_expectations = fixture.activation_expectations();
        wrong_expectations
            .migration
            .as_mut()
            .unwrap()
            .restore_proof_digest = Some(sha256_bytes(b"other proof"));
        let receipt = fixture.migration_receipt().unwrap();
        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                Some(&receipt),
                &wrong_expectations,
            )
            .map(|_| ())),
            Err(AuthorityError::RestoreProofMismatch)
        );

        let mut wire = migration_wire(
            OldRootState::Rootless,
            fixture.current_a2_digest.clone(),
            fixture.anchor.clone(),
            cut(3, Some(fixture.current_a2_digest.clone())),
            fixture.current_a1_digest.clone(),
            fixture.current_a1_generation,
            Some(sha256_bytes(b"fixture restore declaration")),
            Some(sha256_bytes(b"restore proof")),
            empty_signature(),
        );
        set_migration_disposition(&mut wire, crate::MigrationDisposition::Superseded);
        let signature = fixture
            .current_signing_key
            .sign(&migration_signature_preimage_for(&wire));
        set_migration_signature(&mut wire, hex::encode(signature.to_bytes()));
        let superseded = MigrationReceiptBytes::new(migration_bytes(wire));
        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                Some(&superseded),
                &fixture.activation_expectations(),
            )
            .map(|_| ())),
            Err(AuthorityError::MigrationDispositionMismatch)
        );

        let mut wrong_declaration = fixture.activation_expectations();
        wrong_declaration
            .migration
            .as_mut()
            .unwrap()
            .restore_declaration_digest = Some(sha256_bytes(b"other restore declaration"));
        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                Some(&receipt),
                &wrong_declaration,
            )
            .map(|_| ())),
            Err(AuthorityError::RestoreDeclarationMismatch)
        );

        let mut incomplete = fixture.activation_expectations();
        incomplete
            .migration
            .as_mut()
            .unwrap()
            .restore_declaration_digest = None;
        assert_eq!(
            with_verification_brand(|brand| verify_for_establishment(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                Some(&receipt),
                &incomplete,
            )
            .map(|_| ())),
            Err(AuthorityError::RestoreBindingIncomplete)
        );

        let exact_declaration = sha256_bytes(b"independently supplied declaration");
        let exact_proof = sha256_bytes(b"independently supplied proof");
        let exact = RawAuthorityFixture::accepted_migration_with_restore_bindings(
            OldRootState::Rootless,
            Some(exact_declaration.clone()),
            Some(exact_proof.clone()),
        );
        let exact_expectations = exact.activation_expectations().migration.unwrap();
        assert_eq!(
            exact_expectations.restore_declaration_digest,
            Some(exact_declaration)
        );
        assert_eq!(exact_expectations.restore_proof_digest, Some(exact_proof));
        assert!(restart(&exact).is_ok());
    }

    #[test]
    fn nonaccepted_migration_dispositions_mint_only_sealed_freeze_classification() {
        let fixture = RawAuthorityFixture::accepted_migration(
            OldRootState::Rootless,
            Some(sha256_bytes(b"restore proof")),
        );
        let expected_declaration = fixture
            .activation_expectations()
            .migration
            .unwrap()
            .restore_declaration_digest;
        for disposition in [
            crate::MigrationDisposition::Observed,
            crate::MigrationDisposition::Superseded,
            crate::MigrationDisposition::Refused,
        ] {
            let receipt = fixture
                .migration_receipt_with_disposition(disposition)
                .unwrap();
            let verified = with_verification_brand(|brand| {
                verify_nonaccepted_migration_classification(
                    &brand,
                    &fixture.custody(),
                    &fixture.presented_set(),
                    &receipt,
                    &fixture.activation_expectations(),
                )
                .map(|classification| {
                    assert_eq!(classification.disposition(), disposition);
                    assert_eq!(classification.occurrence_id(), FIXTURE_OCCURRENCE_ID);
                    assert_eq!(classification.old_root_state(), &OldRootState::Rootless);
                    assert_eq!(
                        classification.restore_declaration_digest(),
                        expected_declaration.as_ref()
                    );
                    assert!(classification.restore_proof_digest().is_some());
                    classification.reverify_store_owned_presented_set(&fixture.presented_set())?;
                    Ok::<_, AuthorityError>(())
                })?
            });
            assert_eq!(verified, Ok(()));
        }

        let accepted = fixture.migration_receipt().unwrap();
        assert_eq!(
            with_verification_brand(|brand| verify_nonaccepted_migration_classification(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                &accepted,
                &fixture.activation_expectations(),
            )
            .map(|_| ())),
            Err(AuthorityError::MigrationDispositionMismatch)
        );

        let superseded_anchor_change = RawAuthorityFixture::accepted_migration(
            OldRootState::Rooted {
                trust_anchor_id: sha256_bytes(b"evidence-frozen predecessor anchor"),
            },
            None,
        );
        let superseded = superseded_anchor_change
            .migration_receipt_with_disposition(crate::MigrationDisposition::Superseded)
            .unwrap();
        assert!(
            with_verification_brand(|brand| verify_nonaccepted_migration_classification(
                &brand,
                &superseded_anchor_change.custody(),
                &superseded_anchor_change.presented_set(),
                &superseded,
                &superseded_anchor_change.activation_expectations(),
            )
            .map(|_| ()))
            .is_ok()
        );
    }

    #[test]
    fn v7_absent_empty_and_multiple_genesis_dispositions_are_sealed_nonmigratable_evidence() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let source_digest = sha256_bytes(b"locked schema-v7 source logical state");
        let declaration = Some(sha256_bytes(b"official restore declaration"));
        for genesis_identities in [
            Vec::new(),
            vec![String::new()],
            vec!["genesis/a".to_owned(), "genesis/b".to_owned()],
        ] {
            for disposition in [
                crate::MigrationDisposition::Observed,
                crate::MigrationDisposition::Superseded,
                crate::MigrationDisposition::Refused,
            ] {
                let expectations = cardinality_expectations(
                    genesis_identities.clone(),
                    source_digest.clone(),
                    OldRootState::Rootless,
                    declaration.clone(),
                );
                let raw = fixture.v7_cardinality_disposition(
                    disposition,
                    genesis_identities.clone(),
                    source_digest.clone(),
                    OldRootState::Rootless,
                    declaration.clone(),
                );
                let result = with_verification_brand(|brand| {
                    let verified = verify_v7_cardinality_disposition(
                        &brand,
                        fixture.custody().genesis_a1_bytes(),
                        &raw,
                        &expectations,
                    )?;
                    assert_eq!(verified.disposition(), disposition);
                    assert_eq!(verified.genesis_identities(), genesis_identities);
                    assert_eq!(verified.source_logical_digest(), &source_digest);
                    assert_eq!(verified.restore_declaration_digest(), declaration.as_ref());
                    verified.reverify_exact_expectations(&expectations)?;
                    Ok::<_, AuthorityError>(())
                });
                assert_eq!(result, Ok(()));
            }
        }
    }

    #[test]
    fn v7_cardinality_and_accepted_shapes_refuse() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let source_digest = sha256_bytes(b"schema-v7 source");
        let root = OldRootState::Rootless;

        let one = vec!["genesis/only".to_owned()];
        let one_raw = fixture.v7_cardinality_disposition(
            crate::MigrationDisposition::Observed,
            one.clone(),
            source_digest.clone(),
            root.clone(),
            None,
        );
        assert_eq!(
            with_verification_brand(|brand| verify_v7_cardinality_disposition(
                &brand,
                fixture.custody().genesis_a1_bytes(),
                &one_raw,
                &cardinality_expectations(one, source_digest.clone(), root.clone(), None),
            )
            .map(|_| ())),
            Err(AuthorityError::V7CardinalityInvalid)
        );

        let unsorted = vec!["genesis/b".to_owned(), "genesis/a".to_owned()];
        let unsorted_raw = fixture.v7_cardinality_disposition(
            crate::MigrationDisposition::Observed,
            unsorted.clone(),
            source_digest.clone(),
            root.clone(),
            None,
        );
        assert_eq!(
            with_verification_brand(|brand| verify_v7_cardinality_disposition(
                &brand,
                fixture.custody().genesis_a1_bytes(),
                &unsorted_raw,
                &V7CardinalityDispositionExpectations {
                    genesis_identities: unsorted,
                    source_logical_digest: source_digest.clone(),
                    old_root_state: root.clone(),
                    domain: FIXTURE_DOMAIN.to_owned(),
                    policy_floor: 1,
                    restore_declaration_digest: None,
                },
            )
            .map(|_| ())),
            Err(AuthorityError::V7CardinalityInvalid)
        );

        let multiple = vec!["genesis/a".to_owned(), "genesis/b".to_owned()];
        let accepted = fixture.v7_cardinality_disposition(
            crate::MigrationDisposition::Accepted,
            multiple.clone(),
            source_digest.clone(),
            root.clone(),
            None,
        );
        assert_eq!(
            with_verification_brand(|brand| verify_v7_cardinality_disposition(
                &brand,
                fixture.custody().genesis_a1_bytes(),
                &accepted,
                &cardinality_expectations(multiple, source_digest, root, None),
            )
            .map(|_| ())),
            Err(AuthorityError::V7CardinalityAcceptedForbidden)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v7_cardinality_signature_digest_and_exact_fact_substitutions_refuse() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let identities = vec!["genesis/a".to_owned(), "genesis/b".to_owned()];
        let source = sha256_bytes(b"schema-v7 exact logical digest");
        let root = OldRootState::Rooted {
            trust_anchor_id: sha256_bytes(b"historical root"),
        };
        let declaration = Some(sha256_bytes(b"official restore declaration"));
        let expectations = cardinality_expectations(
            identities.clone(),
            source.clone(),
            root.clone(),
            declaration.clone(),
        );
        let verify = |raw: &V7CardinalityDispositionBytes| {
            with_verification_brand(|brand| {
                verify_v7_cardinality_disposition(
                    &brand,
                    fixture.custody().genesis_a1_bytes(),
                    raw,
                    &expectations,
                )
                .map(|_| ())
            })
        };

        let invalid_signature = signed_cardinality_disposition(
            &fixture,
            crate::MigrationDisposition::Observed,
            identities.clone(),
            source.clone(),
            root.clone(),
            FIXTURE_DOMAIN,
            1,
            declaration.clone(),
            99,
        );
        assert_eq!(
            verify(&invalid_signature),
            Err(AuthorityError::V7CardinalityDispositionSignatureInvalid)
        );

        let valid = fixture.v7_cardinality_disposition(
            crate::MigrationDisposition::Observed,
            identities.clone(),
            source.clone(),
            root.clone(),
            declaration.clone(),
        );
        let mut digest_value: Value = serde_json::from_slice(valid.as_bytes()).unwrap();
        digest_value["disposition_digest"] =
            Value::String(sha256_bytes(b"substituted disposition digest").into_string());
        let bad_digest =
            V7CardinalityDispositionBytes::new(canonical_json_bytes(&digest_value).unwrap());
        assert_eq!(
            verify(&bad_digest),
            Err(AuthorityError::V7CardinalityDispositionDigestMismatch)
        );

        let cases = [
            (
                signed_cardinality_disposition(
                    &fixture,
                    crate::MigrationDisposition::Observed,
                    identities.clone(),
                    sha256_bytes(b"other source"),
                    root.clone(),
                    FIXTURE_DOMAIN,
                    1,
                    declaration.clone(),
                    1,
                ),
                AuthorityError::V7CardinalitySourceDigestMismatch,
            ),
            (
                signed_cardinality_disposition(
                    &fixture,
                    crate::MigrationDisposition::Observed,
                    identities.clone(),
                    source.clone(),
                    OldRootState::Rootless,
                    FIXTURE_DOMAIN,
                    1,
                    declaration.clone(),
                    1,
                ),
                AuthorityError::V7CardinalityOldRootMismatch,
            ),
            (
                signed_cardinality_disposition(
                    &fixture,
                    crate::MigrationDisposition::Observed,
                    identities.clone(),
                    source.clone(),
                    root.clone(),
                    "other/backend",
                    1,
                    declaration.clone(),
                    1,
                ),
                AuthorityError::DomainMismatch,
            ),
            (
                signed_cardinality_disposition(
                    &fixture,
                    crate::MigrationDisposition::Observed,
                    identities.clone(),
                    source.clone(),
                    root.clone(),
                    FIXTURE_DOMAIN,
                    2,
                    declaration.clone(),
                    1,
                ),
                AuthorityError::PolicyVersionUnsupported,
            ),
            (
                signed_cardinality_disposition(
                    &fixture,
                    crate::MigrationDisposition::Observed,
                    identities.clone(),
                    source.clone(),
                    root.clone(),
                    FIXTURE_DOMAIN,
                    1,
                    Some(sha256_bytes(b"other declaration")),
                    1,
                ),
                AuthorityError::RestoreDeclarationMismatch,
            ),
            (
                signed_cardinality_disposition(
                    &fixture,
                    crate::MigrationDisposition::Observed,
                    vec!["genesis/a".to_owned(), "genesis/c".to_owned()],
                    source.clone(),
                    root.clone(),
                    FIXTURE_DOMAIN,
                    1,
                    declaration,
                    1,
                ),
                AuthorityError::V7CardinalitySetMismatch,
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(verify(&raw), Err(expected));
        }
    }

    #[test]
    fn restart_uses_retained_migration_receipt_identity_not_redeclared_history() {
        let fixture = RawAuthorityFixture::accepted_migration(
            OldRootState::Rootless,
            Some(sha256_bytes(b"historical restore proof")),
        );
        assert!(restart(&fixture).is_ok());
        let mut restart_expectations = fixture.restart_expectations();
        restart_expectations.expected_migration_receipt_digest =
            Some(sha256_bytes(b"substituted receipt"));
        let receipt = fixture.migration_receipt().unwrap();
        assert_eq!(
            resolve_for_restart(
                &fixture.custody(),
                &fixture.presented_set(),
                Some(&receipt),
                &restart_expectations,
            ),
            Err(AuthorityError::MigrationReceiptDigestMismatch)
        );
    }

    #[test]
    fn restart_snapshot_projects_the_exact_terminal_a1_from_the_verified_chain() {
        let mut fixture = RawAuthorityFixture::fresh_genesis();
        let genesis = restart(&fixture).unwrap();
        assert_eq!(
            genesis.terminal_operator_authority().record_digest(),
            &fixture.current_a1_digest
        );
        assert_eq!(genesis.terminal_operator_authority().key_generation(), 1);
        assert_eq!(
            genesis.terminal_operator_authority().verification_key(),
            fixture.current_signing_key.verifying_key().as_bytes()
        );
        assert_eq!(
            genesis.terminal_operator_authority().operator_principal(),
            "operator/principal-a"
        );
        assert_eq!(genesis.terminal_operator_authority().policy_version(), 1);
        assert_eq!(genesis.terminal_operator_authority().policy_floor(), 1);
        assert_eq!(
            genesis.terminal_authority_event_digest(),
            &fixture.current_a2_digest
        );

        fixture.append_operator_rotation();
        let rotated = restart(&fixture).unwrap();
        assert_eq!(
            rotated.terminal_operator_authority().record_digest(),
            &fixture.current_a1_digest
        );
        assert_eq!(rotated.terminal_operator_authority().key_generation(), 2);
        assert_eq!(
            rotated.terminal_operator_authority().verification_key(),
            fixture.current_signing_key.verifying_key().as_bytes()
        );
        assert_eq!(
            rotated.terminal_operator_authority().cut().sequence(),
            fixture.next_sequence - 1
        );
        assert_eq!(
            rotated.terminal_authority_event_digest(),
            &fixture.current_a1_digest
        );

        fixture.append_activation_successor();
        let successor = restart(&fixture).unwrap();
        assert_eq!(
            successor.terminal_operator_authority().record_digest(),
            &fixture.current_a1_digest
        );
        assert_eq!(successor.terminal_operator_authority().key_generation(), 2);
        assert_eq!(
            successor.terminal_authority_event_digest(),
            &fixture.current_a2_digest
        );
    }

    #[test]
    fn receipt_parser_refuses_noncanonical_and_arm_inconsistent_transcripts() {
        let fixture = RawAuthorityFixture::fresh_genesis();
        let transcript = with_verification_brand(|brand| {
            verify_for_establishment(
                &brand,
                &fixture.custody(),
                &fixture.presented_set(),
                None,
                &fixture.activation_expectations(),
            )
            .unwrap()
            .establishment_receipt_transcript()
            .unwrap()
        });
        let mut noncanonical = transcript.canonical_bytes().unwrap();
        noncanonical.push(b' ');
        assert_eq!(
            EstablishmentReceiptTranscript::from_canonical_bytes(&noncanonical).unwrap_err(),
            AuthorityError::EstablishmentReceiptNonCanonical
        );
        let mut value: Value =
            serde_json::from_slice(&transcript.canonical_bytes().unwrap()).unwrap();
        value["migration_receipt_digest"] =
            Value::String(sha256_bytes(b"unexpected migration").into_string());
        let inconsistent = canonical_json_bytes(&value).unwrap();
        assert_eq!(
            EstablishmentReceiptTranscript::from_canonical_bytes(&inconsistent).unwrap_err(),
            AuthorityError::EstablishmentReceiptArmMismatch
        );
    }

    #[test]
    fn closed_scope_constant_is_exact() {
        assert_eq!(
            RUNTIME_DEPENDENCY_ADMISSION_SCOPE,
            "runtime_dependency_admission"
        );
    }
}
