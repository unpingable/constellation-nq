//! Generative Store-instance brand and sealed verification results.

use std::marker::PhantomData;

use nq_protocol::Sha256Digest;

use crate::{
    ActivationContext, AuthorityCut, AuthorityError, EstablishmentArm,
    EstablishmentReceiptTranscript,
};

/// One unforgeable, generative verification brand.
///
/// The constructor is private.  A Store obtains a fresh, invariant lifetime
/// only through [`with_verification_brand`], and its authority writer session
/// can use that same lifetime as its marker.  Separate invocations receive
/// distinct late-bound lifetimes.
pub struct VerificationBrand<'id> {
    _invariant: PhantomData<fn(&'id mut ()) -> &'id mut ()>,
}

/// Runs one operation with a fresh invariant verification brand.
///
/// The higher-ranked lifetime prevents any brand-bound establishment evidence
/// from escaping the operation.  Store code must create exactly one authority
/// writer session for the yielded brand.
pub fn with_verification_brand<R>(
    operation: impl for<'id> FnOnce(VerificationBrand<'id>) -> R,
) -> R {
    operation(VerificationBrand {
        _invariant: PhantomData,
    })
}

pub(crate) struct ResolutionFields {
    pub(crate) occurrence_id: String,
    pub(crate) domain: String,
    pub(crate) chain_root_activation_digest: Sha256Digest,
    pub(crate) controlling_tip_activation_digest: Sha256Digest,
    pub(crate) trust_anchor_id: Sha256Digest,
    pub(crate) genesis_operator_authority_digest: Sha256Digest,
    pub(crate) genesis_operator_key_generation: u64,
    pub(crate) resident_identity: String,
    pub(crate) resident_generation: u64,
    pub(crate) host_role: String,
    pub(crate) role_manifest_generation: u64,
    pub(crate) policy_version: u64,
    pub(crate) verification_cut: AuthorityCut,
    pub(crate) custody_digest: Sha256Digest,
    pub(crate) candidate_set_digest: Sha256Digest,
    pub(crate) genesis_context: ActivationContext,
    pub(crate) migration_receipt_digest: Option<Sha256Digest>,
    pub(crate) migration_receipt_canonical_bytes: Option<Vec<u8>>,
}

/// Sealed proof that the exact presented authority material resolves to one
/// controlling activation under a fresh Store-instance brand.
///
/// This type proves cryptographic and chain validity over the presented set;
/// it deliberately does not testify that the set is complete.  Store-owned
/// enumeration and exact digest correspondence remain mandatory.
pub struct ResolvedControllingActivation<'id> {
    fields: ResolutionFields,
    _invariant: PhantomData<fn(&'id mut ()) -> &'id mut ()>,
}

impl<'id> ResolvedControllingActivation<'id> {
    pub(crate) fn new(fields: ResolutionFields, _brand: &VerificationBrand<'id>) -> Self {
        Self {
            fields,
            _invariant: PhantomData,
        }
    }

    resolved_getters!();

    /// Derives the canonical Store-side establishment receipt without asking
    /// Store code to duplicate framing or select authority fields.
    ///
    /// # Errors
    ///
    /// Refuses an impossible successor-as-chain-root shape.
    pub fn establishment_receipt_transcript(
        &self,
    ) -> Result<EstablishmentReceiptTranscript, AuthorityError> {
        let arm = match self.fields.genesis_context {
            ActivationContext::FreshGenesis => EstablishmentArm::Genesis,
            ActivationContext::MigrationGenesis => EstablishmentArm::Migration,
            ActivationContext::Successor => return Err(AuthorityError::A2GenesisShapeMismatch),
        };
        Ok(EstablishmentReceiptTranscript::new(
            self.fields.occurrence_id.clone(),
            self.fields.chain_root_activation_digest.clone(),
            self.fields.controlling_tip_activation_digest.clone(),
            self.fields.trust_anchor_id.clone(),
            self.fields.genesis_operator_authority_digest.clone(),
            self.fields.genesis_operator_key_generation,
            self.fields.domain.clone(),
            self.fields.verification_cut.clone(),
            self.fields.policy_version,
            arm,
            self.fields.migration_receipt_digest.clone(),
            self.fields.custody_digest.clone(),
            self.fields.candidate_set_digest.clone(),
        ))
    }
}

/// Read-only restart result.  It is intentionally a different type from
/// establishment evidence and has no conversion into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllingActivationSnapshot {
    fields: SnapshotFields,
}

impl ControllingActivationSnapshot {
    pub(crate) fn new(fields: ResolutionFields) -> Self {
        Self {
            fields: fields.into(),
        }
    }

    snapshot_getters!();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotFields {
    occurrence_id: String,
    domain: String,
    chain_root_activation_digest: Sha256Digest,
    controlling_tip_activation_digest: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    genesis_operator_authority_digest: Sha256Digest,
    genesis_operator_key_generation: u64,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    policy_version: u64,
    verification_cut: AuthorityCut,
    custody_digest: Sha256Digest,
    candidate_set_digest: Sha256Digest,
    genesis_context: ActivationContext,
    migration_receipt_digest: Option<Sha256Digest>,
}

impl From<ResolutionFields> for SnapshotFields {
    fn from(fields: ResolutionFields) -> Self {
        Self {
            occurrence_id: fields.occurrence_id,
            domain: fields.domain,
            chain_root_activation_digest: fields.chain_root_activation_digest,
            controlling_tip_activation_digest: fields.controlling_tip_activation_digest,
            trust_anchor_id: fields.trust_anchor_id,
            genesis_operator_authority_digest: fields.genesis_operator_authority_digest,
            genesis_operator_key_generation: fields.genesis_operator_key_generation,
            resident_identity: fields.resident_identity,
            resident_generation: fields.resident_generation,
            host_role: fields.host_role,
            role_manifest_generation: fields.role_manifest_generation,
            policy_version: fields.policy_version,
            verification_cut: fields.verification_cut,
            custody_digest: fields.custody_digest,
            candidate_set_digest: fields.candidate_set_digest,
            genesis_context: fields.genesis_context,
            migration_receipt_digest: fields.migration_receipt_digest,
        }
    }
}

pub(crate) struct VerifiedEventFields {
    pub(crate) canonical_bytes: Vec<u8>,
    pub(crate) record_digest: Sha256Digest,
    pub(crate) resulting_candidate_set_digest: Sha256Digest,
}

macro_rules! verified_event_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        pub struct $name<'id> {
            fields: VerifiedEventFields,
            _invariant: PhantomData<fn(&'id mut ()) -> &'id mut ()>,
        }

        impl<'id> $name<'id> {
            pub(crate) fn new(
                fields: VerifiedEventFields,
                _brand: &VerificationBrand<'id>,
            ) -> Self {
                Self {
                    fields,
                    _invariant: PhantomData,
                }
            }

            /// Returns the exact verified canonical record bytes.
            #[must_use]
            pub fn canonical_bytes(&self) -> &[u8] {
                &self.fields.canonical_bytes
            }

            /// Returns the exact native record digest.
            #[must_use]
            pub const fn record_digest(&self) -> &Sha256Digest {
                &self.fields.record_digest
            }

            /// Returns the exact candidate-set digest after this event.
            #[must_use]
            pub const fn resulting_candidate_set_digest(&self) -> &Sha256Digest {
                &self.fields.resulting_candidate_set_digest
            }
        }
    };
}

verified_event_type!(
    /// Sealed, brand-bound verification result for one A1 rotation.
    VerifiedOperatorAuthorityRotation
);
verified_event_type!(
    /// Sealed, brand-bound verification result for one A2 successor.
    VerifiedResidentActivationSuccessor
);
verified_event_type!(
    /// Sealed, brand-bound verification result for one prospective revocation.
    VerifiedActivationRevocation
);

macro_rules! resolved_getters {
    () => {
        /// Returns the exact signed Store occurrence.
        #[must_use]
        pub fn occurrence_id(&self) -> &str {
            &self.fields.occurrence_id
        }
        /// Returns the runtime/backend domain.
        #[must_use]
        pub fn domain(&self) -> &str {
            &self.fields.domain
        }
        /// Returns the receipt-pinnable A2 chain root.
        #[must_use]
        pub const fn chain_root_activation_digest(&self) -> &Sha256Digest {
            &self.fields.chain_root_activation_digest
        }
        /// Returns the unique controlling activation tip.
        #[must_use]
        pub const fn controlling_tip_activation_digest(&self) -> &Sha256Digest {
            &self.fields.controlling_tip_activation_digest
        }
        /// Returns the immutable dependency trust anchor.
        #[must_use]
        pub const fn trust_anchor_id(&self) -> &Sha256Digest {
            &self.fields.trust_anchor_id
        }
        /// Returns the custody genesis A1 identity.
        #[must_use]
        pub const fn genesis_operator_authority_digest(&self) -> &Sha256Digest {
            &self.fields.genesis_operator_authority_digest
        }
        /// Returns the custody genesis A1 key generation.
        #[must_use]
        pub const fn genesis_operator_key_generation(&self) -> u64 {
            self.fields.genesis_operator_key_generation
        }
        /// Returns the exact enrolled resident identity.
        #[must_use]
        pub fn resident_identity(&self) -> &str {
            &self.fields.resident_identity
        }
        /// Returns the exact resident generation.
        #[must_use]
        pub const fn resident_generation(&self) -> u64 {
            self.fields.resident_generation
        }
        /// Returns the exact host role.
        #[must_use]
        pub fn host_role(&self) -> &str {
            &self.fields.host_role
        }
        /// Returns the exact role-manifest generation.
        #[must_use]
        pub const fn role_manifest_generation(&self) -> u64 {
            self.fields.role_manifest_generation
        }
        /// Returns the controlling activation policy version.
        #[must_use]
        pub const fn policy_version(&self) -> u64 {
            self.fields.policy_version
        }
        /// Returns the structurally reached terminal authority cut.
        #[must_use]
        pub const fn verification_cut(&self) -> &AuthorityCut {
            &self.fields.verification_cut
        }
        /// Returns the exact external genesis-custody binding.
        #[must_use]
        pub const fn custody_digest(&self) -> &Sha256Digest {
            &self.fields.custody_digest
        }
        /// Returns the exact order-independent Store-resident set binding.
        #[must_use]
        pub const fn candidate_set_digest(&self) -> &Sha256Digest {
            &self.fields.candidate_set_digest
        }
        /// Returns the chain-root establishment context.
        #[must_use]
        pub const fn genesis_context(&self) -> ActivationContext {
            self.fields.genesis_context
        }
        /// Returns the exact migration receipt identity, when applicable.
        #[must_use]
        pub const fn migration_receipt_digest(&self) -> Option<&Sha256Digest> {
            self.fields.migration_receipt_digest.as_ref()
        }
        /// Returns exact verified signed migration-receipt bytes for one-use consumption.
        #[must_use]
        pub fn migration_receipt_canonical_bytes(&self) -> Option<&[u8]> {
            self.fields.migration_receipt_canonical_bytes.as_deref()
        }
    };
}

macro_rules! snapshot_getters {
    () => {
        /// Returns the exact signed Store occurrence.
        #[must_use]
        pub fn occurrence_id(&self) -> &str {
            &self.fields.occurrence_id
        }
        /// Returns the runtime/backend domain.
        #[must_use]
        pub fn domain(&self) -> &str {
            &self.fields.domain
        }
        /// Returns the receipt-pinned A2 chain root.
        #[must_use]
        pub const fn chain_root_activation_digest(&self) -> &Sha256Digest {
            &self.fields.chain_root_activation_digest
        }
        /// Returns the current unique controlling activation tip.
        #[must_use]
        pub const fn controlling_tip_activation_digest(&self) -> &Sha256Digest {
            &self.fields.controlling_tip_activation_digest
        }
        /// Returns the immutable dependency trust anchor.
        #[must_use]
        pub const fn trust_anchor_id(&self) -> &Sha256Digest {
            &self.fields.trust_anchor_id
        }
        /// Returns the custody genesis A1 identity.
        #[must_use]
        pub const fn genesis_operator_authority_digest(&self) -> &Sha256Digest {
            &self.fields.genesis_operator_authority_digest
        }
        /// Returns the custody genesis A1 key generation.
        #[must_use]
        pub const fn genesis_operator_key_generation(&self) -> u64 {
            self.fields.genesis_operator_key_generation
        }
        /// Returns the exact enrolled resident identity.
        #[must_use]
        pub fn resident_identity(&self) -> &str {
            &self.fields.resident_identity
        }
        /// Returns the exact resident generation.
        #[must_use]
        pub const fn resident_generation(&self) -> u64 {
            self.fields.resident_generation
        }
        /// Returns the exact host role.
        #[must_use]
        pub fn host_role(&self) -> &str {
            &self.fields.host_role
        }
        /// Returns the exact role-manifest generation.
        #[must_use]
        pub const fn role_manifest_generation(&self) -> u64 {
            self.fields.role_manifest_generation
        }
        /// Returns the controlling activation policy version.
        #[must_use]
        pub const fn policy_version(&self) -> u64 {
            self.fields.policy_version
        }
        /// Returns the structurally reached terminal authority cut.
        #[must_use]
        pub const fn verification_cut(&self) -> &AuthorityCut {
            &self.fields.verification_cut
        }
        /// Returns the exact external genesis-custody binding.
        #[must_use]
        pub const fn custody_digest(&self) -> &Sha256Digest {
            &self.fields.custody_digest
        }
        /// Returns the exact order-independent Store-resident set binding.
        #[must_use]
        pub const fn candidate_set_digest(&self) -> &Sha256Digest {
            &self.fields.candidate_set_digest
        }
        /// Returns the chain-root establishment context.
        #[must_use]
        pub const fn genesis_context(&self) -> ActivationContext {
            self.fields.genesis_context
        }
        /// Returns the exact migration receipt identity, when applicable.
        #[must_use]
        pub const fn migration_receipt_digest(&self) -> Option<&Sha256Digest> {
            self.fields.migration_receipt_digest.as_ref()
        }
    };
}

use resolved_getters;
use snapshot_getters;
