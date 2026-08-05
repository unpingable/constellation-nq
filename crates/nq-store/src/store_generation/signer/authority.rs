//! Exact authority separation and terminal-A1 bootstrap projection.
//!
//! This module consumes a complete Store-owned authority snapshot.  It never
//! signs as A1 and never converts A2 applicability, possession, custody, or a
//! Store-integrity key into external grant authority.

use nq_protocol::Sha256Digest;
use nq_runtime_dependency_authority::{
    ControllingActivationSnapshot, RUNTIME_DEPENDENCY_ADMISSION_SCOPE,
    ResolvedTerminalOperatorAuthority,
};

use crate::{CurrentActivationResolverInputV1, verify_n_08_complete_gen4_authority_ledger};

use super::external_governance::{TerminalA1AuthenticityVerifierV1, TerminalA1IssuerClaimV1};
use super::messages::{ClosedMessageFamilyV1, SignerIdentityV1};
use super::result::SignerRefusalV2;

pub(crate) const A2_APPLICABILITY_INTERPRETATION_V1: &str =
    "nq.c2.a1_runtime_dependency_admission_refinement.v1";

/// Borrowed terminal-A1 projection from one complete Store-owned resolution.
///
/// The value is neither cloneable nor serializable and cannot be built from a
/// digest, candidate list, Boolean currentness assertion, or detached resolver
/// result. Its lifetime ties the exact complete Store enumeration to the exact
/// resolver snapshot that selected the terminal A1 by verified adjacency.
pub(crate) struct TerminalA1AuthoritySnapshotV1<'snapshot> {
    input: &'snapshot CurrentActivationResolverInputV1<'snapshot>,
    resolved: &'snapshot ControllingActivationSnapshot,
}

impl TerminalA1AuthoritySnapshotV1<'_> {
    pub(crate) const fn occurrence(&self) -> &str {
        self.input.occurrence_id()
    }

    pub(crate) const fn snapshot_identity(&self) -> &Sha256Digest {
        self.input.candidate_set_digest()
    }

    pub(crate) const fn trust_anchor_id(&self) -> &Sha256Digest {
        self.input.root()
    }

    pub(crate) const fn issuance_cut(&self) -> u64 {
        self.resolved.verification_cut().sequence()
    }

    pub(crate) const fn terminal(&self) -> &ResolvedTerminalOperatorAuthority {
        self.resolved.terminal_operator_authority()
    }

    pub(crate) const fn terminal_event(&self) -> &Sha256Digest {
        self.resolved.terminal_authority_event_digest()
    }

    pub(crate) const fn controlling_activation(&self) -> &Sha256Digest {
        self.resolved.controlling_tip_activation_digest()
    }

    pub(crate) fn resident_identity(&self) -> &str {
        self.resolved.resident_identity()
    }

    pub(crate) const fn resident_generation(&self) -> u64 {
        self.resolved.resident_generation()
    }

    pub(crate) fn host_role(&self) -> &str {
        self.resolved.host_role()
    }

    pub(crate) const fn role_manifest_generation(&self) -> u64 {
        self.resolved.role_manifest_generation()
    }

    pub(crate) const fn activation_policy_version(&self) -> u64 {
        self.resolved.policy_version()
    }
}

/// The only A1 key generation permitted to verify an initial bootstrap grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalA1BootstrapIssuerV1 {
    pub(crate) snapshot_identity: Sha256Digest,
    pub(crate) occurrence: String,
    pub(crate) trust_anchor_id: Sha256Digest,
    pub(crate) record_digest: Sha256Digest,
    pub(crate) key_generation: u64,
    pub(crate) verifying_key: [u8; 32],
    pub(crate) operator_principal: String,
    pub(crate) domain: String,
    pub(crate) policy_version: u64,
    pub(crate) policy_floor: u64,
    pub(crate) terminal_a1_cut: u64,
    pub(crate) terminal_event: Sha256Digest,
    pub(crate) issuance_cut: u64,
}

/// Complete signer bootstrap grant scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapGrantScopeV1 {
    pub(crate) occurrence: String,
    pub(crate) physical_generation: SignerIdentityV1,
    pub(crate) resident: SignerIdentityV1,
    pub(crate) role: SignerIdentityV1,
    pub(crate) role_manifest_generation: SignerIdentityV1,
    pub(crate) domain: SignerIdentityV1,
    pub(crate) signer_scope: SignerIdentityV1,
    pub(crate) active_policy: SignerIdentityV1,
    pub(crate) proposed_key_generation: SignerIdentityV1,
    pub(crate) proposed_verifying_key: [u8; 32],
    pub(crate) a2_snapshot: SignerIdentityV1,
    pub(crate) grant_cut: u64,
}

/// Verified one-to-one grant/request identity; this is evidence, not a signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapGrantIdentityV1 {
    pub(crate) request_identity: SignerIdentityV1,
    pub(crate) grant_identity: SignerIdentityV1,
    pub(crate) issuer: TerminalA1BootstrapIssuerV1,
    pub(crate) scope: BootstrapGrantScopeV1,
    pub(crate) canonical_carrier_digest: SignerIdentityV1,
}

/// Explicit A2 applicability input.  Its type has no issuing or signing API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct A2ApplicabilityRefinementV1 {
    pub(crate) grant_identity: SignerIdentityV1,
    pub(crate) a2_snapshot: SignerIdentityV1,
    pub(crate) interpretation: &'static str,
    pub(crate) applicable: bool,
}

/// Exact interpretation of A2 succession against an existing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivationSuccessorDispositionV1 {
    ExistingGrantSurvives,
    ExactRegrantSupersedes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivationSuccessorGrantV1 {
    pub(crate) prior_grant_identity: SignerIdentityV1,
    pub(crate) effective_grant_identity: SignerIdentityV1,
    pub(crate) prior_a2_snapshot: SignerIdentityV1,
    pub(crate) current_a2_snapshot: SignerIdentityV1,
    pub(crate) disposition: ActivationSuccessorDispositionV1,
    pub(crate) effective_cut: u64,
}

/// Structural witness that A1, A2, and Store-integrity signer coordinates are
/// distinct and have not been converted into one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignerAuthoritySeparationV1 {
    pub(crate) terminal_a1_key_generation: SignerIdentityV1,
    pub(crate) a2_snapshot: SignerIdentityV1,
    pub(crate) store_signer_key_generation: SignerIdentityV1,
    pub(crate) bootstrap_grant_identity: SignerIdentityV1,
}

/// Store-owned ingress projection for an already verified external A1
/// bootstrap/regrant carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalA1ExternalCarrierIngressV1 {
    pub(crate) family: ClosedMessageFamilyV1,
    pub(crate) issuer: TerminalA1BootstrapIssuerV1,
    pub(crate) grant: BootstrapGrantIdentityV1,
    pub(crate) applicability: A2ApplicabilityRefinementV1,
}

fn nonzero(identity: &SignerIdentityV1) -> bool {
    identity.iter().any(|byte| *byte != 0)
}

fn verify_snapshot(snapshot: &TerminalA1AuthoritySnapshotV1<'_>) -> Result<(), SignerRefusalV2> {
    let terminal = snapshot.terminal();
    if snapshot.occurrence().is_empty()
        || snapshot.snapshot_identity().as_str().is_empty()
        || snapshot.trust_anchor_id().as_str().is_empty()
        || snapshot.terminal_event().as_str().is_empty()
        || terminal.record_digest().as_str().is_empty()
        || terminal.key_generation() == 0
        || terminal.verification_key().iter().all(|byte| *byte == 0)
        || terminal.operator_principal().is_empty()
        || terminal.domain().is_empty()
        || terminal.permitted_scope() != RUNTIME_DEPENDENCY_ADMISSION_SCOPE
        || terminal.policy_version() == 0
        || terminal.policy_floor() == 0
        || terminal.policy_version() < terminal.policy_floor()
        || terminal.cut().sequence() > snapshot.issuance_cut()
    {
        return Err(SignerRefusalV2::IncompleteTerminalA1Snapshot);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_03_issuer_currentness_is_resolved_complete_store_owned<'snapshot>(
    input: &'snapshot CurrentActivationResolverInputV1<'snapshot>,
    resolved: &'snapshot ControllingActivationSnapshot,
) -> Result<TerminalA1AuthoritySnapshotV1<'snapshot>, SignerRefusalV2> {
    verify_n_08_complete_gen4_authority_ledger(input)
        .map_err(|_| SignerRefusalV2::IncompleteTerminalA1Snapshot)?;
    if resolved.occurrence_id() != input.occurrence_id()
        || resolved.trust_anchor_id() != input.root()
        || resolved.candidate_set_digest() != input.candidate_set_digest()
        || resolved.domain() != input.receipt().transcript.domain()
        || resolved.chain_root_activation_digest()
            != input.receipt().transcript.chain_root_activation_digest()
    {
        return Err(SignerRefusalV2::WrongTerminalA1Issuer);
    }
    let snapshot = TerminalA1AuthoritySnapshotV1 { input, resolved };
    verify_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub(crate) fn verify_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(
    snapshot: &TerminalA1AuthoritySnapshotV1<'_>,
) -> Result<(), SignerRefusalV2> {
    verify_snapshot(snapshot)
}

pub(crate) fn construct_sg_n_02_bootstrap_grant_issuer_is_exactly_resolver_selected(
    snapshot: &TerminalA1AuthoritySnapshotV1<'_>,
    store_signer_verifying_key: [u8; 32],
) -> Result<TerminalA1BootstrapIssuerV1, SignerRefusalV2> {
    verify_snapshot(snapshot)?;
    let terminal = snapshot.terminal();
    if terminal.verification_key() == &store_signer_verifying_key {
        return Err(SignerRefusalV2::IssuerSignerKeyCollision);
    }
    Ok(TerminalA1BootstrapIssuerV1 {
        snapshot_identity: snapshot.snapshot_identity().clone(),
        occurrence: snapshot.occurrence().to_owned(),
        trust_anchor_id: snapshot.trust_anchor_id().clone(),
        record_digest: terminal.record_digest().clone(),
        key_generation: terminal.key_generation(),
        verifying_key: *terminal.verification_key(),
        operator_principal: terminal.operator_principal().to_owned(),
        domain: terminal.domain().to_owned(),
        policy_version: terminal.policy_version(),
        policy_floor: terminal.policy_floor(),
        terminal_a1_cut: terminal.cut().sequence(),
        terminal_event: snapshot.terminal_event().clone(),
        issuance_cut: snapshot.issuance_cut(),
    })
}

pub(crate) fn verify_sg_n_02_bootstrap_grant_issuer_is_exactly_resolver_selected(
    issuer: &TerminalA1BootstrapIssuerV1,
    snapshot: &TerminalA1AuthoritySnapshotV1<'_>,
    store_signer_verifying_key: [u8; 32],
) -> Result<(), SignerRefusalV2> {
    let expected = construct_sg_n_02_bootstrap_grant_issuer_is_exactly_resolver_selected(
        snapshot,
        store_signer_verifying_key,
    )?;
    if *issuer != expected {
        return Err(SignerRefusalV2::WrongTerminalA1Issuer);
    }
    Ok(())
}

impl TerminalA1AuthenticityVerifierV1 for TerminalA1AuthoritySnapshotV1<'_> {
    fn verify_unique_terminal_a1(
        &self,
        claim: &TerminalA1IssuerClaimV1,
    ) -> Result<(), SignerRefusalV2> {
        verify_snapshot(self)?;
        let terminal = self.terminal();
        if claim.digest != terminal.record_digest().as_str()
            || claim.key_generation != terminal.key_generation()
            || claim.verification_key != *terminal.verification_key()
            || claim.operator_principal != terminal.operator_principal()
            || claim.domain != terminal.domain()
            || claim.policy_version != terminal.policy_version()
            || claim.policy_floor != terminal.policy_floor()
            || claim.issued_against_gen4_cut != self.issuance_cut()
            || claim.issued_against_terminal_event != self.terminal_event().as_str()
            || claim.issued_against_candidate_set != self.snapshot_identity().as_str()
        {
            return Err(SignerRefusalV2::WrongTerminalA1Issuer);
        }
        Ok(())
    }
}

pub(crate) fn construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
    issuer: &TerminalA1BootstrapIssuerV1,
    scope: BootstrapGrantScopeV1,
) -> Result<BootstrapGrantScopeV1, SignerRefusalV2> {
    if scope.grant_cut < issuer.issuance_cut
        || scope.occurrence != issuer.occurrence
        || [
            scope.physical_generation,
            scope.resident,
            scope.role,
            scope.role_manifest_generation,
            scope.domain,
            scope.signer_scope,
            scope.active_policy,
            scope.proposed_key_generation,
            scope.a2_snapshot,
        ]
        .iter()
        .any(|identity| !nonzero(identity))
        || scope.proposed_verifying_key == issuer.verifying_key
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(scope)
}

pub(crate) fn verify_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
    issuer: &TerminalA1BootstrapIssuerV1,
    scope: &BootstrapGrantScopeV1,
) -> Result<(), SignerRefusalV2> {
    construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(issuer, scope.clone())
        .map(|_| ())
}

pub(crate) fn construct_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
    issuer: TerminalA1BootstrapIssuerV1,
    scope: BootstrapGrantScopeV1,
    request_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    canonical_carrier_digest: SignerIdentityV1,
) -> Result<BootstrapGrantIdentityV1, SignerRefusalV2> {
    verify_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(&issuer, &scope)?;
    if [request_identity, grant_identity, canonical_carrier_digest]
        .iter()
        .any(|identity| !nonzero(identity))
        || request_identity == grant_identity
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(BootstrapGrantIdentityV1 {
        request_identity,
        grant_identity,
        issuer,
        scope,
        canonical_carrier_digest,
    })
}

pub(crate) fn verify_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
    grant: &BootstrapGrantIdentityV1,
) -> Result<(), SignerRefusalV2> {
    let rebuilt = construct_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
        grant.issuer.clone(),
        grant.scope.clone(),
        grant.request_identity,
        grant.grant_identity,
        grant.canonical_carrier_digest,
    )?;
    if rebuilt != *grant {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_06_current_a2_is_applicability_constraint_named_by(
    grant: &BootstrapGrantIdentityV1,
    current_a2_snapshot: SignerIdentityV1,
) -> Result<A2ApplicabilityRefinementV1, SignerRefusalV2> {
    if grant.scope.a2_snapshot != current_a2_snapshot {
        return Err(SignerRefusalV2::A2ApplicabilityMismatch);
    }
    Ok(A2ApplicabilityRefinementV1 {
        grant_identity: grant.grant_identity,
        a2_snapshot: current_a2_snapshot,
        interpretation: A2_APPLICABILITY_INTERPRETATION_V1,
        applicable: true,
    })
}

pub(crate) fn verify_sg_n_06_current_a2_is_applicability_constraint_named_by(
    applicability: &A2ApplicabilityRefinementV1,
    grant: &BootstrapGrantIdentityV1,
) -> Result<(), SignerRefusalV2> {
    if applicability.grant_identity != grant.grant_identity
        || applicability.a2_snapshot != grant.scope.a2_snapshot
        || applicability.interpretation != A2_APPLICABILITY_INTERPRETATION_V1
        || !applicability.applicable
    {
        return Err(SignerRefusalV2::A2ApplicabilityMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_07_a2_succession_follows_grant_survival_regrant_supersession(
    prior_grant_identity: SignerIdentityV1,
    effective_grant_identity: SignerIdentityV1,
    prior_a2_snapshot: SignerIdentityV1,
    current_a2_snapshot: SignerIdentityV1,
    disposition: ActivationSuccessorDispositionV1,
    effective_cut: u64,
) -> Result<ActivationSuccessorGrantV1, SignerRefusalV2> {
    let grant = ActivationSuccessorGrantV1 {
        prior_grant_identity,
        effective_grant_identity,
        prior_a2_snapshot,
        current_a2_snapshot,
        disposition,
        effective_cut,
    };
    verify_sg_n_07_a2_succession_follows_grant_survival_regrant_supersession(&grant)?;
    Ok(grant)
}

pub(crate) fn verify_sg_n_07_a2_succession_follows_grant_survival_regrant_supersession(
    grant: &ActivationSuccessorGrantV1,
) -> Result<(), SignerRefusalV2> {
    if grant.effective_cut == 0
        || !nonzero(&grant.prior_grant_identity)
        || !nonzero(&grant.effective_grant_identity)
        || !nonzero(&grant.prior_a2_snapshot)
        || !nonzero(&grant.current_a2_snapshot)
    {
        return Err(SignerRefusalV2::ExternalCarrierStale);
    }
    match grant.disposition {
        ActivationSuccessorDispositionV1::ExistingGrantSurvives => {
            if grant.prior_grant_identity != grant.effective_grant_identity {
                return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
            }
        }
        ActivationSuccessorDispositionV1::ExactRegrantSupersedes => {
            if grant.prior_grant_identity == grant.effective_grant_identity {
                return Err(SignerRefusalV2::ExternalCarrierReplay);
            }
        }
    }
    Ok(())
}

pub(crate) fn construct_sg_n_01_keep_operator_authority_a1_possession_a2_activation(
    terminal_a1_key_generation: SignerIdentityV1,
    a2_snapshot: SignerIdentityV1,
    store_signer_key_generation: SignerIdentityV1,
    bootstrap_grant_identity: SignerIdentityV1,
) -> Result<SignerAuthoritySeparationV1, SignerRefusalV2> {
    let separation = SignerAuthoritySeparationV1 {
        terminal_a1_key_generation,
        a2_snapshot,
        store_signer_key_generation,
        bootstrap_grant_identity,
    };
    verify_sg_n_01_keep_operator_authority_a1_possession_a2_activation(&separation)?;
    Ok(separation)
}

pub(crate) fn verify_sg_n_01_keep_operator_authority_a1_possession_a2_activation(
    separation: &SignerAuthoritySeparationV1,
) -> Result<(), SignerRefusalV2> {
    let identities = [
        separation.terminal_a1_key_generation,
        separation.a2_snapshot,
        separation.store_signer_key_generation,
        separation.bootstrap_grant_identity,
    ];
    if identities.iter().any(|identity| !nonzero(identity))
        || separation.terminal_a1_key_generation == separation.store_signer_key_generation
        || separation.a2_snapshot == separation.terminal_a1_key_generation
        || separation.a2_snapshot == separation.store_signer_key_generation
    {
        return Err(SignerRefusalV2::IssuerSignerKeyCollision);
    }
    Ok(())
}

pub(crate) fn construct_sg_wu_01_a1_grant_interpretation_owner_terminal_a1_projection(
    issuer: TerminalA1BootstrapIssuerV1,
    grant: BootstrapGrantIdentityV1,
    applicability: A2ApplicabilityRefinementV1,
) -> Result<TerminalA1ExternalCarrierIngressV1, SignerRefusalV2> {
    let ingress = TerminalA1ExternalCarrierIngressV1 {
        family: ClosedMessageFamilyV1::Msg01BootstrapGrant,
        issuer,
        grant,
        applicability,
    };
    verify_sg_wu_01_a1_grant_interpretation_owner_terminal_a1_projection(&ingress)?;
    Ok(ingress)
}

pub(crate) fn verify_sg_wu_01_a1_grant_interpretation_owner_terminal_a1_projection(
    ingress: &TerminalA1ExternalCarrierIngressV1,
) -> Result<(), SignerRefusalV2> {
    if ingress.family != ClosedMessageFamilyV1::Msg01BootstrapGrant
        || ingress.family.owner() != super::messages::MessageFamilyOwnerV1::ExternalTerminalA1
        || ingress.issuer != ingress.grant.issuer
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(&ingress.grant)?;
    verify_sg_n_06_current_a2_is_applicability_constraint_named_by(
        &ingress.applicability,
        &ingress.grant,
    )
}
