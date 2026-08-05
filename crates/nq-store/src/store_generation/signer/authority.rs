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

use crate::{
    CurrentActivationForC2, CurrentActivationResolverInputV1,
    verify_n_08_complete_gen4_authority_ledger, verify_n_09_current_activation_for_c2,
};

use super::external_governance::{
    TerminalA1AuthenticityVerifierV1, TerminalA1IssuerClaimV1, VerifiedBootstrapGrantV1,
};
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
    occurrence: String,
    physical_generation: SignerIdentityV1,
    a2_chain_root: SignerIdentityV1,
    a2_snapshot: SignerIdentityV1,
    resident: SignerIdentityV1,
    resident_generation: u64,
    role: String,
    role_manifest_generation: u64,
    trust_anchor: SignerIdentityV1,
    domain: String,
    activation_policy_version: u64,
    signer_scope: SignerIdentityV1,
    signer_scope_policy_version: u64,
    initial_active_policy: SignerIdentityV1,
    proposed_key_generation: u64,
    proposed_verifying_key: [u8; 32],
    custody_instance: SignerIdentityV1,
    proposal: SignerIdentityV1,
    installation_mode: String,
    grant_cut: u64,
}

/// Verified one-to-one grant/request identity; this is evidence, not a signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapGrantIdentityV1 {
    request_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    issuer: TerminalA1BootstrapIssuerV1,
    scope: BootstrapGrantScopeV1,
    canonical_carrier_digest: SignerIdentityV1,
    canonical_signature: [u8; 64],
}

/// Explicit A2 applicability input.  Its type has no issuing or signing API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct A2ApplicabilityRefinementV1 {
    grant_identity: SignerIdentityV1,
    occurrence: String,
    a2_snapshot: SignerIdentityV1,
    candidate_set: SignerIdentityV1,
    activation_policy_version: u64,
    interpretation: &'static str,
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
    family: ClosedMessageFamilyV1,
    issuer: TerminalA1BootstrapIssuerV1,
    grant: BootstrapGrantIdentityV1,
    applicability: A2ApplicabilityRefinementV1,
}

impl BootstrapGrantIdentityV1 {
    pub(crate) const fn request_identity(&self) -> &SignerIdentityV1 {
        &self.request_identity
    }

    pub(crate) const fn grant_identity(&self) -> &SignerIdentityV1 {
        &self.grant_identity
    }

    pub(crate) const fn issuer(&self) -> &TerminalA1BootstrapIssuerV1 {
        &self.issuer
    }
}

impl A2ApplicabilityRefinementV1 {
    pub(crate) const fn grant_identity(&self) -> &SignerIdentityV1 {
        &self.grant_identity
    }

    pub(crate) const fn a2_snapshot(&self) -> &SignerIdentityV1 {
        &self.a2_snapshot
    }

    pub(crate) const fn interpretation(&self) -> &'static str {
        self.interpretation
    }
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

fn digest_identity(digest: &Sha256Digest) -> Result<SignerIdentityV1, SignerRefusalV2> {
    hex::decode(
        digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?,
    )
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?
    .try_into()
    .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)
}

fn verified_issuer_matches(
    issuer: &TerminalA1BootstrapIssuerV1,
    claim: &TerminalA1IssuerClaimV1,
) -> bool {
    claim.digest == issuer.record_digest.as_str()
        && claim.key_generation == issuer.key_generation
        && claim.verification_key == issuer.verifying_key
        && claim.operator_principal == issuer.operator_principal
        && claim.domain == issuer.domain
        && claim.policy_version == issuer.policy_version
        && claim.policy_floor == issuer.policy_floor
        && claim.issued_against_gen4_cut == issuer.issuance_cut
        && claim.issued_against_terminal_event == issuer.terminal_event.as_str()
        && claim.issued_against_candidate_set == issuer.snapshot_identity.as_str()
}

fn verify_bootstrap_scope_against_issuer(
    issuer: &TerminalA1BootstrapIssuerV1,
    scope: &BootstrapGrantScopeV1,
) -> Result<(), SignerRefusalV2> {
    if scope.grant_cut < issuer.issuance_cut
        || scope.occurrence != issuer.occurrence
        || scope.trust_anchor != digest_identity(&issuer.trust_anchor_id)?
        || scope.domain != issuer.domain
        || scope.resident_generation == 0
        || scope.role.is_empty()
        || scope.role_manifest_generation == 0
        || scope.activation_policy_version == 0
        || scope.signer_scope_policy_version == 0
        || scope.installation_mode.is_empty()
        || [
            scope.physical_generation,
            scope.a2_chain_root,
            scope.a2_snapshot,
            scope.resident,
            scope.trust_anchor,
            scope.signer_scope,
            scope.initial_active_policy,
            scope.custody_instance,
            scope.proposal,
        ]
        .iter()
        .any(|identity| !nonzero(identity))
        || scope.proposed_verifying_key.iter().all(|byte| *byte == 0)
        || scope.proposed_verifying_key == issuer.verifying_key
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
    issuer: &TerminalA1BootstrapIssuerV1,
    verified: &VerifiedBootstrapGrantV1,
) -> Result<BootstrapGrantScopeV1, SignerRefusalV2> {
    if !verified_issuer_matches(issuer, verified.issuer())
        || verified.occurrence_id() != issuer.occurrence
        || verified.trust_anchor_id() != issuer.trust_anchor_id.as_str()
        || verified.authority_domain() != issuer.domain
        || verified.interpretation_policy() != A2_APPLICABILITY_INTERPRETATION_V1
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let scope = BootstrapGrantScopeV1 {
        occurrence: verified.occurrence_id().to_owned(),
        physical_generation: verified.physical_generation_bytes(),
        a2_chain_root: verified.a2_chain_root_bytes(),
        a2_snapshot: verified.controlling_activation_bytes(),
        resident: verified.resident_identity_bytes(),
        resident_generation: verified.resident_generation(),
        role: verified.host_role().to_owned(),
        role_manifest_generation: verified.role_manifest_generation(),
        trust_anchor: verified.trust_anchor_id_bytes(),
        domain: verified.authority_domain().to_owned(),
        activation_policy_version: verified.activation_policy_version(),
        signer_scope: verified.signer_scope_policy_bytes(),
        signer_scope_policy_version: verified.signer_scope_policy_version(),
        initial_active_policy: verified.install_policy_digest(),
        proposed_key_generation: verified.proposed_key_generation(),
        proposed_verifying_key: verified.store_integrity_public_key(),
        custody_instance: verified.custody_instance_identity(),
        proposal: verified.proposal_identity_bytes(),
        installation_mode: verified.installation_mode().to_owned(),
        grant_cut: verified.lifecycle_cut(),
    };
    verify_bootstrap_scope_against_issuer(issuer, &scope)?;
    Ok(scope)
}

pub(crate) fn verify_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
    issuer: &TerminalA1BootstrapIssuerV1,
    verified: &VerifiedBootstrapGrantV1,
    scope: &BootstrapGrantScopeV1,
) -> Result<(), SignerRefusalV2> {
    let expected = construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
        issuer, verified,
    )?;
    (expected == *scope)
        .then_some(())
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
}

pub(crate) fn construct_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
    issuer: &TerminalA1BootstrapIssuerV1,
    verified: &VerifiedBootstrapGrantV1,
) -> Result<BootstrapGrantIdentityV1, SignerRefusalV2> {
    let scope = construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(
        issuer, verified,
    )?;
    let request_identity = *verified.request_identity().bytes();
    let grant_identity = *verified.grant_identity().bytes();
    let canonical_carrier_digest = verified.canonical_carrier_digest();
    let canonical_signature = *verified.canonical_signature();
    if [request_identity, grant_identity, canonical_carrier_digest]
        .iter()
        .any(|identity| !nonzero(identity))
        || request_identity == grant_identity
        || canonical_signature.iter().all(|byte| *byte == 0)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(BootstrapGrantIdentityV1 {
        request_identity,
        grant_identity,
        issuer: issuer.clone(),
        scope,
        canonical_carrier_digest,
        canonical_signature,
    })
}

pub(crate) fn verify_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
    grant: &BootstrapGrantIdentityV1,
) -> Result<(), SignerRefusalV2> {
    verify_bootstrap_scope_against_issuer(&grant.issuer, &grant.scope)?;
    if [
        grant.request_identity,
        grant.grant_identity,
        grant.canonical_carrier_digest,
    ]
    .iter()
    .any(|identity| !nonzero(identity))
        || grant.request_identity == grant.grant_identity
        || grant.canonical_signature.iter().all(|byte| *byte == 0)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_06_current_a2_is_applicability_constraint_named_by(
    grant: &BootstrapGrantIdentityV1,
    current: &CurrentActivationForC2<'_>,
) -> Result<A2ApplicabilityRefinementV1, SignerRefusalV2> {
    verify_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(grant)?;
    verify_n_09_current_activation_for_c2(current)
        .map_err(|_| SignerRefusalV2::A2ApplicabilityMismatch)?;
    let a2_snapshot = digest_identity(current.controlling_tip_activation_digest())?;
    let candidate_set = digest_identity(current.candidate_set_digest())?;
    if grant.scope.occurrence != current.occurrence_id()
        || grant.scope.a2_snapshot != a2_snapshot
        || grant.scope.activation_policy_version != current.policy_version()
        || digest_identity(&grant.issuer.snapshot_identity)? != candidate_set
    {
        return Err(SignerRefusalV2::A2ApplicabilityMismatch);
    }
    Ok(A2ApplicabilityRefinementV1 {
        grant_identity: grant.grant_identity,
        occurrence: grant.scope.occurrence.clone(),
        a2_snapshot,
        candidate_set,
        activation_policy_version: current.policy_version(),
        interpretation: A2_APPLICABILITY_INTERPRETATION_V1,
    })
}

pub(crate) fn verify_sg_n_06_current_a2_is_applicability_constraint_named_by(
    applicability: &A2ApplicabilityRefinementV1,
    grant: &BootstrapGrantIdentityV1,
) -> Result<(), SignerRefusalV2> {
    if applicability.grant_identity != grant.grant_identity
        || applicability.occurrence != grant.scope.occurrence
        || applicability.a2_snapshot != grant.scope.a2_snapshot
        || applicability.candidate_set != digest_identity(&grant.issuer.snapshot_identity)?
        || applicability.activation_policy_version != grant.scope.activation_policy_version
        || applicability.interpretation != A2_APPLICABILITY_INTERPRETATION_V1
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
    issuer: &TerminalA1BootstrapIssuerV1,
    verified: &VerifiedBootstrapGrantV1,
    current: &CurrentActivationForC2<'_>,
) -> Result<TerminalA1ExternalCarrierIngressV1, SignerRefusalV2> {
    let grant = construct_sg_n_05_grant_uses_canonical_encoding_identity_signature_domain(
        issuer, verified,
    )?;
    let applicability =
        construct_sg_n_06_current_a2_is_applicability_constraint_named_by(&grant, current)?;
    let ingress = TerminalA1ExternalCarrierIngressV1 {
        family: ClosedMessageFamilyV1::Msg01BootstrapGrant,
        issuer: issuer.clone(),
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
