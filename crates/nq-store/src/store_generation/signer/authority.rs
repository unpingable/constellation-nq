//! Exact authority separation and terminal-A1 bootstrap projection.
//!
//! This module consumes a complete Store-owned authority snapshot.  It never
//! signs as A1 and never converts A2 applicability, possession, custody, or a
//! Store-integrity key into external grant authority.

use super::messages::{ClosedMessageFamilyV1, SignerIdentityV1};
use super::result::SignerRefusalV2;

pub(crate) const A2_APPLICABILITY_INTERPRETATION_V1: &str =
    "nq.c2.a1_runtime_dependency_admission_refinement.v1";

/// One candidate from the complete Store-resident A1 authority snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalA1CandidateV1 {
    pub(crate) key_generation: SignerIdentityV1,
    pub(crate) verifying_key: [u8; 32],
    pub(crate) terminal: bool,
    pub(crate) current_at_cut: bool,
}

/// Complete Store-owned A1 chain projection at one issuance cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalA1AuthoritySnapshotV1 {
    occurrence: SignerIdentityV1,
    snapshot_identity: SignerIdentityV1,
    issuance_cut: u64,
    candidates: Vec<TerminalA1CandidateV1>,
    terminal_index: usize,
}

impl TerminalA1AuthoritySnapshotV1 {
    pub(crate) fn occurrence(&self) -> SignerIdentityV1 {
        self.occurrence
    }

    pub(crate) fn snapshot_identity(&self) -> SignerIdentityV1 {
        self.snapshot_identity
    }

    pub(crate) fn issuance_cut(&self) -> u64 {
        self.issuance_cut
    }

    pub(crate) fn terminal(&self) -> TerminalA1CandidateV1 {
        self.candidates[self.terminal_index]
    }
}

/// The only A1 key generation permitted to verify an initial bootstrap grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalA1BootstrapIssuerV1 {
    pub(crate) snapshot_identity: SignerIdentityV1,
    pub(crate) occurrence: SignerIdentityV1,
    pub(crate) key_generation: SignerIdentityV1,
    pub(crate) verifying_key: [u8; 32],
    pub(crate) issuance_cut: u64,
}

/// Complete signer bootstrap grant scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootstrapGrantScopeV1 {
    pub(crate) occurrence: SignerIdentityV1,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalA1ExternalCarrierIngressV1 {
    pub(crate) family: ClosedMessageFamilyV1,
    pub(crate) issuer: TerminalA1BootstrapIssuerV1,
    pub(crate) grant: BootstrapGrantIdentityV1,
    pub(crate) applicability: A2ApplicabilityRefinementV1,
}

fn nonzero(identity: &SignerIdentityV1) -> bool {
    identity.iter().any(|byte| *byte != 0)
}

fn verify_snapshot(snapshot: &TerminalA1AuthoritySnapshotV1) -> Result<(), SignerRefusalV2> {
    if snapshot.issuance_cut == 0
        || !nonzero(&snapshot.occurrence)
        || !nonzero(&snapshot.snapshot_identity)
        || snapshot.candidates.is_empty()
    {
        return Err(SignerRefusalV2::IncompleteTerminalA1Snapshot);
    }
    let terminal_count = snapshot
        .candidates
        .iter()
        .filter(|candidate| candidate.terminal && candidate.current_at_cut)
        .count();
    if terminal_count != 1
        || snapshot.terminal_index >= snapshot.candidates.len()
        || !snapshot.candidates[snapshot.terminal_index].terminal
        || !snapshot.candidates[snapshot.terminal_index].current_at_cut
    {
        return Err(SignerRefusalV2::WrongTerminalA1Issuer);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(
    occurrence: SignerIdentityV1,
    snapshot_identity: SignerIdentityV1,
    issuance_cut: u64,
    candidates: Vec<TerminalA1CandidateV1>,
) -> Result<TerminalA1AuthoritySnapshotV1, SignerRefusalV2> {
    let terminal_indices = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            (candidate.terminal && candidate.current_at_cut).then_some(index)
        })
        .collect::<Vec<_>>();
    if terminal_indices.len() != 1 {
        return Err(SignerRefusalV2::WrongTerminalA1Issuer);
    }
    let snapshot = TerminalA1AuthoritySnapshotV1 {
        occurrence,
        snapshot_identity,
        issuance_cut,
        candidates,
        terminal_index: terminal_indices[0],
    };
    verify_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub(crate) fn verify_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(
    snapshot: &TerminalA1AuthoritySnapshotV1,
) -> Result<(), SignerRefusalV2> {
    verify_snapshot(snapshot)
}

pub(crate) fn construct_sg_n_02_bootstrap_grant_issuer_is_exactly_resolver_selected(
    snapshot: &TerminalA1AuthoritySnapshotV1,
    store_signer_verifying_key: [u8; 32],
) -> Result<TerminalA1BootstrapIssuerV1, SignerRefusalV2> {
    verify_snapshot(snapshot)?;
    let terminal = snapshot.terminal();
    if terminal.verifying_key == store_signer_verifying_key {
        return Err(SignerRefusalV2::IssuerSignerKeyCollision);
    }
    Ok(TerminalA1BootstrapIssuerV1 {
        snapshot_identity: snapshot.snapshot_identity,
        occurrence: snapshot.occurrence,
        key_generation: terminal.key_generation,
        verifying_key: terminal.verifying_key,
        issuance_cut: snapshot.issuance_cut,
    })
}

pub(crate) fn verify_sg_n_02_bootstrap_grant_issuer_is_exactly_resolver_selected(
    issuer: &TerminalA1BootstrapIssuerV1,
    snapshot: &TerminalA1AuthoritySnapshotV1,
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
    construct_sg_n_04_bootstrap_grant_binds_complete_occurrence_resident_role(issuer, *scope)
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
        grant.issuer,
        grant.scope,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> TerminalA1AuthoritySnapshotV1 {
        construct_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(
            [1; 32],
            [2; 32],
            9,
            vec![TerminalA1CandidateV1 {
                key_generation: [3; 32],
                verifying_key: [4; 32],
                terminal: true,
                current_at_cut: true,
            }],
        )
        .expect("complete singleton terminal snapshot")
    }

    #[test]
    fn caller_cannot_select_a_nonterminal_a1_issuer() {
        let bad = construct_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(
            [1; 32],
            [2; 32],
            9,
            vec![
                TerminalA1CandidateV1 {
                    key_generation: [3; 32],
                    verifying_key: [4; 32],
                    terminal: true,
                    current_at_cut: true,
                },
                TerminalA1CandidateV1 {
                    key_generation: [5; 32],
                    verifying_key: [6; 32],
                    terminal: true,
                    current_at_cut: true,
                },
            ],
        );
        assert_eq!(bad, Err(SignerRefusalV2::WrongTerminalA1Issuer));
    }

    #[test]
    fn terminal_a1_and_store_signer_keys_must_differ() {
        assert_eq!(
            construct_sg_n_02_bootstrap_grant_issuer_is_exactly_resolver_selected(
                &snapshot(),
                [4; 32]
            ),
            Err(SignerRefusalV2::IssuerSignerKeyCollision)
        );
    }
}
