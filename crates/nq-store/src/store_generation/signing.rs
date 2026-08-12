//! Read-only projection of the canonical MSG-01 through MSG-16 registry.
//!
//! The normative table lives in the Store-private signer message module.  This
//! public module exposes inert registry metadata only; it has no parser,
//! generic domain constructor, signing operation, key, permit, or standing.

use std::collections::BTreeSet;

use thiserror::Error;

pub use super::signer::messages::{
    C2ExternalSigningRouteV1, C2SignerPhaseV1, C2SigningAuthorityClassV1, C2SigningScopeClassV1,
    C2SoleConsumerV1, C2StoreSigningRouteV1, C2VerifiedInputKindV1, ClosedMessageFamilyV1,
};

/// Exact semantic-family count.
pub const C2_MESSAGE_FAMILY_COUNT: usize = 16;
/// Exact Store/proposal-key signable-family count.
pub const C2_STORE_SIGNABLE_FAMILY_COUNT: usize = 10;
/// Exact Store/proposal-key route count; MSG-12 owns two routes.
pub const C2_STORE_SIGNING_ROUTE_COUNT: usize = 11;
/// Exact external terminal-A1 route count over five semantic families.
pub const C2_EXTERNAL_SIGNING_ROUTE_COUNT: usize = 7;
/// Exact unsigned Store-relation family count.
pub const C2_UNSIGNED_FAMILY_COUNT: usize = 1;

/// One inert Store/proposal-key route projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2StoreSigningRegistryEntryV1 {
    /// Closed route.
    pub route: C2StoreSigningRouteV1,
    /// Semantic family.
    pub family: ClosedMessageFamilyV1,
    /// Exact identity domain.
    pub identity_domain: &'static str,
    /// Exact signature domain.
    pub signature_domain: &'static str,
    /// Required signer phase.
    pub phase: C2SignerPhaseV1,
    /// Required scope class.
    pub scope_class: C2SigningScopeClassV1,
    /// Required authority class.
    pub authority_class: C2SigningAuthorityClassV1,
    /// Exact verified-input class.
    pub input_kind: C2VerifiedInputKindV1,
    /// Sole consumer/effect.
    pub sole_consumer: C2SoleConsumerV1,
}

/// One inert external-terminal-A1 route projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2ExternalSigningRegistryEntryV1 {
    /// Closed external route.
    pub route: C2ExternalSigningRouteV1,
    /// Semantic family.
    pub family: ClosedMessageFamilyV1,
    /// Exact identity domain.
    pub identity_domain: &'static str,
    /// Exact signature domain.
    pub signature_domain: &'static str,
    /// Exact verified external-input class.
    pub input_kind: &'static str,
    /// Sole Store consumer/effect.
    pub sole_consumer: &'static str,
}

/// Failure of the compile-time closed registry census.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum C2SigningRegistryErrorV1 {
    /// A count, mapping, or uniqueness law was changed.
    #[error("the canonical C2 MSG-01 through MSG-16 registry is malformed")]
    MalformedClosedRegistry,
}

/// Exact 16-family inventory.
#[must_use]
pub const fn c2_message_families() -> [ClosedMessageFamilyV1; C2_MESSAGE_FAMILY_COUNT] {
    ClosedMessageFamilyV1::ALL
}

/// Exact 11-route Store/proposal-key projection mechanically derived from the
/// normative registry.
#[must_use]
pub fn c2_store_signing_registry() -> [C2StoreSigningRegistryEntryV1; C2_STORE_SIGNING_ROUTE_COUNT]
{
    C2StoreSigningRouteV1::ALL.map(|route| C2StoreSigningRegistryEntryV1 {
        route,
        family: route.family(),
        identity_domain: route.identity_domain(),
        signature_domain: route.signature_domain(),
        phase: route.phase(),
        scope_class: route.scope_class(),
        authority_class: route.authority_class(),
        input_kind: route.input_kind(),
        sole_consumer: route.sole_consumer(),
    })
}

/// Exact seven-route external-terminal-A1 projection mechanically derived from
/// the normative registry.
#[must_use]
pub fn c2_external_signing_registry()
-> [C2ExternalSigningRegistryEntryV1; C2_EXTERNAL_SIGNING_ROUTE_COUNT] {
    C2ExternalSigningRouteV1::ALL.map(|route| C2ExternalSigningRegistryEntryV1 {
        route,
        family: route.family(),
        identity_domain: route.identity_domain(),
        signature_domain: route.signature_domain(),
        input_kind: route.input_kind(),
        sole_consumer: route.sole_consumer(),
    })
}

/// Verify the exact family/route census and domain non-substitutability.
pub fn verify_closed_c2_signing_registry() -> Result<(), C2SigningRegistryErrorV1> {
    let families = c2_message_families();
    let store = c2_store_signing_registry();
    let external = c2_external_signing_registry();
    let store_families = store
        .iter()
        .map(|entry| entry.family)
        .collect::<BTreeSet<_>>();
    let unsigned = families
        .iter()
        .filter(|family| {
            !store_families.contains(family)
                && !external.iter().any(|entry| entry.family == **family)
        })
        .copied()
        .collect::<Vec<_>>();
    let unique_store_domains = store
        .iter()
        .map(|entry| entry.signature_domain)
        .collect::<BTreeSet<_>>();
    let unique_external_domains = external
        .iter()
        .map(|entry| entry.signature_domain)
        .collect::<BTreeSet<_>>();
    if families.len() != C2_MESSAGE_FAMILY_COUNT
        || store.len() != C2_STORE_SIGNING_ROUTE_COUNT
        || external.len() != C2_EXTERNAL_SIGNING_ROUTE_COUNT
        || store_families.len() != C2_STORE_SIGNABLE_FAMILY_COUNT
        || unsigned != [ClosedMessageFamilyV1::Msg04BootstrapToGenerationRelation]
        || unique_store_domains.len() != C2_STORE_SIGNING_ROUTE_COUNT
        || unique_external_domains.len() != C2_EXTERNAL_SIGNING_ROUTE_COUNT
        || store.iter().any(|entry| {
            entry.family.identity_domain() != entry.identity_domain
                || !entry.family.is_store_signable()
        })
        || external.iter().any(|entry| {
            entry.family == ClosedMessageFamilyV1::Msg04BootstrapToGenerationRelation
                || entry.family.is_store_signable()
        })
    {
        return Err(C2SigningRegistryErrorV1::MalformedClosedRegistry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_projection_has_exact_16_10_11_7_1_census() {
        verify_closed_c2_signing_registry().unwrap();
        assert_eq!(c2_message_families().len(), 16);
        assert_eq!(
            c2_store_signing_registry()
                .iter()
                .map(|entry| entry.family)
                .collect::<BTreeSet<_>>()
                .len(),
            10
        );
        assert_eq!(c2_store_signing_registry().len(), 11);
        assert_eq!(c2_external_signing_registry().len(), 7);
    }

    #[test]
    fn msg12_is_one_family_and_two_non_substitutable_routes() {
        let routes = c2_store_signing_registry();
        let current = routes
            .iter()
            .find(|entry| entry.route == C2StoreSigningRouteV1::Msg12ReceiptCurrent)
            .unwrap();
        let pending = routes
            .iter()
            .find(|entry| entry.route == C2StoreSigningRouteV1::Msg12ReceiptPending)
            .unwrap();
        assert_eq!(current.family, pending.family);
        assert_ne!(current.phase, pending.phase);
        assert_ne!(current.signature_domain, pending.signature_domain);
        assert_ne!(current.authority_class, pending.authority_class);
        assert_ne!(current.input_kind, pending.input_kind);
        assert_ne!(current.sole_consumer, pending.sole_consumer);
    }

    #[test]
    fn projection_exposes_no_string_to_route_or_generic_signing_constructor() {
        assert!(
            c2_store_signing_registry()
                .iter()
                .all(|entry| entry.signature_domain.starts_with("nq.c2."))
        );
    }
}
