//! Non-conversion law for the C2 authority geometry.
//!
//! The values in this module classify coordinates for audits and refusals;
//! they are not authority capabilities.  Actual authority-bearing types stay
//! distinct and private to their owning modules.  In particular, this module
//! offers no conversion from a satisfied coordinate to any other coordinate.

use serde::Serialize;
use thiserror::Error;

/// Closed list of authority, identity, possession, and standing coordinates
/// that C2 must not collapse.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2AuthorityCoordinateV1 {
    /// Gen4 terminal operator authority and A1 possession.
    Gen4OperatorAuthority,
    /// Gen4 enrolled resident activation.
    Gen4ResidentActivation,
    /// Store-complete current controlling activation.
    CurrentControllingActivation,
    /// Runtime-dependency anchor identity and key generation.
    RuntimeDependencyTrustAnchor,
    /// Anchor-authenticated Store-integrity public-key enrollment.
    StoreIntegrityKeyEnrollment,
    /// Possession of Store-integrity private key material.
    StoreIntegrityPrivateKeyPossession,
    /// Gen4 Store occurrence identity.
    StoreOccurrence,
    /// Immutable physical Store-generation identity.
    PhysicalStoreGeneration,
    /// Evolving active-policy generation.
    ActivePolicyGeneration,
    /// Permanent lock identity and OS flock possession.
    PermanentLockAndFlock,
    /// Closed backend correspondence.
    ClosedBackend,
    /// Ordinary Store writer-session standing.
    StoreWriterSession,
    /// Downstream C3 capacity.
    C3Capacity,
    /// Diagnostic warrant.
    DiagnosticWarrant,
    /// Invocation judgment.
    InvocationJudgment,
    /// Effect authority.
    EffectAuthority,
    /// Docket authority.
    DocketAuthority,
}

impl C2AuthorityCoordinateV1 {
    /// Complete coordinate census in stable order.
    pub const ALL: [Self; 17] = [
        Self::Gen4OperatorAuthority,
        Self::Gen4ResidentActivation,
        Self::CurrentControllingActivation,
        Self::RuntimeDependencyTrustAnchor,
        Self::StoreIntegrityKeyEnrollment,
        Self::StoreIntegrityPrivateKeyPossession,
        Self::StoreOccurrence,
        Self::PhysicalStoreGeneration,
        Self::ActivePolicyGeneration,
        Self::PermanentLockAndFlock,
        Self::ClosedBackend,
        Self::StoreWriterSession,
        Self::C3Capacity,
        Self::DiagnosticWarrant,
        Self::InvocationJudgment,
        Self::EffectAuthority,
        Self::DocketAuthority,
    ];
}

/// Pure, non-authority-bearing description of an attempted conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct C2AuthorityGeometryV1 {
    source: C2AuthorityCoordinateV1,
    target: C2AuthorityCoordinateV1,
}

impl C2AuthorityGeometryV1 {
    /// Coordinate being presented.
    #[must_use]
    pub const fn source(self) -> C2AuthorityCoordinateV1 {
        self.source
    }

    /// Coordinate the caller attempted to obtain.
    #[must_use]
    pub const fn target(self) -> C2AuthorityCoordinateV1 {
        self.target
    }
}

/// Exact refusal for a silent cross-coordinate conversion.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum C2AuthorityGeometryRefusalV1 {
    /// One authority/identity/standing coordinate was substituted for another.
    #[error("C2 authority coordinates are distinct; {presented:?} cannot establish {target:?}")]
    SilentConversion {
        /// Presented coordinate.
        presented: C2AuthorityCoordinateV1,
        /// Requested coordinate.
        target: C2AuthorityCoordinateV1,
    },
}

/// N-06 verifier target.
///
/// Equality confirms only that a classifier did not change coordinates.  It
/// does not construct, validate, or return an authority-bearing value.
pub fn verify_n_06_refusal(
    source: C2AuthorityCoordinateV1,
    target: C2AuthorityCoordinateV1,
) -> Result<C2AuthorityGeometryV1, C2AuthorityGeometryRefusalV1> {
    if source != target {
        return Err(C2AuthorityGeometryRefusalV1::SilentConversion {
            presented: source,
            target,
        });
    }
    Ok(C2AuthorityGeometryV1 { source, target })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn coordinate_census_is_unique() {
        assert_eq!(
            C2AuthorityCoordinateV1::ALL
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            17
        );
    }

    #[test]
    fn possession_does_not_become_enrollment_or_session() {
        let possession = C2AuthorityCoordinateV1::StoreIntegrityPrivateKeyPossession;
        assert!(matches!(
            verify_n_06_refusal(
                possession,
                C2AuthorityCoordinateV1::StoreIntegrityKeyEnrollment
            ),
            Err(C2AuthorityGeometryRefusalV1::SilentConversion { .. })
        ));
        assert!(matches!(
            verify_n_06_refusal(possession, C2AuthorityCoordinateV1::StoreWriterSession),
            Err(C2AuthorityGeometryRefusalV1::SilentConversion { .. })
        ));
    }

    #[test]
    fn identity_does_not_become_downstream_authority() {
        assert!(
            verify_n_06_refusal(
                C2AuthorityCoordinateV1::PhysicalStoreGeneration,
                C2AuthorityCoordinateV1::C3Capacity
            )
            .is_err()
        );
    }
}
