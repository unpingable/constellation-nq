//! Closed Store-integrity signature-domain vocabulary.
//!
//! This module deliberately models only domain selection.  It does not own a
//! private key, expose a generic signing operation, or turn a domain value
//! into signing standing.  The Store-private signer adapter consumes these
//! values through its family-specific request types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact number of Store-integrity signature domains admitted by C2.
pub const C2_STORE_INTEGRITY_SIGNATURE_DOMAIN_COUNT: usize = 8;

/// The closed Store-integrity signature-domain family.
///
/// There is intentionally no `Other(String)` variant and no public generic
/// domain constructor.  Parsing accepts only the eight exact wire values.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum C2StoreIntegritySignatureDomainV1 {
    /// Physical Store-generation bootstrap.
    #[serde(rename = "nq.c2.store_generation.bootstrap.signature.v1")]
    StoreGenerationBootstrap,
    /// Old-current-key countersignature over an active-policy record.
    #[serde(rename = "nq.c2.active_store_policy.store_integrity_countersignature.v1")]
    ActiveStorePolicyCountersignature,
    /// Proposed-key proof of possession over an active-policy record.
    #[serde(rename = "nq.c2.active_store_policy.new_key_possession_signature.v1")]
    ActiveStorePolicyNewKeyPossession,
    /// Post-installation bounded global-refusal record.
    #[serde(rename = "nq.c2.global_refusal.store_integrity_signature.v1")]
    GlobalRefusal,
    /// Store-generation installation intent.
    #[serde(rename = "nq.c2.installation_intent.store_integrity_signature.v1")]
    InstallationIntent,
    /// Store-generation installation completion receipt.
    #[serde(rename = "nq.c2.installation_receipt.store_integrity_signature.v1")]
    InstallationReceipt,
    /// Active-policy or signer transition intent.
    #[serde(rename = "nq.c2.policy_transition_intent.store_integrity_signature.v1")]
    PolicyTransitionIntent,
    /// Active-policy or signer transition completion receipt.
    #[serde(rename = "nq.c2.policy_transition_receipt.store_integrity_signature.v1")]
    PolicyTransitionReceipt,
}

impl C2StoreIntegritySignatureDomainV1 {
    /// Complete domain set in stable canonical order.
    pub const ALL: [Self; C2_STORE_INTEGRITY_SIGNATURE_DOMAIN_COUNT] = [
        Self::StoreGenerationBootstrap,
        Self::ActiveStorePolicyCountersignature,
        Self::ActiveStorePolicyNewKeyPossession,
        Self::GlobalRefusal,
        Self::InstallationIntent,
        Self::InstallationReceipt,
        Self::PolicyTransitionIntent,
        Self::PolicyTransitionReceipt,
    ];

    /// Exact wire-domain string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreGenerationBootstrap => "nq.c2.store_generation.bootstrap.signature.v1",
            Self::ActiveStorePolicyCountersignature => {
                "nq.c2.active_store_policy.store_integrity_countersignature.v1"
            }
            Self::ActiveStorePolicyNewKeyPossession => {
                "nq.c2.active_store_policy.new_key_possession_signature.v1"
            }
            Self::GlobalRefusal => "nq.c2.global_refusal.store_integrity_signature.v1",
            Self::InstallationIntent => "nq.c2.installation_intent.store_integrity_signature.v1",
            Self::InstallationReceipt => "nq.c2.installation_receipt.store_integrity_signature.v1",
            Self::PolicyTransitionIntent => {
                "nq.c2.policy_transition_intent.store_integrity_signature.v1"
            }
            Self::PolicyTransitionReceipt => {
                "nq.c2.policy_transition_receipt.store_integrity_signature.v1"
            }
        }
    }
}

impl fmt::Display for C2StoreIntegritySignatureDomainV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for C2StoreIntegritySignatureDomainV1 {
    type Err = C2SignatureDomainErrorV1;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|domain| domain.as_str() == value)
            .ok_or_else(|| C2SignatureDomainErrorV1::UnknownDomain(value.to_owned()))
    }
}

/// Refusal returned when bytes name something outside the closed domain set.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum C2SignatureDomainErrorV1 {
    /// The supplied value is not one of the eight exact domains.
    #[error("unknown C2 Store-integrity signature domain: {0}")]
    UnknownDomain(String),
    /// The compile-time domain table was altered or contains a duplicate.
    #[error("the closed C2 Store-integrity signature-domain table is malformed")]
    MalformedClosedDomainTable,
}

/// Non-authority-bearing evidence that the exact closed domain table was
/// enumerated and checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedSignatureDomainSetV1 {
    count: usize,
}

impl ClosedSignatureDomainSetV1 {
    /// Number of checked domains.
    #[must_use]
    pub const fn count(self) -> usize {
        self.count
    }
}

/// N-17 constructor target: enumerate the exact domain set.
#[must_use]
pub const fn construct_n_17_signature_domain_enum_has_exactly_eight_named()
-> [C2StoreIntegritySignatureDomainV1; C2_STORE_INTEGRITY_SIGNATURE_DOMAIN_COUNT] {
    C2StoreIntegritySignatureDomainV1::ALL
}

/// N-17 verifier target: prove that the stable table contains exactly the
/// eight distinct accepted strings.
pub fn verify_n_17_signature_domain_enum_has_exactly_eight_named()
-> Result<ClosedSignatureDomainSetV1, C2SignatureDomainErrorV1> {
    let domains = construct_n_17_signature_domain_enum_has_exactly_eight_named();
    for (index, domain) in domains.iter().enumerate() {
        if domains[..index]
            .iter()
            .any(|earlier| earlier.as_str() == domain.as_str())
            || domain.as_str().parse::<C2StoreIntegritySignatureDomainV1>() != Ok(*domain)
        {
            return Err(C2SignatureDomainErrorV1::MalformedClosedDomainTable);
        }
    }
    Ok(ClosedSignatureDomainSetV1 {
        count: domains.len(),
    })
}

/// REC-01 constructor target: parse one exact domain from canonical carrier
/// text.  Unknown and generic strings refuse.
pub fn construct_rec_01_signature_domain(
    canonical_domain: &str,
) -> Result<C2StoreIntegritySignatureDomainV1, C2SignatureDomainErrorV1> {
    canonical_domain.parse()
}

/// REC-01 verifier target: establish membership in the closed domain set.
pub fn verify_rec_01_closed_signature_domain(
    domain: C2StoreIntegritySignatureDomainV1,
) -> Result<ClosedSignatureDomainSetV1, C2SignatureDomainErrorV1> {
    let verified = verify_n_17_signature_domain_enum_has_exactly_eight_named()?;
    if C2StoreIntegritySignatureDomainV1::ALL.contains(&domain) {
        Ok(verified)
    } else {
        Err(C2SignatureDomainErrorV1::MalformedClosedDomainTable)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn exact_domain_table_is_closed_and_unique() {
        let verification = verify_n_17_signature_domain_enum_has_exactly_eight_named().unwrap();
        assert_eq!(verification.count(), 8);
        assert_eq!(
            C2StoreIntegritySignatureDomainV1::ALL
                .iter()
                .map(|domain| domain.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            8
        );
    }

    #[test]
    fn arbitrary_and_near_miss_domains_refuse() {
        assert!(construct_rec_01_signature_domain("caller.selected.domain").is_err());
        assert!(
            construct_rec_01_signature_domain("nq.c2.store_generation.bootstrap.signature.v2")
                .is_err()
        );
    }

    #[test]
    fn serde_uses_the_exact_wire_value() {
        let domain = C2StoreIntegritySignatureDomainV1::PolicyTransitionReceipt;
        assert_eq!(
            serde_json::to_string(&domain).unwrap(),
            "\"nq.c2.policy_transition_receipt.store_integrity_signature.v1\""
        );
        assert_eq!(
            serde_json::from_str::<C2StoreIntegritySignatureDomainV1>(
                "\"nq.c2.policy_transition_receipt.store_integrity_signature.v1\""
            )
            .unwrap(),
            domain
        );
    }
}
