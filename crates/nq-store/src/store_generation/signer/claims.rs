//! Bounded signer claims and explicit non-amplification boundaries.
//!
//! These witnesses deliberately say less than a capability.  Finite crash
//! evidence remains corpus-bound, and Store-integrity signer output cannot be
//! converted into any downstream authority family.

use super::result::{CompileExclusionV2, SignerCrashClaimBoundaryV1};

/// Exact finite crash corpus named by SG-N-31.
pub(crate) const SIGNER_FINITE_CRASH_CUTS_V1: [&str; 14] = [
    "SC-10",
    "SC-11",
    "SC-12",
    "SC-14-successor",
    "SC-17",
    "SCF-09",
    "SCF-11",
    "SCF-14",
    "SCG-06",
    "SCG-07",
    "SCG-08",
    "SCG-10",
    "SCG-14",
    "RPA-11-through-RPA-14",
];

/// SG-N-31's proof that the claimed crash surface is finite and named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignerFiniteCrashCoverageV1 {
    cuts: &'static [&'static str],
}

/// Construct only the accepted finite crash corpus.
#[must_use]
pub(crate) const fn construct_sg_n_31_signer_crash_evidence_is_finite_corpus_bound()
-> SignerFiniteCrashCoverageV1 {
    SignerFiniteCrashCoverageV1 {
        cuts: &SIGNER_FINITE_CRASH_CUTS_V1,
    }
}

/// Verify SG-N-31 without claiming universal filesystem or crash safety.
pub(crate) fn verify_sg_n_31_signer_crash_evidence_is_finite_corpus_bound(
    coverage: &SignerFiniteCrashCoverageV1,
) -> SignerCrashClaimBoundaryV1 {
    // Construction is sealed and the only inhabitant carries this exact
    // static slice.  Read the field so this verifier remains an explicit
    // custody boundary without adding a panic-based authority decision.
    let _exact_named_corpus = coverage.cuts;
    SignerCrashClaimBoundaryV1::FiniteCorpusOnly
}

/// Authority families that signer standing and signer output cannot mint.
pub(crate) const SIGNER_PROHIBITED_AUTHORITY_AMPLIFICATIONS_V1: [&str; 13] = [
    "B",
    "G",
    "permanent-B-or-G-capacity",
    "StoreWriterSession",
    "F",
    "M",
    "L",
    "reservation",
    "diagnostic-warrant",
    "invocation-judgment",
    "effect-authority",
    "Docket-authority",
    "external-governed-judgment",
];

/// SG-N-32's sealed non-amplification boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignerNonAmplificationBoundaryV1 {
    prohibited: &'static [&'static str],
}

/// Construct the exact accepted non-amplification boundary.
#[must_use]
pub(crate) const fn construct_sg_n_32_signer_outputs_do_not_mint_b_g()
-> SignerNonAmplificationBoundaryV1 {
    SignerNonAmplificationBoundaryV1 {
        prohibited: &SIGNER_PROHIBITED_AUTHORITY_AMPLIFICATIONS_V1,
    }
}

/// Verify SG-N-32's structural exclusion inventory.
pub(crate) fn verify_sg_n_32_signer_outputs_do_not_mint_b_g(
    boundary: &SignerNonAmplificationBoundaryV1,
) -> CompileExclusionV2 {
    let _exact_prohibited_inventory = boundary.prohibited;
    CompileExclusionV2::SignerAuthorityNonAmplification
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_claim_is_exactly_the_named_finite_corpus() {
        let coverage = construct_sg_n_31_signer_crash_evidence_is_finite_corpus_bound();
        assert_eq!(coverage.cuts.len(), 14);
        assert_eq!(
            verify_sg_n_31_signer_crash_evidence_is_finite_corpus_bound(&coverage),
            SignerCrashClaimBoundaryV1::FiniteCorpusOnly
        );
    }

    #[test]
    fn signer_output_has_no_downstream_authority_conversion() {
        let boundary = construct_sg_n_32_signer_outputs_do_not_mint_b_g();
        assert_eq!(boundary.prohibited.len(), 13);
        assert_eq!(
            verify_sg_n_32_signer_outputs_do_not_mint_b_g(&boundary),
            CompileExclusionV2::SignerAuthorityNonAmplification
        );
    }
}
