//! Matrix V3 row SCF-17: "forked child cannot use inherited signer
//! capability or file handle as standing".
//!
//! This module is included by the `c2_signer_compile_fail_v2` harness as
//! `ui::c2::scf_17`; it is not a trybuild case. It binds the row's assigned
//! constructor and verifier to the observed compile-fail diagnostic of
//! `tests/ui/c2/v2-scf-17.rs`.
//!
//! The accepted compile-time boundary is crate privacy: the signer custody
//! module (`nq_store::store_generation::signer::custody`) and its capability
//! types (`C2StoreIntegrityCustodian`, `StoreIntegrityCustodyFileV1`) are
//! crate-private, so a forked child — a separate compilation, exactly like
//! any external crate — cannot name the capability, cannot construct
//! standing from an inherited file handle, and cannot extract secret
//! material.

/// Expected outcome of the SCF-17 compile-fail case.
///
/// Mirrors `nq_qualification::c1_gen5::SignerCompileExclusionV2::Scf17`,
/// which is a candidate-bound naming anchor, not a creatable artifact; this
/// enum is the local, constructible reflection of the row's expected result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scf17CompileExclusionV2 {
    /// The prohibited construction — naming the crate-private custody path to
    /// turn an inherited signer capability or file handle into standing — was
    /// refused at compile time by module privacy (E0603).
    ForkedChildCannotUseInheritedSignerCapabilityFileHandleAsCompileExcluded,
}

/// Classify an actual compiler diagnostic from the SCF-17 case.
///
/// Returns the exclusion variant only if the diagnostic shows the prohibited
/// construction was refused for the intended reason: a visibility error
/// (E0603) reporting that the signer `custody` module is private. Any other
/// shape — a different error kind, an unresolved name (typo), an unrelated
/// type error, extra diagnostics, or an empty capture — is an `Err`
/// describing the mismatch, so the row fails loudly instead of absorbing a
/// broken case file.
///
/// # Errors
///
/// Returns an `Err` describing the mismatch when the diagnostic is not
/// exactly the intended privacy refusal.
pub fn construct_scf_17_forked_child_cannot_use_inherited_signer_capability(
    diagnostic: &str,
) -> Result<Scf17CompileExclusionV2, String> {
    if diagnostic.trim().is_empty() {
        return Err("SCF-17: no diagnostic captured; the case file may have compiled".to_string());
    }
    if diagnostic.contains("warning") {
        return Err(format!(
            "SCF-17: unexpected warning captured alongside the refusal:\n{diagnostic}"
        ));
    }
    let error_count = diagnostic.matches("error[").count() + diagnostic.matches("\nerror:").count();
    if !diagnostic.contains("error[E0603]") {
        return Err(format!(
            "SCF-17: expected visibility error E0603 (private custody module) \
             but the captured diagnostic has a different error kind:\n{diagnostic}"
        ));
    }
    if error_count != 1 {
        return Err(format!(
            "SCF-17: expected exactly one error diagnostic (the E0603 privacy \
             refusal) but counted {error_count}; an unrelated error or a typo \
             may be masked:\n{diagnostic}"
        ));
    }
    if !diagnostic.contains("module `custody` is private") {
        return Err(format!(
            "SCF-17: E0603 is present but does not name the private custody \
             module; the refusal may be on the wrong path (typo or unrelated \
             import):\n{diagnostic}"
        ));
    }
    Ok(Scf17CompileExclusionV2::ForkedChildCannotUseInheritedSignerCapabilityFileHandleAsCompileExcluded)
}

/// Verify that a classified SCF-17 exclusion is exactly the expected variant.
///
/// # Errors
///
/// Returns an `Err` if the exclusion is anything other than the variant
/// assigned by Matrix V3 row SCF-17.
pub fn verify_scf_17_forked_child_cannot_use_inherited_signer_capability(
    exclusion: &Scf17CompileExclusionV2,
) -> Result<(), String> {
    match exclusion {
        Scf17CompileExclusionV2::ForkedChildCannotUseInheritedSignerCapabilityFileHandleAsCompileExcluded => {
            Ok(())
        }
    }
}
