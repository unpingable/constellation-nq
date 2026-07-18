//! Compile-fail proof that the sealed evaluator identity cannot be forged by an
//! ordinary (external, non-test) caller.
//!
//! The API *intends* that production identity come only from the platform
//! provider inside `CollectionEngine::open`. These cases prove the type system
//! enforces that intent: an external caller cannot construct
//! `EvaluatorRuntimeIdentity`, cannot reach the `#[cfg(test)]` fixture
//! constructor, and cannot inject an identity into an engine. If any of these
//! ever starts compiling, an innocent refactor has reopened the seal and this
//! test fails.

#[test]
fn sealed_evaluator_identity_cannot_be_forged_by_external_callers() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
