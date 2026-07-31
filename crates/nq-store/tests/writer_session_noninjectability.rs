//! Compile-fail proof that the type-level sole-writer law cannot be
//! bypassed: no mutator without a session, no forged, cloned, serialized,
//! Boolean-minted, or publicly constructed session, and no custody mutation
//! without writer standing.

#[test]
fn writer_session_api_cannot_be_forged_cloned_serialized_or_bypassed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/writer/*.rs");
}
