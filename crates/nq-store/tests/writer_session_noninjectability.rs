#[test]
fn writer_session_api_cannot_be_forged_cloned_serialized_or_bypassed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/writer/*.rs");
}
