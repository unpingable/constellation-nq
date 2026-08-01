//! Compile-time qualification for the Gen4 evidence-typed establishment law.
//!
//! Keep this list explicit: deleting or renaming one mandatory specimen must
//! fail the harness instead of silently reducing a globbed proof family.

const GEN4_COMPILE_FAIL_CASES: &[&str] = &[
    "tests/ui/gen4/no_session_establishment.rs",
    "tests/ui/gen4/bare_digest_to_session_establishment.rs",
    "tests/ui/gen4/evidence_public_construction.rs",
    "tests/ui/gen4/evidence_private_constructor.rs",
    "tests/ui/gen4/evidence_unchecked_construction.rs",
    "tests/ui/gen4/evidence_builder_construction.rs",
    "tests/ui/gen4/evidence_from_digest_construction.rs",
    "tests/ui/gen4/evidence_from_boolean_construction.rs",
    "tests/ui/gen4/evidence_clone.rs",
    "tests/ui/gen4/evidence_copy.rs",
    "tests/ui/gen4/evidence_default.rs",
    "tests/ui/gen4/evidence_serialize.rs",
    "tests/ui/gen4/evidence_deserialize.rs",
    "tests/ui/gen4/evidence_to_session_conversion.rs",
    "tests/ui/gen4/session_to_evidence_conversion.rs",
    "tests/ui/gen4/session_from_another_store.rs",
    "tests/ui/gen4/external_brand_to_store_session.rs",
    "tests/ui/gen4/evidence_from_another_store.rs",
    "tests/ui/gen4/use_after_writer_fence.rs",
    "tests/ui/gen4/direct_bare_store_mutation.rs",
    "tests/ui/gen4/r0b_forged_complete_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_pending_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_single_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_resolver_trait_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_v2_capacity_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_v3_capacity_resolver_to_establishment.rs",
];

#[test]
fn runtime_authority_evidence_and_session_cannot_be_forged_or_crossed() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ui/gen4");
    let actual = std::fs::read_dir(directory)
        .expect("read Gen4 compile-fail directory")
        .map(|entry| entry.expect("read Gen4 compile-fail entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| {
            format!(
                "tests/ui/gen4/{}",
                path.file_name()
                    .expect("Gen4 compile-fail filename")
                    .to_string_lossy()
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let expected = GEN4_COMPILE_FAIL_CASES
        .iter()
        .map(|case| (*case).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected, "Gen4 compile-fail manifest drifted");

    let cases = trybuild::TestCases::new();
    for case in GEN4_COMPILE_FAIL_CASES {
        cases.compile_fail(case);
    }
}
