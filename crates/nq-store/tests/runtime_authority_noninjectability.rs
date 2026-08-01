//! Compile-time qualification for the Gen4 evidence-typed establishment law.
//!
//! Keep this list explicit: deleting or renaming one mandatory specimen must
//! fail the harness instead of silently reducing a globbed proof family.

const GEN4_COMPILE_FAIL_CASES: &[&str] = &[
    "tests/ui/gen4/no_session_establishment.rs",
    "tests/ui/gen4/session_establishment_missing_evidence.rs",
    "tests/ui/gen4/bare_digest_to_session_establishment.rs",
    "tests/ui/gen4/raw_a2_to_session_establishment.rs",
    "tests/ui/gen4/boolean_to_session_establishment.rs",
    "tests/ui/gen4/operator_key_to_session_establishment.rs",
    "tests/ui/gen4/widened_authority_to_session_establishment.rs",
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
    "tests/ui/gen4/raw_store_initialize_unavailable.rs",
    "tests/ui/gen4/unqualified_store_to_runtime_establishment.rs",
    "tests/ui/gen4/in_memory_store_to_runtime_establishment.rs",
    "tests/ui/gen4/private_authority_candidate_initializer.rs",
    "tests/ui/gen4/private_branded_session_scope.rs",
    "tests/ui/gen4/r0b_forged_complete_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_pending_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_single_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_resolver_trait_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_v2_capacity_resolver_to_establishment.rs",
    "tests/ui/gen4/r0b_forged_v3_capacity_resolver_to_establishment.rs",
];

const DEFAULT_ONLY_RAW_INITIALIZER_CASE: &str = "tests/ui/gen4/raw_store_initialize_unavailable.rs";

fn assert_isolated_compile_failure(relative_manifest: &str, expected: &[&str]) -> String {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_manifest);
    let target = tempfile::tempdir().expect("isolated Gen4 compile-fail target");
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "check",
            "--offline",
            "--quiet",
            "--manifest-path",
            manifest.to_str().expect("UTF-8 isolated manifest path"),
        ])
        .env("CARGO_TARGET_DIR", target.path())
        .output()
        .expect("run isolated Gen4 compile-fail check");
    assert!(
        !output.status.success(),
        "{relative_manifest} unexpectedly compiled"
    );
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 isolated compiler stderr");
    for fragment in expected {
        assert!(
            stderr.contains(fragment),
            "{relative_manifest} stderr lacks {fragment:?}:\n{stderr}"
        );
    }
    stderr
}

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
        // The compatibility spelling exists only when nq-store itself is
        // compiled with `test-support`; the isolated default-surface build
        // below proves it remains absent from the default downstream API.
        if cfg!(feature = "test-support") && *case == DEFAULT_ONLY_RAW_INITIALIZER_CASE {
            continue;
        }
        cases.compile_fail(case);
    }
}

#[test]
fn default_feature_surface_exposes_no_authority_fixture_support() {
    let stderr = assert_isolated_compile_failure(
        "tests/isolated/gen4-default-surface/Cargo.toml",
        &[
            "could not find `test_support`",
            "no function or associated item named `initialize`",
            "no function or associated item named `initialize_from_unqualified_store`",
        ],
    );
    assert!(
        stderr
            .matches("no function or associated item named `initialize_from_unqualified_store`")
            .count()
            >= 2,
        "default surface did not refuse both unqualified and in-memory two-step routes:\n{stderr}"
    );
}

#[test]
fn all_feature_fixture_inputs_cannot_enter_the_private_store_scope() {
    let stderr = assert_isolated_compile_failure(
        "tests/isolated/gen4-all-features-surface/Cargo.toml",
        &[
            "method `with_runtime_authority_writer_session` is private",
            "private method defined here",
            "no function or associated item named `initialize_from_unqualified_store`",
        ],
    );
    assert!(
        stderr
            .matches("no function or associated item named `initialize_from_unqualified_store`")
            .count()
            >= 2,
        "all-feature surface did not refuse both unqualified and in-memory two-step routes:\n{stderr}"
    );
}
