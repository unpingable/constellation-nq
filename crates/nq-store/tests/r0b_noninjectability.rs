//! Compile-time qualification for the Store-owned dependency/source boundary.

#[test]
fn callers_cannot_inject_dependency_resolution_or_construct_standing() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/r0b/*.rs");
}

fn assert_isolated_compile_failure(relative_manifest: &str, expected: &[&str]) {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_manifest);
    let target = tempfile::tempdir().expect("isolated compile-fail target");
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
        .expect("run isolated compile-fail check");
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
}

#[test]
fn default_feature_build_exposes_no_fixture_signer_or_test_support() {
    assert_isolated_compile_failure(
        "tests/isolated/r0b-default-surface/Cargo.toml",
        &[
            "could not find `test_support`",
            "no function or associated item named `fixture_signed`",
        ],
    );
}

#[test]
fn host_runtime_reexport_cannot_restore_literal_construction() {
    assert_isolated_compile_failure(
        "tests/isolated/r0b-runtime-reexport/Cargo.toml",
        &["cannot construct `AuthenticatedRuntimeDependencyClosure`"],
    );
}

#[test]
fn store_owned_callgraph_and_dependency_direction_are_static() {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/verify_r0b_callgraph.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .output()
        .expect("run R0b static verifier");
    assert!(
        output.status.success(),
        "R0b static verifier failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[allow(clippy::type_complexity)]
fn governed_store_apis_retain_zero_resolver_signatures() {
    use nq_protocol::Sha256Digest;
    use nq_store::{
        GovernedCustodyReservation, GovernedExecutionCustodyClosureV2Capacity,
        GovernedProjectionRecovery, GovernedProjectionVerification, Store, StoreError,
    };

    let _: fn(
        &Store,
        &GovernedCustodyReservation,
        &Sha256Digest,
    ) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> =
        Store::verify_governed_execution_custody_closure_v2_capacity;
    let _: fn(
        &Store,
        &GovernedCustodyReservation,
        &Sha256Digest,
    ) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> =
        Store::verify_governed_execution_custody_closure_v3_capacity;
    let _: fn(&mut Store) -> Result<Vec<GovernedProjectionRecovery>, StoreError> =
        Store::recover_pending_governed_projections;
    let _: fn(&mut Store, &Sha256Digest) -> Result<GovernedProjectionRecovery, StoreError> =
        Store::recover_governed_projection_and_mark_indexed;
    let _: fn(&Store, &Sha256Digest) -> Result<GovernedProjectionVerification, StoreError> =
        Store::verify_governed_projection_and_mark_indexed;
}
