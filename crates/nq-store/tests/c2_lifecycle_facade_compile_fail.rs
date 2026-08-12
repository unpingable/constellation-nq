//! Public facade reachability and opaque candidate-verifier boundary.

use nq_store::Store;
use nq_store::store_generation::c2_lifecycle::{
    C2BootstrapInstallSelectionV1, C2CurrentAuthorityVerificationV1, C2LifecycleRefusalV1,
    C2SignerImplementationManifestV1, StoreC2CandidateVerifierResultV1, StoreC2LifecycleV1,
};

fn enter_public_lifecycle<'store>(
    store: &'store mut Store,
    verified_candidate: &'store StoreC2CandidateVerifierResultV1,
    manifest: &'store C2SignerImplementationManifestV1,
) -> StoreC2LifecycleV1<'store> {
    store.c2_lifecycle_v1(verified_candidate, manifest)
}

fn use_public_writer_callback(
    lifecycle: &mut StoreC2LifecycleV1<'_>,
    authority: &C2CurrentAuthorityVerificationV1<'_>,
) -> Result<(), C2LifecycleRefusalV1> {
    lifecycle.with_current_writer(authority, |writer| writer.verify_live())
}

#[test]
fn public_lifecycle_surface_is_nameable() {
    let _ = enter_public_lifecycle;
    let _ = use_public_writer_callback;
    let _: Option<C2BootstrapInstallSelectionV1> = None;
    assert!(C2SignerImplementationManifestV1::from_canonical_bytes(b"{}").is_err());
}

#[test]
fn candidate_verifier_is_not_an_external_authority_constructor() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/c2/lifecycle-facade-private.rs");
    cases.compile_fail("tests/ui/c2/lifecycle-raw-authority-tuple.rs");
    cases.compile_fail("tests/ui/c2/candidate-verifier-result-private.rs");
    cases.compile_fail("tests/ui/c2/candidate-verifier-result-nonclone.rs");
    cases.compile_fail("tests/ui/c2/candidate-verifier-result-nonserialize.rs");
    cases.compile_fail("tests/ui/c2/candidate-verifier-no-raw-trust-input.rs");
}
