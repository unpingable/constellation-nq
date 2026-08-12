//! Current live-C2 compile boundary.
//!
//! These cases are intentionally separate from the historical V2 custody and
//! fork-fence specimens.  They bind the production architecture directly:
//! external code may hold and serialize inert digests, frontiers, custody-like
//! bytes, detached signatures, and generation coordinates, but it cannot even
//! name the Store-private live context or governed-ingress permit into which
//! those values would have to be injected.
//!
//! Same-crate semantic joins (fresh process, exact Store snapshot, admitted
//! manifest, accepted enrollment, authenticated custody, generation/frontier,
//! policy/scope, and exact content) are enforced and tested in `live_c2`; this
//! harness makes only the narrower, honest external noninjectability claim.

#[test]
fn live_c2_authority_types_are_not_externally_nameable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/c2/live-context-private.rs");
    cases.compile_fail("tests/ui/c2/live-ingress-permit-private.rs");
    cases.compile_fail("tests/ui/c2/live-authority-family-private.rs");
    cases.compile_fail("tests/ui/c2/live-generic-route-inert.rs");
    cases.pass("tests/ui/c2/live-inert-evidence-control.rs");
}
