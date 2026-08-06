//! Compile-fail evidence for Matrix V3 rows SCF-17 and CSH-10.
//!
//! SCF-17: a forked child cannot use an inherited signer capability or file
//! handle as standing — refused at compile time because the signer custody
//! module and its capability types are crate-private.
//!
//! CSH-10: a child process must not inherit the loaded key/fd — refused at
//! compile time because the fork-fence guard's fields are private (no
//! accessor exposes the lock) and the custody capability is crate-private.
//!
//! Each row pairs a compile-fail case with a pass control that performs the
//! analogous operations strictly against public API, proving the case fails
//! at the intended boundary rather than through a broken harness.

// The `#[path]` on the innermost module resolves relative to the inline
// modules' directory (`tests/` + `ui/` + `c2/`), so the row module's logical
// path is `ui::c2::scf_17` while the file lives beside the case files.
mod ui {
    pub mod c2 {
        #[path = "scf-17.rs"]
        pub mod scf_17;
    }
}

#[test]
fn v2_scf_17_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/c2/v2-scf-17.rs");
    // Control: the analogous operations against public API must compile,
    // proving the case fails only at the crate-privacy boundary.
    cases.pass("tests/ui/c2/v2-scf-17-control.rs");
    // trybuild runs its queued cases in `Drop`, and skips them entirely if
    // the thread is already panicking — drop explicitly so a classification
    // failure below cannot mask the trybuild results.
    drop(cases);

    // Bind the row's assigned constructor/verifier to the observed
    // diagnostic: classify the committed `.stderr`, then verify the
    // classification is exactly the expected SCF-17 exclusion.
    let diagnostic = std::fs::read_to_string("tests/ui/c2/v2-scf-17.stderr")
        .expect("committed SCF-17 expected diagnostic");
    let exclusion =
        ui::c2::scf_17::construct_scf_17_forked_child_cannot_use_inherited_signer_capability(
            &diagnostic,
        )
        .unwrap_or_else(|mismatch| {
            panic!("SCF-17 classification refused the observed diagnostic: {mismatch}")
        });
    ui::c2::scf_17::verify_scf_17_forked_child_cannot_use_inherited_signer_capability(&exclusion)
        .expect("SCF-17 verification of the classified exclusion");
}

#[test]
fn v2_csh_10_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/c2/v2-csh-10.rs");
    // Control: lawful public-API fence usage must compile, proving the case
    // fails only at the private-field boundary.
    cases.pass("tests/ui/c2/v2-csh-10-control.rs");
    // trybuild runs its queued cases in `Drop`, and skips them entirely if
    // the thread is already panicking — drop explicitly so an assertion
    // failure below cannot mask the trybuild results.
    drop(cases);

    // CSH-10's assigned construct/verify functions live in the separate
    // hostile case file for the refusal row (`Csh10::
    // ChildProcessInheritsLoadedKeyFdRefused`), not in this compile-fail
    // harness. Here the compile-fail column is bound by asserting the
    // observed diagnostic is exactly the intended privacy refusal and
    // nothing else.
    let diagnostic = std::fs::read_to_string("tests/ui/c2/v2-csh-10.stderr")
        .expect("committed CSH-10 expected diagnostic");
    assert!(
        diagnostic.contains("error[E0616]"),
        "CSH-10: expected private-field error E0616:\n{diagnostic}"
    );
    assert!(
        diagnostic.contains("field `owner_pid` of struct `C2ForkFenceGuard` is private"),
        "CSH-10: expected the refusal to name the guard's private owner field:\n{diagnostic}"
    );
    let error_count = diagnostic.matches("error[").count() + diagnostic.matches("\nerror:").count();
    assert_eq!(
        error_count, 1,
        "CSH-10: expected exactly one error diagnostic (the privacy refusal):\n{diagnostic}"
    );
    assert!(
        !diagnostic.contains("warning"),
        "CSH-10: unexpected warning captured alongside the refusal:\n{diagnostic}"
    );
}
