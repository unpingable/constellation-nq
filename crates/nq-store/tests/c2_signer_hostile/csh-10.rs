//! Matrix V3 row CSH-10: "child process inherits loaded key/fd" — the
//! refusal row's case types and its assigned constructor/verifier.
//!
//! This module is included by the `c2_signer_hostile_v2` hostile runner as
//! `c2_signer_hostile::csh_10`. The runner perturbs the real load-bearing
//! boundary — the public `nq_helper_sandbox::C2ForkFence` shared fork fence,
//! plus a two-process fd-inheritance probe with a deliberate-inheritance
//! decoy control — and hands the structured observations to
//! [`construct_csh_10_child_process_inherits_loaded_key_fd`], which produces
//! the refusal outcome only when every premise holds.
//!
//! The docket refusal mechanism is "PID/boot/process nonce mismatch and
//! close-on-exec refuse"; per the V3 amendment, the no-secret-in-child result
//! is established by the shared fork fence — O_CLOEXEC and the PID check are
//! supporting evidence, not the refusal mechanism by themselves.
//!
//! [`ConcreteSignerHostileCaseV2::Csh10`] mirrors the candidate-bound naming
//! anchor `nq_test_support::c2_signer_hostile::ConcreteSignerHostileCaseV2::Csh10`.
//! The anchor is not a creatable artifact; this enum is the local,
//! constructible reflection of the row's expected case identity.

/// Matrix V3 hostile-case identity for row CSH-10.
///
/// Mirrors the candidate-bound
/// `nq_test_support::c2_signer_hostile::ConcreteSignerHostileCaseV2::Csh10`
/// anchor; that crate is a naming anchor only and must not be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcreteSignerHostileCaseV2 {
    /// CSH-10: "child process inherits loaded key/fd".
    Csh10,
}

/// The refusal a CSH-10 outcome can carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Csh10RefusalV2 {
    /// A child process did not inherit the loaded key/fd: the shared fork
    /// fence failed closed on in-process process creation while the
    /// custody-analog interval was live, the re-exec child's fd table held
    /// no parent marker fd, and the deliberate-inheritance decoy control
    /// proved the probe would have caught any inheritance.
    ChildProcessInheritsLoadedKeyFdRefused,
}

/// Outcome of the CSH-10 hostile case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Csh10Outcome {
    /// The case this outcome belongs to; always
    /// [`ConcreteSignerHostileCaseV2::Csh10`].
    pub case: ConcreteSignerHostileCaseV2,
    /// The refusal the hostile evidence established.
    pub refusal: Csh10RefusalV2,
}

/// Structured runtime observations gathered by the CSH-10 hostile runner.
///
/// Every field is one premise of the row; the constructor produces the
/// refusal outcome only when each premise is exactly true, and names the
/// first failed premise otherwise.
// One bool per docket-assigned premise; a per-premise enum would obscure the
// runner-to-constructor contract without adding information.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Csh10Observations {
    /// While the current thread held the fence (the signer secret-live
    /// interval analog), a same-thread `C2ForkFence::acquire()` — the first
    /// step of the production spawn choke — was refused as non-reentrant.
    pub same_thread_reacquire_refused: bool,
    /// While one thread held the fence, a contender thread's `acquire()` did
    /// not complete within the bounded negative window.
    pub cross_thread_excluded_while_held: bool,
    /// After the holder released the fence, the contender's `acquire()`
    /// completed within the generous positive window (the fence excludes; it
    /// does not deadlock).
    pub cross_thread_acquired_after_release: bool,
    /// The guard's process-identity check held across both re-exec spawns
    /// (PID nonce: the protected interval never crossed a process boundary).
    pub process_identity_stable_across_spawn: bool,
    /// The re-exec child, spawned while the parent held a live custody-analog
    /// interval and an open O_CLOEXEC marker fd, reported no foreign fd.
    pub child_inherited_no_parent_fd: bool,
    /// The decoy control — the same probe with the marker deliberately made
    /// inheritable — detected the inherited fd, proving the clean probe is
    /// non-vacuous.
    pub decoy_inheritance_detected: bool,
    /// The committed compile-fail diagnostic is still exactly the E0616
    /// private-field refusal and nothing else, binding the compile-time and
    /// runtime halves of the row.
    pub compile_fail_stderr_exact: bool,
}

/// Construct the CSH-10 refusal outcome from the runner's observations.
///
/// Returns the refusal outcome only when every premise holds; any missing or
/// wrong premise yields an `Err` naming the exact mismatch, so the row fails
/// loudly instead of absorbing a broken probe.
///
/// # Errors
///
/// Returns an `Err` describing the first failed premise when any observation
/// is not exactly the expected refusal evidence.
pub fn construct_csh_10_child_process_inherits_loaded_key_fd(
    observations: &Csh10Observations,
) -> Result<Csh10Outcome, String> {
    if !observations.same_thread_reacquire_refused {
        return Err(
            "CSH-10: same-thread reacquisition during a live fence interval was not \
             refused as non-reentrant; the fork fence did not fail closed on the \
             production attack shape"
                .to_string(),
        );
    }
    if !observations.cross_thread_excluded_while_held {
        return Err(
            "CSH-10: a contender thread acquired the fence while it was held (or \
             never contended); the fence did not exclude across threads"
                .to_string(),
        );
    }
    if !observations.cross_thread_acquired_after_release {
        return Err(
            "CSH-10: the contender thread did not acquire the fence after release; \
             the fence may be wedged rather than excluding"
                .to_string(),
        );
    }
    if !observations.process_identity_stable_across_spawn {
        return Err(
            "CSH-10: the fence guard's process-identity check failed across the \
             re-exec spawns; the protected interval crossed a process boundary"
                .to_string(),
        );
    }
    if !observations.child_inherited_no_parent_fd {
        return Err(
            "CSH-10: the re-exec child observed a foreign fd (or its report was \
             missing or malformed); the parent's marker fd reached the child"
                .to_string(),
        );
    }
    if !observations.decoy_inheritance_detected {
        return Err(
            "CSH-10: the decoy control failed to detect the deliberately \
             inheritable marker fd; the clean probe is vacuous without it"
                .to_string(),
        );
    }
    if !observations.compile_fail_stderr_exact {
        return Err(
            "CSH-10: the committed compile-fail diagnostic is no longer exactly \
             the E0616 private-field refusal; the compile-time half of the row \
             drifted"
                .to_string(),
        );
    }
    Ok(Csh10Outcome {
        case: ConcreteSignerHostileCaseV2::Csh10,
        refusal: Csh10RefusalV2::ChildProcessInheritsLoadedKeyFdRefused,
    })
}

/// Verify that a CSH-10 outcome is exactly the assigned refusal.
///
/// # Errors
///
/// Returns an `Err` if the outcome is anything other than
/// `Csh10::ChildProcessInheritsLoadedKeyFdRefused`.
pub fn verify_csh_10_child_process_inherits_loaded_key_fd(
    outcome: &Csh10Outcome,
) -> Result<(), String> {
    match (outcome.case, outcome.refusal) {
        (
            ConcreteSignerHostileCaseV2::Csh10,
            Csh10RefusalV2::ChildProcessInheritsLoadedKeyFdRefused,
        ) => Ok(()),
    }
}
