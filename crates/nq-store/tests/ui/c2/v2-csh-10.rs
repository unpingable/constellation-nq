//! Matrix V3 row CSH-10: "child process inherits loaded key/fd" — refused by
//! the shared fork fence and the custody boundary.
//!
//! This retained case proves only fork-fence field privacy.  Current
//! process-local live authority is tested by the live-C2 noninjectability and
//! Store-owned reopen suites, not inferred from this diagnostic.
//!
//! This case attempts the prohibited condition at compile level: extracting
//! the fork-fence guard's private owner field so its standing could be handed
//! to (or forged for) a child process. The guard's fields are private and no
//! accessor exposes the underlying lock, and the custody capability that owns
//! the loaded key/fd is crate-private, so there is no public route to package
//! signer standing for a child. The case must fail SOLELY with a privacy
//! diagnostic (E0616: private field); the body is otherwise valid public-API
//! usage.

use nq_helper_sandbox::C2ForkFence;

fn main() {
    let guard = C2ForkFence::acquire().expect("fence acquisition is public");
    // Prohibited: read the guard's private owner field to hand fence standing
    // — and with it the protected interval wrapping the loaded key/fd — to a
    // child process.
    let _handoff_to_child: u32 = guard.owner_pid;
}
