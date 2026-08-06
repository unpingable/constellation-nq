//! SCF-17 pass control: the analogous operations succeed strictly against
//! public API, proving `v2-scf-17.rs` fails only at the crate-privacy
//! boundary and not because the harness or imports are broken.

use nq_helper_sandbox::C2ForkFence;
use nq_store::store_generation::signer::binding::StoreGenerationSignerRootBindingV1;
use nq_store::store_generation::signer::lineage::RootedCurrentBindingLineageV1;

/// Public signer record types are nameable by any crate; only the
/// authority-bearing custody capability is crate-private.
fn name_public_record_types(
    _root: &StoreGenerationSignerRootBindingV1,
    _lineage: &RootedCurrentBindingLineageV1,
) {
}

fn main() {
    let _ = name_public_record_types;
    // Lawful fence acquisition through the public constructor API.
    let guard = C2ForkFence::acquire().expect("public fork fence acquisition");
    guard.verify_same_process().expect("same process");
}
