//! Matrix V3 row SCF-17: "forked child cannot use inherited signer
//! capability or file handle as standing".
//!
//! This case stands in for the forked child's own code — a separate
//! compilation, exactly like any external crate. The only route by which a
//! child could turn an inherited signer capability or file handle into
//! standing is naming the custody capability, and that path is crate-private.
//! The case must fail SOLELY with E0603 (module `custody` is private); the
//! body below intentionally does not reference the type so the privacy error
//! is the only diagnostic.

use nq_store::store_generation::signer::custody::C2StoreIntegrityCustodian;

fn main() {
    // Raw inherited material is all a forked child actually holds: a file
    // descriptor number and the custody path bytes. No public constructor
    // turns these into standing, and naming the custody capability (above)
    // is refused by module privacy.
    let _inherited_fd_number: i32 = 3;
    let _inherited_path_bytes: &[u8] = b"/var/lib/nq/store-integrity-custody.v1";
}
