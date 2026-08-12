//! Raw evidence cannot be injected into the process-local live signer context.

use nq_store::store_generation::live_c2::C2LiveSignerContextV1;

fn main() {
    // These are deliberately just caller-authored evidence coordinates.  The
    // rejected import is the sole diagnostic: there is no downstream-visible
    // live-context type or constructor into which they can be supplied.
    let _raw_manifest_digest = [0_u8; 32];
    let _raw_frontier = 7_u64;
    let _raw_custody_proof = vec![0_u8; 64];
    let _prior_process = 1234_u32;
    let _other_generation = 8_u64;
}
