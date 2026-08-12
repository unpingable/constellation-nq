//! The public route census is inert metadata, not a generic signing API.

use nq_store::store_generation::signing::C2StoreSigningRouteV1;

fn main() {
    let route = C2StoreSigningRouteV1::Msg06NormalRotationContinuity;
    let caller_selected_bytes = b"caller-selected signing preimage";
    let caller_selected_key = [7_u8; 32];

    // A downstream caller may inspect the closed registry.  It cannot turn a
    // route enum plus caller-selected bytes/key material into a signature.
    let _ = route.sign(caller_selected_key, caller_selected_bytes);
}
