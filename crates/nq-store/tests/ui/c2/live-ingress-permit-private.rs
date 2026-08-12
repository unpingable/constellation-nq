//! A detached signature and raw carrier coordinates cannot mint ingress.

use nq_store::store_generation::signer::external_governance::ExternalCarrierVerificationPermitV1;

fn main() {
    // The rejected import is the sole diagnostic.  Production ingress permits
    // are lexical Store-actor values, not a public conversion target for these
    // caller-authored bytes.
    let _detached_signature = [0_u8; 64];
    let _raw_carrier_identity = [0_u8; 32];
    let _raw_terminal_claim = [0_u8; 32];
}
