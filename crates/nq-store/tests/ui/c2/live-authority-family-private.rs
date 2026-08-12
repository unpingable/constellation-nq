//! Every authority-bearing live-C2 family remains outside the downstream API.
//!
//! Separate imports intentionally make this a per-authority boundary check,
//! not one generic assertion that some unrelated private module exists.

use nq_store::store_generation::live_c2::C2LiveSignerContextV1;
use nq_store::store_generation::live_c2::C2LiveWriterSessionV1;
use nq_store::store_generation::live_c2::ConsumedStoreFoundationAdoptionAuthorityV1;
use nq_store::store_generation::live_c2::GenerationCurrentV1;
use nq_store::store_generation::live_c2::PendingPossessionV1;
use nq_store::store_generation::live_c2::PendingSelectedV1;
use nq_store::store_generation::live_c2::StoreVerifiedCurrentPredecessorAuthorityV1;
use nq_store::store_generation::live_c2::StoreVerifiedOrdinarySuccessorFoundationAuthorityV1;
use nq_store::store_generation::live_c2::StoreVerifiedRecoveryEntryAuthorityV1;
use nq_store::store_generation::live_c2::StoreVerifiedRecoveryFoundationAuthorityV1;
use nq_store::store_generation::live_c2::StoreVerifiedRecoveryPossessionPermitV1;
use nq_store::store_generation::live_c2::StoreVerifiedRestoreEntryAuthorityV1;
use nq_store::store_generation::live_c2::StoreVerifiedRestoreFoundationAuthorityV1;
use nq_store::store_generation::live_c2::StoreVerifiedRestorePossessionPermitV1;
use nq_store::store_generation::signer::messages::SignerMessageV1;

fn main() {
    // Caller-authored coordinates remain inert even when they resemble every
    // scalar carried by the private authority families above.
    let _raw_store = [0_u8; 32];
    let _raw_process = 42_u32;
    let _raw_generation = [1_u8; 32];
    let _raw_frontier = [2_u8; 32];
    let _raw_manifest = [3_u8; 32];
    let _raw_custody = vec![4_u8; 64];
    let _raw_signature = [5_u8; 64];
}
