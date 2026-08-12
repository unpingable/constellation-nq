use nq_store::store_generation::c2_lifecycle::{
    C2SignerImplementationManifestV1, StoreC2CandidateRuntimeVerifierV1,
};

fn substitute_trust_root(
    certificate: &[u8],
    caller_selected_trust_root: &[u8],
    manifest: &C2SignerImplementationManifestV1,
) {
    let _result = StoreC2CandidateRuntimeVerifierV1::verify_candidate_runtime(
        certificate,
        caller_selected_trust_root,
        manifest,
    );
}

fn main() {}
