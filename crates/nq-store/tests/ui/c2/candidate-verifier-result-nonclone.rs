use nq_store::store_generation::c2_lifecycle::StoreC2CandidateVerifierResultV1;

fn duplicate(result: StoreC2CandidateVerifierResultV1) {
    let _duplicate = result.clone();
}

fn main() {}
