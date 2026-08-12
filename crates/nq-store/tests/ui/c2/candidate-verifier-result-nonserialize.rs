use nq_store::store_generation::c2_lifecycle::StoreC2CandidateVerifierResultV1;

fn serialize(result: &StoreC2CandidateVerifierResultV1) {
    let _serialized = serde_json::to_vec(result).unwrap();
}

fn main() {}
