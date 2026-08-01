use nq_store::GenesisInput;

fn bypass(store: &mut nq_store::Store, genesis: &GenesisInput) {
    let _ = store.append_genesis(genesis);
}

fn main() {}
