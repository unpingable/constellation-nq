use nq_store::{GenesisInput, Store};

fn bypass(store: &mut Store, genesis: &GenesisInput) {
    let _ = store.append_genesis(genesis);
}

fn main() {}
