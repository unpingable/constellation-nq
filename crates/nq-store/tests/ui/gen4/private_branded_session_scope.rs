use nq_store::{Store, StoreError};

fn enter_private_authority_scope(store: &mut Store) {
    let _ =
        store.with_runtime_authority_writer_session(|_brand, _session| Ok::<(), StoreError>(()));
}

fn main() {}
