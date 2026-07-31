use nq_store::Store;

fn forge_with_boolean(store: &mut Store) {
    let _session = store.begin_writer_session(true);
}

fn main() {}
