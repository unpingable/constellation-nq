use nq_store::Store;

fn inject(store: &mut Store, forged_resolution: ()) {
    let _ = store
        .begin_writer_session()
        .expect("writer session")
        .recover_pending_governed_projections(forged_resolution);
}

fn main() {}
