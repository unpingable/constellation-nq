use nq_store::Store;

fn inject(store: &mut Store, forged_resolution: ()) {
    let _ = store.recover_pending_governed_projections(forged_resolution);
}

fn main() {}
