use nq_store::StoreWriterSession;

fn use_after_fence(session: StoreWriterSession<'_>) {
    let _ = session.finish();
    let _ = session.bound_generation();
}

fn main() {}
