use nq_store::StoreWriterSession;

fn forge_with_boolean() {
    let _session: StoreWriterSession<'static> = true.into();
}

fn main() {}
