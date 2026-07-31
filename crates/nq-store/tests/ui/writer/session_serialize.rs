use nq_store::StoreWriterSession;

fn replay(session: &StoreWriterSession<'_>) -> String {
    serde_json::to_string(session).expect("serialize session")
}

fn main() {}
