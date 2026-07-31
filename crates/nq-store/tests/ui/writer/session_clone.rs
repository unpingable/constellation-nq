use nq_store::StoreWriterSession;

fn clone_session<'s>(session: &StoreWriterSession<'s>) -> StoreWriterSession<'s> {
    (*session).clone()
}

fn main() {}
