use nq_runtime_dependency_authority::{ResolvedControllingActivation, VerificationBrand};
use nq_store::StoreWriterSession;

fn convert<'store, 'id>(session: StoreWriterSession<'store, VerificationBrand<'id>>) {
    let _: ResolvedControllingActivation<'id> = session.into();
}

fn main() {}
