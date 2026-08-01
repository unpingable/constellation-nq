use nq_runtime_dependency_authority::{ResolvedControllingActivation, VerificationBrand};
use nq_store::StoreWriterSession;

fn convert<'id>(evidence: ResolvedControllingActivation<'id>) {
    let _: StoreWriterSession<'static, VerificationBrand<'id>> = evidence.into();
}

fn main() {}
