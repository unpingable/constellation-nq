use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

fn establish_without_evidence<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
) {
    let _ = session.establish_runtime_dependency_trust_root();
}

fn main() {}
