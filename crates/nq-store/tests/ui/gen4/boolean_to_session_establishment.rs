use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

fn establish_from_boolean<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    boolean_authority: &bool,
) {
    let _ = session.establish_runtime_dependency_trust_root(boolean_authority);
}

fn main() {}
