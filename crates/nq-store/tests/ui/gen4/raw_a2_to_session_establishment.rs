use nq_runtime_dependency_authority::{ResidentActivationRecord, VerificationBrand};
use nq_store::StoreWriterSession;

fn establish_from_raw_a2<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    raw_a2: &ResidentActivationRecord,
) {
    let _ = session.establish_runtime_dependency_trust_root(raw_a2);
}

fn main() {}
