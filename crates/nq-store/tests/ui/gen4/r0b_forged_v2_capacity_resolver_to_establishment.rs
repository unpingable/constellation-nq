use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

struct ForgedV2CapacityResolver;

fn inject<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    forged: &ForgedV2CapacityResolver,
) {
    let _ = session.establish_runtime_dependency_trust_root(forged);
}

fn main() {}
