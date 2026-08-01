use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

fn require_same_store_brand<'store, 'id>(
    _brand: &VerificationBrand<'id>,
    _session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
) {
}

fn session_from_first_used_for_second<'store, 'first_store, 'second_store>(
    first_session: &mut StoreWriterSession<'store, VerificationBrand<'first_store>>,
    second_store_brand: &VerificationBrand<'second_store>,
) {
    require_same_store_brand(second_store_brand, first_session);
}

fn main() {}
