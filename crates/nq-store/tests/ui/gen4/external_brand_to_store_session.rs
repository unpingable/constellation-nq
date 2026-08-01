use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::Store;

fn externally_brand_another_store<'id>(
    other_store: &mut Store,
    brand_from_first_store: &VerificationBrand<'id>,
) {
    let _ = other_store.begin_runtime_authority_writer_session(brand_from_first_store);
}

fn main() {}
