use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::{Store, StoreWriterSession};

fn externally_brand_another_store<'id>(
    other_store: &mut Store,
    brand_from_first_store: &VerificationBrand<'id>,
) {
    let _ = StoreWriterSession::begin_runtime_authority(other_store, brand_from_first_store);
}

fn main() {}
