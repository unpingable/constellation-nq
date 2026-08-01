use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::{Store, StoreError, StoreWriterSession};

fn require_same_store_brand<'store, 'id>(
    _brand: &VerificationBrand<'id>,
    _session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
) {
}

fn session_from_first_used_for_second(
    first_store: &mut Store,
    second_store: &mut Store,
) -> Result<(), StoreError> {
    first_store.with_runtime_authority_writer_session(|_, first_session| {
        second_store.with_runtime_authority_writer_session(|second_brand, _| {
            require_same_store_brand(second_brand, first_session);
            Ok(())
        })?;
        Ok(())
    })
}

fn main() {}
