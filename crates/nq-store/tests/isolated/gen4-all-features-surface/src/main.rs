use std::path::Path;

use nq_host_role_runtime::{
    GenesisAuthorityCustody as RuntimeGenesisAuthorityCustody, HostRoleRuntime,
    RuntimeAuthorityResidentBinding, RuntimeDependencies,
};
use nq_runtime_dependency_authority::{
    ActivationExpectations, GenesisAuthorityCustody, PresentedAuthoritySet, VerificationBrand,
    test_support::RawAuthorityFixture, verify_for_establishment,
};
use nq_store::{Store, StoreError, StoreWriterSession};

fn attempt_unqualified_two_step(
    path: &Path,
    dependencies: &RuntimeDependencies,
    custody: &RuntimeGenesisAuthorityCustody,
    resident: &RuntimeAuthorityResidentBinding,
) {
    let mut store = Store::initialize_unqualified_storage(path).unwrap();
    let _ = HostRoleRuntime::initialize_from_unqualified_store(
        &mut store,
        dependencies,
        custody,
        resident,
    );
}

fn attempt_in_memory_two_step(
    dependencies: &RuntimeDependencies,
    custody: &RuntimeGenesisAuthorityCustody,
    resident: &RuntimeAuthorityResidentBinding,
) {
    let mut store = Store::initialize_in_memory().unwrap();
    let _ = HostRoleRuntime::initialize_from_unqualified_store(
        &mut store,
        dependencies,
        custody,
        resident,
    );
}

fn attempt_feature_fixture_establishment<'store, 'id>(
    brand: &VerificationBrand<'id>,
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    custody: &GenesisAuthorityCustody,
    presented: &PresentedAuthoritySet,
    expectations: &ActivationExpectations,
) -> Result<(), StoreError> {
    let evidence = verify_for_establishment(brand, custody, presented, None, expectations)?;
    session.establish_runtime_dependency_trust_root(&evidence)?;
    Ok(())
}

fn main() {
    let mut store = Store::initialize("feature-fixture.db").unwrap();
    let fixture = RawAuthorityFixture::fresh_genesis();
    let custody = fixture.custody();
    let presented = fixture.presented_set();
    let expectations = fixture.activation_expectations();

    let _ = store.with_runtime_authority_writer_session(|brand, session| {
        attempt_feature_fixture_establishment(brand, session, &custody, &presented, &expectations)
    });
}
