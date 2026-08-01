use std::path::Path;

use nq_host_role_runtime::{
    GenesisAuthorityCustody, HostRoleRuntime, RuntimeAuthorityResidentBinding,
    RuntimeDependencies,
};
use nq_runtime_dependency_authority::test_support::RawAuthorityFixture;
use nq_store::Store;

fn attempt_unqualified_two_step(
    path: &Path,
    dependencies: &RuntimeDependencies,
    custody: &GenesisAuthorityCustody,
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
    custody: &GenesisAuthorityCustody,
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

fn main() {
    let _ = RawAuthorityFixture::fresh_genesis();
    let _ = Store::initialize("default-surface.db");
}
